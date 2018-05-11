use managed::ManagedSlice;
use time::Instant;

use wire::{IpCidr, IpAddress};
#[cfg(feature = "proto-ipv4")]
use wire::{Ipv4Address, Ipv4Cidr};
#[cfg(feature = "proto-ipv6")]
use wire::{Ipv6Address, Ipv6Cidr};

/// A prefix of addresses that should be routed via a router
#[derive(Debug, Clone, Copy)]
pub struct Route {
    pub via_router: IpAddress,
    pub prefix: IpCidr,
    /// `None` means "forever".
    pub preferred_until: Option<Instant>,
    /// `None` means "forever".
    pub expires_at: Option<Instant>,
}

impl Route {
    /// Returns a route to 0.0.0.0/0 via the `gateway`, with no expiry.
    #[cfg(feature = "proto-ipv4")]
    pub fn new_ipv4_gateway(gateway: Ipv4Address) -> Route {
        Route {
            via_router: gateway.into(),
            prefix: IpCidr::Ipv4(Ipv4Cidr::new(Ipv4Address::UNSPECIFIED, 0)),
            preferred_until: None,
            expires_at: None,
        }
    }

    /// Returns a route to ::/0 via the `gateway`, with no expiry.
    #[cfg(feature = "proto-ipv6")]
    pub fn new_ipv6_gateway(gateway: Ipv6Address) -> Route {
        Route {
            via_router: gateway.into(),
            prefix: IpCidr::Ipv6(Ipv6Cidr::new(Ipv6Address::UNSPECIFIED, 0)),
            preferred_until: None,
            expires_at: None,
        }
    }
}

/// A routing table.
///
/// # Examples
///
/// On systems with heap, this table can be created with:
///
/// ```rust
/// use smoltcp::iface::Routes;
/// let mut routes = Routes::new(Vec::new());
/// ```
///
/// On systems without heap, use:
///
/// ```rust
/// use smoltcp::iface::Routes;
/// let mut routes_storage = [];
/// let mut routes = Routes::new(&mut routes_storage[..]);
/// ```
#[derive(Debug)]
pub struct Routes<'a> {
    storage:      ManagedSlice<'a, Route>,
}

impl<'a> Routes<'a> {
    /// Creates a routing tables. The backing storage is **not** cleared
    /// upon creation.
    pub fn new<T>(storage: T) -> Routes<'a>
            where T: Into<ManagedSlice<'a, Route>> {
        let storage = storage.into();
        let r = Routes { storage };
        r.check_ip_addrs();
        r
    }

    /// Update the routes of this node.
    ///
    /// # Panics
    /// This function panics if any of the addresses are not unicast.
    pub fn update_routes<F: FnOnce(&mut ManagedSlice<'a, Route>)>(&mut self, f: F) {
        f(&mut self.storage);
        self.check_ip_addrs();
    }

    pub(crate) fn lookup(&self, addr: &IpAddress, timestamp: Instant) ->
            Option<IpAddress> {
        if addr.is_broadcast() {
            panic!("IP address {} is broadcast", addr);
        }

        let mut current_prefix_length = 0u8;
        let mut current_address = None;

        for route in self.storage.iter() {
            // TODO: do something with route.preferred_until
            if let Some(expires_at) = route.expires_at {
                if timestamp > expires_at {
                    continue;
                }
            }

            if current_prefix_length <= route.prefix.prefix_len() &&
                    route.via_router != *addr &&
                    route.prefix.contains_addr(addr) {
                current_prefix_length = route.prefix.prefix_len();
                current_address = Some(route.via_router);
            }
        }

        current_address
    }

    fn check_ip_addrs(&self) {
        for &Route { prefix, .. } in self.storage.iter() {
            if !prefix.address().is_unicast() {
                panic!("IP address {} is not unicast", prefix.address())
            }
        }
    }
}

#[cfg(all(test, feature = "proto-ipv4"))]
mod test {
    use super::*;
    const ADDR_1A: Ipv4Address = Ipv4Address([192, 0, 2, 1]);
    const ADDR_1B: Ipv4Address = Ipv4Address([192, 0, 2, 13]);
    const ADDR_1C: Ipv4Address = Ipv4Address([192, 0, 2, 42]);
    const CIDR_1: Ipv4Cidr = Ipv4Cidr {
        address: Ipv4Address([192, 0, 2, 0]),
        prefix_len: 24,
    };

    const ADDR_2A: Ipv4Address = Ipv4Address([198, 51, 100, 1]);
    const ADDR_2B: Ipv4Address = Ipv4Address([198, 51, 100, 21]);
    const CIDR_2: Ipv4Cidr = Ipv4Cidr {
        address: Ipv4Address([198, 51, 100, 0]),
        prefix_len: 24,
    };

    #[test]
    fn test_fill() {
        let mut routes_storage = vec![];
        let mut routes = Routes::new(&mut routes_storage[..]);

        assert_eq!(routes.lookup(&ADDR_1A.into(), Instant::from_millis(0)), None);
        assert_eq!(routes.lookup(&ADDR_1B.into(), Instant::from_millis(0)), None);
        assert_eq!(routes.lookup(&ADDR_1C.into(), Instant::from_millis(0)), None);
        assert_eq!(routes.lookup(&ADDR_2A.into(), Instant::from_millis(0)), None);
        assert_eq!(routes.lookup(&ADDR_2B.into(), Instant::from_millis(0)), None);

        let route = Route {
            prefix: CIDR_1.into(), via_router: ADDR_1A.into(),
            preferred_until: None, expires_at: None,
        };
        let mut routes_storage2 = vec![route];
        routes.update_routes(|storage| {
            routes_storage2.extend(storage.to_vec());
            *storage = routes_storage2.into();
        });

        assert_eq!(routes.lookup(&ADDR_1A.into(), Instant::from_millis(0)), None);
        assert_eq!(routes.lookup(&ADDR_1B.into(), Instant::from_millis(0)), Some(ADDR_1A.into()));
        assert_eq!(routes.lookup(&ADDR_1C.into(), Instant::from_millis(0)), Some(ADDR_1A.into()));
        assert_eq!(routes.lookup(&ADDR_2A.into(), Instant::from_millis(0)), None);
        assert_eq!(routes.lookup(&ADDR_2B.into(), Instant::from_millis(0)), None);

        let route2 = Route {
            prefix: CIDR_2.into(), via_router: ADDR_2A.into(),
            preferred_until: Some(Instant::from_millis(10)),
            expires_at: Some(Instant::from_millis(10)),
        };
        let mut routes_storage3 = vec![route2];
        routes.update_routes(|storage| {
            routes_storage3.extend(storage.to_vec());
            *storage = routes_storage3.into();
        });

        assert_eq!(routes.lookup(&ADDR_1A.into(), Instant::from_millis(0)), None);
        assert_eq!(routes.lookup(&ADDR_1B.into(), Instant::from_millis(0)), Some(ADDR_1A.into()));
        assert_eq!(routes.lookup(&ADDR_1C.into(), Instant::from_millis(0)), Some(ADDR_1A.into()));
        assert_eq!(routes.lookup(&ADDR_2A.into(), Instant::from_millis(0)), None);
        assert_eq!(routes.lookup(&ADDR_2B.into(), Instant::from_millis(0)), Some(ADDR_2A.into()));

        assert_eq!(routes.lookup(&ADDR_1A.into(), Instant::from_millis(10)), None);
        assert_eq!(routes.lookup(&ADDR_1B.into(), Instant::from_millis(10)), Some(ADDR_1A.into()));
        assert_eq!(routes.lookup(&ADDR_1C.into(), Instant::from_millis(10)), Some(ADDR_1A.into()));
        assert_eq!(routes.lookup(&ADDR_2A.into(), Instant::from_millis(10)), None);
        assert_eq!(routes.lookup(&ADDR_2B.into(), Instant::from_millis(10)), Some(ADDR_2A.into()));
    }
}
