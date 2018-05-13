use Result;

use super::icmpv6::Packet;
use wire::{NdiscOption, NdiscOptionRepr};
use wire::EthernetAddress;

/// Maximum number of NDISC options, if neither 'std' or 'alloc' is
/// available.
///
/// `32` is a completely arbitrary value, but it has the advantage of allowing
/// `Copy`able and `Debug`able arrays.
pub const MAX_NDISC_OPTIONS: usize = 32;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct NdiscOptions<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> NdiscOptions<'a> {
    pub fn new_checked(data: &'a [u8]) -> Result<NdiscOptions> {
        let options = NdiscOptions { data, offset: 0 };
        options.check().map(|_| options)
    }

    fn next_or_error(&mut self) -> Option<Result<NdiscOption<&'a [u8]>>> {
        if self.data.len() - self.offset > 0 {
            let opt = match NdiscOption::new_checked(&self.data[self.offset..]) {
                Ok(pkt) => pkt,
                Err(err) => {
                    return Some(Err(err))},
            };
            self.offset += (opt.data_len() as usize)*8;
            Some(Ok(opt))
        }
        else {
            None
        }
    }

    fn check(&self) -> Result<()> {
        let mut iter = self.clone();
        loop {
            match iter.next_or_error() {
                Some(Ok(_)) => {},
                Some(Err(err)) => return Err(err),
                None => return Ok(()),
            }
        }
    }

    /// Returns the size needed to emit these options.
    ///
    /// # Panic
    ///
    /// Panics if next() was called on this structure.
    pub fn buffer_len(&self) -> usize {
        if self.offset != 0 {
            panic!("next() has been called before buffer_len().")
        }
        self.data.len()
    }

    pub fn emit<T>(&self, packet: &mut Packet<&mut T>)
            where T: AsRef<[u8]> + AsMut<[u8]> + ?Sized {
        packet.payload_mut()[0..self.data.len()].copy_from_slice(self.data);
    }
}

impl<'a> Iterator for NdiscOptions<'a> {
    type Item = NdiscOption<&'a [u8]>;

    fn next(&mut self) -> Option<NdiscOption<&'a [u8]>> {
        self.next_or_error().map(Result::unwrap) // Cannot panic if it was created with new_checked().
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct Repr<'a> {
    data: [Option<NdiscOptionRepr<'a>>; MAX_NDISC_OPTIONS],
}

impl<'b, 'a: 'b> Repr<'a> {
    pub fn new<T>(data: T) -> Repr<'a>
            where T: Iterator<Item=&'b NdiscOptionRepr<'a>> {
        let mut repr = Repr { data: [None; MAX_NDISC_OPTIONS] };
        for (i, opt_repr) in data.into_iter().enumerate() {
            repr.data[i] = Some(opt_repr.clone())
        }
        repr
    }

    pub fn parse(opts: NdiscOptions<'a>) -> Result<Repr<'a>> {
        let mut repr = Repr { data: [None; MAX_NDISC_OPTIONS] };
        for (i, opt) in opts.enumerate() {
            repr.data[i] = Some(NdiscOptionRepr::parse(&opt)?)
        }
        Ok(repr)
    }

    pub fn emit<T>(&self, packet: &mut Packet<&mut T>)
            where T: AsRef<[u8]> + AsMut<[u8]> + ?Sized {
        let mut offset = 0;
        for repr in self.data.iter() {
            if let &Some(repr) = repr {
                let mut opt = NdiscOption::new(&mut packet.payload_mut()[offset..]);
                repr.emit(&mut opt);
                offset += repr.buffer_len();
            }
        }
    }

    /// Returns the exact length of the data (not in units of 8 octets, ie.
    /// it's `sum(repr.buffer_len()*8 for repr in self)`)
    pub fn data_len(&self) -> usize {
        let mut len = 0;
        for repr in self.data.iter() {
            if let &Some(repr) = repr {
                len += repr.buffer_len()
            }
        }
        len
    }

    /// Returns the SourceLinkLayerAddr, if any.
    pub fn slladdr(&self) -> Option<EthernetAddress> {
        for repr in self.data.iter() {
            if let &Some(NdiscOptionRepr::SourceLinkLayerAddr(addr)) = repr {
                return Some(addr)
            }
        }
        None
    }
}
