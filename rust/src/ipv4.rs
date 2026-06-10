//! Minimal dependency-free IPv4 address and network types.
//!
//! Mirrors the subset of Python's `ipaddress` module that netbat relies on:
//! parsing dotted-quad addresses, parsing `addr/prefix` networks with
//! non-strict host-bit handling (the host portion is masked off, like
//! `ip_network(s, strict=False)`), and membership testing.

use std::fmt;

/// A 32-bit IPv4 address.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Ipv4Addr(pub u32);

impl Ipv4Addr {
    /// Parse a dotted-quad string such as `192.168.1.1`.
    pub fn parse(s: &str) -> Result<Ipv4Addr, String> {
        let mut octets = [0u32; 4];
        let mut count = 0;
        for part in s.split('.') {
            if count >= 4 {
                return Err(format!("invalid IPv4 address: {s}"));
            }
            if part.is_empty() {
                return Err(format!("invalid IPv4 address: {s}"));
            }
            let v: u32 = part
                .parse()
                .map_err(|_| format!("invalid IPv4 address: {s}"))?;
            if v > 255 {
                return Err(format!("invalid IPv4 address: {s}"));
            }
            octets[count] = v;
            count += 1;
        }
        if count != 4 {
            return Err(format!("invalid IPv4 address: {s}"));
        }
        Ok(Ipv4Addr(
            (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3],
        ))
    }
}

impl fmt::Display for Ipv4Addr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}.{}.{}.{}",
            (self.0 >> 24) & 0xff,
            (self.0 >> 16) & 0xff,
            (self.0 >> 8) & 0xff,
            self.0 & 0xff
        )
    }
}

impl fmt::Debug for Ipv4Addr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self}")
    }
}

/// An IPv4 network: a base address plus a prefix length.
///
/// Constructed with non-strict semantics — any host bits in the supplied
/// address are masked off so that `192.168.1.5/24` becomes `192.168.1.0/24`.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ipv4Network {
    pub base: u32,
    pub prefix: u8,
}

impl Ipv4Network {
    /// Parse `addr/prefix` or a bare `addr` (treated as a /32 host route).
    pub fn parse(s: &str) -> Result<Ipv4Network, String> {
        let (addr_part, prefix) = match s.split_once('/') {
            Some((a, p)) => {
                let prefix: u8 = p
                    .parse()
                    .map_err(|_| format!("invalid prefix length: {s}"))?;
                if prefix > 32 {
                    return Err(format!("invalid prefix length: {s}"));
                }
                (a, prefix)
            }
            None => (s, 32u8),
        };
        let addr = Ipv4Addr::parse(addr_part)?;
        let mask = Self::mask(prefix);
        Ok(Ipv4Network {
            base: addr.0 & mask,
            prefix,
        })
    }

    fn mask(prefix: u8) -> u32 {
        if prefix == 0 {
            0
        } else {
            u32::MAX << (32 - prefix as u32)
        }
    }

    /// The `0.0.0.0/0` network matching every address.
    pub fn any() -> Ipv4Network {
        Ipv4Network { base: 0, prefix: 0 }
    }

    /// Whether `addr` falls within this network.
    pub fn contains(&self, addr: Ipv4Addr) -> bool {
        let mask = Self::mask(self.prefix);
        (addr.0 & mask) == self.base
    }
}

impl fmt::Display for Ipv4Network {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", Ipv4Addr(self.base), self.prefix)
    }
}

impl fmt::Debug for Ipv4Network {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self}")
    }
}
