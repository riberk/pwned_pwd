use std::{
    fmt::{Debug, Display},
    hash::Hash,
    str::from_utf8_unchecked,
};

use hex::ToHex;

/// Representetion of a pwned password
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct PwnedPwd {
    /// password SHA-1
    pub sha1: [u8; 20],

    /// how many times it appears in the data set
    pub count: u32,
}

/// Prefix for downloading from haveibeenpwned with k-anonimity
#[derive(Debug, Default, PartialEq, Eq, Clone, Copy, Hash, PartialOrd, Ord)]
pub struct Prefix(u32);

/// String representation of a [Prefix]
#[derive(Debug, Default, PartialEq, Eq, Clone, Copy)]
pub struct PrefixStr([u8; 5]);

impl FromIterator<char> for PrefixStr {
    fn from_iter<T: IntoIterator<Item = char>>(iter: T) -> Self {
        let mut iter = iter.into_iter();
        for _ in 0..3 {
            iter.next().expect("Invalid iterator len");
        }

        let mut res = [0u8; 5];
        for i in 0..5 {
            let value = iter.next().expect("Invalid iterator len");
            res[i] = value as u8;
        }

        PrefixStr(res)
    }
}

impl From<&Prefix> for PrefixStr {
    fn from(value: &Prefix) -> Self {
        value.as_prefix_str()
    }
}

impl AsRef<str> for PrefixStr {
    fn as_ref(&self) -> &str {
        // PrefixStr may be created ONLY from Prefix with `encode_hex_upper`
        // so, while `hex` crate returns us good data, we can be sure that is valid utf8 bytes
        unsafe { from_utf8_unchecked(&self.0) }
    }
}

impl std::ops::Add<u32> for Prefix {
    type Output = Option<Prefix>;

    fn add(self, rhs: u32) -> Self::Output {
        Prefix::create(self.0 + rhs)
    }
}

impl Prefix {
    const MAX_PREFIX: u32 = 0xFFFFF;

    pub fn create(v: u32) -> Option<Prefix> {
        if v > Self::MAX_PREFIX {
            None
        } else {
            Some(Prefix(v))
        }
    }

    /// Max possible prefix
    pub fn max() -> Self {
        Prefix(Self::MAX_PREFIX)
    }

    /// Count of prefixes
    pub fn count() -> u32 {
        Self::MAX_PREFIX
    }

    /// Get a next prefix or None, if self is max
    pub fn next(&self) -> Option<Self> {
        self.forward(1)
    }

    /// Get a forwarded prefix by `v` or None, if self + v is invalid prefix
    pub fn forward(&self, v: u32) -> Option<Self> {
        Self::create(self.0 + v)
    }

    /// Get string representation
    pub fn as_prefix_str(&self) -> PrefixStr {
        let bytes = self.0.to_be_bytes();
        bytes.encode_hex_upper()
    }

    /// Write prefix into slice. Slice length must be greater or equal 3
    pub fn write_prefix(&self, dst: &mut [u8]) {
        dst[0..3].copy_from_slice(&(self.0 << 4).to_be_bytes()[1..])
    }

    pub fn parser(&self) -> Parser {
        self.clone().into()
    }
}

impl TryFrom<u32> for Prefix {
    type Error = PrefixError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        if value > Self::MAX_PREFIX {
            Err(PrefixError::OutOfRange)
        } else {
            Ok(Self(value))
        }
    }
}

impl IntoIterator for Prefix {
    type Item = Prefix;

    type IntoIter = PrefixIterator;

    fn into_iter(self) -> Self::IntoIter {
        PrefixIterator { next: Some(self) }
    }
}

pub struct PrefixIterator {
    next: Option<Prefix>,
}

impl Iterator for PrefixIterator {
    type Item = Prefix;

    fn next(&mut self) -> Option<Self::Item> {
        let current = self.next.clone();
        self.next = self.next.and_then(|v| v.next());
        current
    }
}

#[derive(Debug)]
pub struct Chunk {
    pub prefix: Prefix,
    pub passwords: Vec<PwnedPwd>,
}

impl IntoIterator for Chunk {
    type Item = PwnedPwd;

    type IntoIter = std::vec::IntoIter<PwnedPwd>;

    fn into_iter(self) -> Self::IntoIter {
        self.passwords.into_iter()
    }
}

#[derive(thiserror::Error, Debug, PartialEq, Eq)]
pub enum PrefixError {
    #[error("Prefix is out of range, it must be from 0x00000 to 0xfffff")]
    OutOfRange,
}

#[derive(thiserror::Error, Debug, PartialEq)]
pub enum ParseError {
    #[error("Invalid hex: {0}")]
    FromHexError(#[from] hex::FromHexError),

    #[error("Invalid count: {0}")]
    ParseIntError(#[from] std::num::ParseIntError),

    #[error("Invalid string lenght")]
    InvalidStringLength,

    #[error("String must contain 35 hex characters, then a ':' char and then a positive or zero integer")]
    InvalidString,
}

/// Haveibeenpwned result lines parser
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Parser {
    prefix: Prefix,
}

impl From<Prefix> for Parser {
    fn from(value: Prefix) -> Self {
        Self { prefix: value }
    }
}

impl Parser {
    pub fn new(prefix: Prefix) -> Self {
        Self { prefix }
    }

    pub fn parse(&self, value: impl AsRef<str>) -> Result<PwnedPwd, ParseError> {
        let value = value.as_ref();

        if value.len() < 37 {
            return Err(ParseError::InvalidStringLength);
        }

        if value.as_bytes()[35] != b':' {
            return Err(ParseError::InvalidString);
        }

        let mut res = [0; 20];
        self.prefix.write_prefix(&mut res);

        res[2] = res[2] | val(value.as_bytes()[0], 0)?;

        hex::decode_to_slice(&value[1..35], &mut res[3..])?;

        Ok(PwnedPwd {
            sha1: res,
            count: value[36..].parse()?,
        })
    }
}

fn val(char: u8, idx: usize) -> Result<u8, hex::FromHexError> {
    match char {
        b'A'..=b'F' => Ok(char - b'A' + 10),
        b'a'..=b'f' => Ok(char - b'a' + 10),
        b'0'..=b'9' => Ok(char - b'0'),
        _ => Err(hex::FromHexError::InvalidHexCharacter {
            c: char as char,
            index: idx,
        }),
    }
}

impl Display for Prefix {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.as_prefix_str().fmt(f)
    }
}

#[cfg(test)]
#[rustfmt::skip]
mod tests {
    use super::*;

    
    #[test]
    fn prefix_as_prefix_str() {
        assert_eq!("00000", Prefix(0x00000).as_prefix_str().as_ref());
        assert_eq!("00000", Prefix(0x00000).as_prefix_str().as_ref());
        assert_eq!("00001", Prefix(0x00001).as_prefix_str().as_ref());
        assert_eq!("00002", Prefix(0x00002).as_prefix_str().as_ref());
        assert_eq!("0000A", Prefix(0x0000A).as_prefix_str().as_ref());
        assert_eq!("0000F", Prefix(0x0000F).as_prefix_str().as_ref());
        assert_eq!("000F0", Prefix(0x000F0).as_prefix_str().as_ref());
        assert_eq!("000FF", Prefix(0x000FF).as_prefix_str().as_ref());
        assert_eq!("12345", Prefix(0x12345).as_prefix_str().as_ref());
        assert_eq!("FF00F", Prefix(0xFF00F).as_prefix_str().as_ref());
        assert_eq!("0F00F", Prefix(0x0F00F).as_prefix_str().as_ref());
        assert_eq!("FFFFF", Prefix(0xFFFFF).as_prefix_str().as_ref());
        assert_eq!("FFFFF", Prefix::max().as_prefix_str().as_ref());
    }

    #[test]
    fn prefix_write_prefix() { 
        let mut dst = [0u8; 3];
        Prefix(0x21BD4).write_prefix(&mut dst);

        assert_eq!([0x21, 0xBD, 0x40], dst)
    }

    #[test]
    fn prefix_default() {
        assert_eq!(Prefix(0), Prefix::default())
    }

    #[test]
    fn prefix_try_from_u32() {
        assert_eq!(Ok(Prefix(0x00000)), 0x00000.try_into());
        assert_eq!(Ok(Prefix(0x00001)), 0x00001.try_into());
        assert_eq!(Ok(Prefix(0xFFFFF)), 0xFFFFF.try_into());
        assert_eq!(Err::<Prefix, PrefixError>(PrefixError::OutOfRange), 0x100000u32.try_into());
        assert_eq!(Err::<Prefix, PrefixError>(PrefixError::OutOfRange), 0x200000u32.try_into());
    }

    #[test]
    fn prefix_next() {
        let mut prefix = Prefix(0);
        while let Some(next) = prefix.next(){
            assert_eq!(next.0, prefix.0 + 1);
            prefix = next;
        }
        assert_eq!(0xFFFFF, prefix.0);
        assert_eq!(None, prefix.next());
        assert_eq!(None, prefix.next());
    }

    #[test]
    fn parse() {

        let parser = Parser::new(Prefix(0x21BD4));

        assert_eq!(PwnedPwd { sha1: hex::decode("21BD4004DDDC80AE4683948C5A1C5903584D8087").unwrap().try_into().unwrap(), count: 13 }, parser.parse("004DDDC80AE4683948C5A1C5903584D8087:13").unwrap());
        assert_eq!(PwnedPwd { sha1: hex::decode("21BD4FFF08998514E6E8F28DBB4CA9F74EA5CAFA").unwrap().try_into().unwrap(), count: 3 }, parser.parse("FFF08998514E6E8F28DBB4CA9F74EA5CAFA:3").unwrap());

        let parser = Parser { prefix: Prefix(0x00000) };
        assert_eq!(PwnedPwd { sha1: hex::decode("00000004DDDC80AE4683948C5A1C5903584D8087").unwrap().try_into().unwrap(), count: 0 }, parser.parse("004DDDC80AE4683948C5A1C5903584D8087:0").unwrap());
        assert_eq!(PwnedPwd { sha1: hex::decode("00000FFF08998514E6E8F28DBB4CA9F74EA5CAFA").unwrap().try_into().unwrap(), count: 999999 }, parser.parse("FFF08998514E6E8F28DBB4CA9F74EA5CAFA:999999").unwrap());

        assert_eq!(Err::<PwnedPwd, ParseError>(ParseError::FromHexError(hex::FromHexError::InvalidHexCharacter { c: 'Q', index: 0 })), parser.parse("QFF08998514E6E8F28DBB4CA9F74EA5CAFA:999999"));
        assert_eq!(Err::<PwnedPwd, ParseError>(ParseError::FromHexError(hex::FromHexError::InvalidHexCharacter { c: ':', index: 33 })), parser.parse("AFF08998514E6E8F28DBB4CA9F74EA5CAF::999999"));
        assert_eq!(Err::<PwnedPwd, ParseError>(ParseError::InvalidStringLength), parser.parse("FF08998514E6E8F28DBB4CA9F74EA5CAFA"));
        assert_eq!(Err::<PwnedPwd, ParseError>(ParseError::InvalidString), parser.parse("FF08998514E6E8F28DBB4CA9F74EA5CAFA|999999"));
    }

    #[test]
    fn iterator() {
        let mut iterator = Prefix(0x0000).into_iter();
        for i in 0..=Prefix::MAX_PREFIX {
            assert_eq!(Some(Prefix(i)), iterator.next())
        }

        assert_eq!(None, iterator.next())
    }
}
