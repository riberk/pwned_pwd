use crate::{prefix::Prefix, pwned_pwd::PwnedPwd};

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

        res[2] |= val(value.as_bytes()[0], 0)?;

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

#[cfg(test)]
#[rustfmt::skip]
mod tests {
    use crate::{prefix::Prefix, pwned_pwd::PwnedPwd};

    use super::*;

    #[test]
    fn parse() {

        let parser = Parser::new(Prefix::create(0x21BD4).unwrap());

        assert_eq!(PwnedPwd { sha1: hex::decode("21BD4004DDDC80AE4683948C5A1C5903584D8087").unwrap().try_into().unwrap(), count: 13 }, parser.parse("004DDDC80AE4683948C5A1C5903584D8087:13").unwrap());
        assert_eq!(PwnedPwd { sha1: hex::decode("21BD4FFF08998514E6E8F28DBB4CA9F74EA5CAFA").unwrap().try_into().unwrap(), count: 3 }, parser.parse("FFF08998514E6E8F28DBB4CA9F74EA5CAFA:3").unwrap());

        let parser = Parser { prefix: Prefix::create(0x00000).unwrap() };
        assert_eq!(PwnedPwd { sha1: hex::decode("00000004DDDC80AE4683948C5A1C5903584D8087").unwrap().try_into().unwrap(), count: 0 }, parser.parse("004DDDC80AE4683948C5A1C5903584D8087:0").unwrap());
        assert_eq!(PwnedPwd { sha1: hex::decode("00000FFF08998514E6E8F28DBB4CA9F74EA5CAFA").unwrap().try_into().unwrap(), count: 999999 }, parser.parse("FFF08998514E6E8F28DBB4CA9F74EA5CAFA:999999").unwrap());

        assert_eq!(Err::<PwnedPwd, ParseError>(ParseError::FromHexError(hex::FromHexError::InvalidHexCharacter { c: 'Q', index: 0 })), parser.parse("QFF08998514E6E8F28DBB4CA9F74EA5CAFA:999999"));
        assert_eq!(Err::<PwnedPwd, ParseError>(ParseError::FromHexError(hex::FromHexError::InvalidHexCharacter { c: ':', index: 33 })), parser.parse("AFF08998514E6E8F28DBB4CA9F74EA5CAF::999999"));
        assert_eq!(Err::<PwnedPwd, ParseError>(ParseError::InvalidStringLength), parser.parse("FF08998514E6E8F28DBB4CA9F74EA5CAFA"));
        assert_eq!(Err::<PwnedPwd, ParseError>(ParseError::InvalidString), parser.parse("FF08998514E6E8F28DBB4CA9F74EA5CAFA|999999"));
    }
}
