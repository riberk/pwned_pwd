use std::fmt::{Display, Write};

use hex::ToHex;

/// Representetion of a pwned password
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct PwnedPwd {
    /// password SHA-1
    pub sha1: [u8; 20],

    /// how many times it appears in the data set
    pub count: u32,
}

impl Display for PwnedPwd {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let writer: Writer = self.sha1.encode_hex_upper();
        writer.write(f)?;
        f.write_char(':')?;
        write!(f, "{}", self.count)
    }
}

struct Writer {
    chars: [char; 40],
}

impl FromIterator<char> for Writer {
    fn from_iter<T: IntoIterator<Item = char>>(iter: T) -> Self {
        let mut chars = [char::default(); 40];

        for (i, ch) in iter.into_iter().enumerate() {
            chars[i] = ch;
        }
        Self { chars }
    }
}

impl Writer {
    fn write(self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for ch in self.chars {
            f.write_char(ch)?
        }
        Ok(())
    }
}
