use crate::{prefix::Prefix, pwned_pwd::PwnedPwd};

#[derive(Debug)]
pub struct Chunk {
    pub prefix: Prefix,
    pub passwords: Vec<PwnedPwd>,
}

impl Chunk {
    pub fn empty(prefix: Prefix) -> Self {
        Self {
            prefix,
            passwords: vec![],
        }
    }
}

impl IntoIterator for Chunk {
    type Item = PwnedPwd;

    type IntoIter = std::vec::IntoIter<PwnedPwd>;

    fn into_iter(self) -> Self::IntoIter {
        self.passwords.into_iter()
    }
}
