use futures::{future::BoxFuture, Stream};
use pwned_pwd_core::PwnedPwd;

pub trait Store {
    type Error;

    fn save<'a, S: 'a + Stream<Item = PwnedPwd> + std::marker::Unpin + std::marker::Send>(
        &'a self,
        s: S,
    ) -> BoxFuture<'a, Result<(), Self::Error>>;

    fn exists<'a>(&'a self, val: [u8; 20]) -> BoxFuture<'a, Result<bool, Self::Error>>;
}
