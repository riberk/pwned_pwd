use futures::{future::BoxFuture, Stream};
use pwned_pwd_core::Chunk;

pub trait Store {
    type Error;

    fn order_requirement() -> OrderRequirement;

    fn save<'a, S: 'a + Stream<Item = Chunk> + std::marker::Unpin + std::marker::Send>(
        &'a self,
        s: S,
    ) -> BoxFuture<'a, Result<(), Self::Error>>;

    fn exists<'a>(&'a self, val: [u8; 20]) -> BoxFuture<'a, Result<bool, Self::Error>>;
}

/// Store may or may not be order-agnostic to saving data
/// If it is, a Stream argument must be ordered (for example for local store)
/// If it's not, a Stream argument can be unordered
pub enum OrderRequirement {
    /// Stream must be ordered
    Ordered,

    /// Stream can be unordered
    Unordered,
}
