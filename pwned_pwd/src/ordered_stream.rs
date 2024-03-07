use std::collections::BTreeMap;

use futures::{ready, Stream};

use pin_project_lite::pin_project;

use crate::{chunk::Chunk, downloader::DownloadError, prefix::Prefix};

pin_project! {
    #[derive(Debug)]
    #[must_use = "streams do nothing unless polled"]
    pub(crate) struct OrderedStream<St> {
        #[pin]
        stream: St,
        buf: BTreeMap<Prefix, Chunk>,
        first_expected_prefix: Prefix,
        expected_prefix: Option<Prefix>,
    }
}

impl<St: Stream<Item = Result<Chunk, DownloadError>>> OrderedStream<St> {
    pub fn new(st: St, first_expected_prefix: Prefix) -> Self {
        Self {
            stream: st,
            buf: Default::default(),
            first_expected_prefix,
            expected_prefix: Some(first_expected_prefix),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum OrderedStreamError {
    #[error("Discontinuous sequence")]
    Discontinuous,

    #[error("Download error: '{0}'")]
    DownloadError(DownloadError),
}

impl<S: Stream<Item = Result<Chunk, DownloadError>>> Stream for OrderedStream<S> {
    type Item = Result<Chunk, OrderedStreamError>;

    fn poll_next(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        let mut this = self.project();

        if let Some(expected_prefix) = this.expected_prefix {
            if let Some(buf_chunk) = this.buf.remove(expected_prefix) {
                *this.expected_prefix = expected_prefix.next();
                return std::task::Poll::Ready(Some(Ok(buf_chunk)));
            }
        }

        loop {
            match ready!(this.stream.as_mut().poll_next(cx)) {
                Some(Ok(chunk)) => match this.expected_prefix {
                    Some(expected_prefix) if expected_prefix != &chunk.prefix => {
                        this.buf.insert(chunk.prefix, chunk);
                        continue;
                    }

                    Some(_) => {
                        *this.expected_prefix = chunk.prefix.next();
                        return std::task::Poll::Ready(Some(Ok(chunk)));
                    }
                    None => {
                        return std::task::Poll::Ready(Some(Err(OrderedStreamError::Discontinuous)))
                    }
                },
                Some(Err(err)) => {
                    return std::task::Poll::Ready(Some(Err(OrderedStreamError::DownloadError(
                        err,
                    ))))
                }
                None => return std::task::Poll::Ready(None),
            }
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.buf.len(), self.stream.size_hint().1)
    }
}

impl<T: ?Sized> ChunksStreamExt for T where T: Stream<Item = Result<Chunk, DownloadError>> {}

pub(crate) trait ChunksStreamExt: Stream<Item = Result<Chunk, DownloadError>> {
    /// self MUST be continuous sequence and MUST contain an first_expected_prefix
    /// If it's not, 'next' will panic when sequence completed
    fn order_continuous_sequence(self, first_expected_prefix: Prefix) -> OrderedStream<Self>
    where
        Self: Sized,
    {
        OrderedStream::new(self, first_expected_prefix)
    }
}

#[cfg(test)]
#[rustfmt::skip]
mod tests {
    use futures::{stream, SinkExt, StreamExt};
    use super::*;

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn order_continuous_sequence_in_memory() {
        let expected = stream::iter([
            Ok(Chunk::empty(Prefix::create(0x00000).unwrap())),
            Ok(Chunk::empty(Prefix::create(0x00004).unwrap())),
            Ok(Chunk::empty(Prefix::create(0x00003).unwrap())),
            Ok(Chunk::empty(Prefix::create(0x00002).unwrap())),
            Ok(Chunk::empty(Prefix::create(0x00001).unwrap())),
            Ok(Chunk::empty(Prefix::create(0x00005).unwrap())),
        ])
        .order_continuous_sequence(Prefix::create(0x00000).unwrap())
        .map(|ch| ch.unwrap().prefix)
        .collect::<Vec<_>>()
        .await;


        assert_eq!(vec![
            Prefix::create(0x00000).unwrap(),
            Prefix::create(0x00001).unwrap(),
            Prefix::create(0x00002).unwrap(),
            Prefix::create(0x00003).unwrap(),
            Prefix::create(0x00004).unwrap(),
            Prefix::create(0x00005).unwrap(),
        ], expected);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn order_continuous_sequence_discontinuous() {
        let mut stream = stream::iter([
            Ok(Chunk::empty(Prefix::create(0xFFFFF).unwrap())),
            Ok(Chunk::empty(Prefix::create(0xFFFF1).unwrap())),
        ])
        .order_continuous_sequence(Prefix::create(0xFFFFF).unwrap())
        .map(|ch| ch.map(|ch| ch.prefix));

        assert_eq!(Prefix::create(0xFFFFF).unwrap(), stream.next().await.unwrap().unwrap());

        match stream.next().await.unwrap().unwrap_err() {
            OrderedStreamError::Discontinuous => {},
            v => panic!("Unexpected error: {}", v),
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn order_continuous_sequence_real_async() {
        let (mut sender, receiver) = futures::channel::mpsc::unbounded();

        let mut stream = receiver
        .order_continuous_sequence(Prefix::create(0x00000).unwrap())
        .map(|ch| ch.unwrap().prefix);

        let next_handle = tokio::spawn(async move {
            let value = stream.next().await;
            (stream, value)
        });

        assert!(!next_handle.is_finished());

        sender.send(Ok(Chunk::empty(Prefix::create(0x00002).unwrap()))).await.unwrap();

        assert!(!next_handle.is_finished());

        sender.send(Ok(Chunk::empty(Prefix::create(0x00000).unwrap()))).await.unwrap();

        let (mut stream, value) = next_handle.await.unwrap();

        assert_eq!(Prefix::create(0x00000).unwrap(), value.unwrap());

        
        let next_handle = tokio::spawn(async move {
            let value = stream.next().await;
            (stream, value)
        });
        assert!(!next_handle.is_finished());

        sender.send(Ok(Chunk::empty(Prefix::create(0x00003).unwrap()))).await.unwrap();
        sender.send(Ok(Chunk::empty(Prefix::create(0x00004).unwrap()))).await.unwrap();
        sender.send(Ok(Chunk::empty(Prefix::create(0x00005).unwrap()))).await.unwrap();

        assert!(!next_handle.is_finished());

        sender.send(Ok(Chunk::empty(Prefix::create(0x00001).unwrap()))).await.unwrap();
        let (mut stream, value) = next_handle.await.unwrap();

        assert_eq!(Prefix::create(0x00001).unwrap(), value.unwrap());
        assert_eq!(Prefix::create(0x00002).unwrap(), stream.next().await.unwrap());
        assert_eq!(Prefix::create(0x00003).unwrap(), stream.next().await.unwrap());
        assert_eq!(Prefix::create(0x00004).unwrap(), stream.next().await.unwrap());
        assert_eq!(Prefix::create(0x00005).unwrap(), stream.next().await.unwrap());

        sender.close().await.unwrap();

        assert_eq!(None, stream.next().await);
    }

}
