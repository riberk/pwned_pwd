use std::collections::{BTreeMap, BTreeSet};

use futures::{ready, Stream, StreamExt};
use pwned_pwd_core::{Chunk, Prefix};
use pwned_pwd_downloader::{DownloadError, Downloader};
use pwned_pwd_store::Store;

use pin_project_lite::pin_project;

pin_project! {
    #[derive(Debug)]
    #[must_use = "streams do nothing unless polled"]
    struct OrderedStream<St> {
        #[pin]
        stream: St,
        buf: BTreeMap<Prefix, Chunk>,
        first_expected_prefix: Prefix,
        expected_prefix: Option<Prefix>,
    }
}

// pub async fn download_to_store<S: Store>(
//     downloader: Downloader,
//     store: &S
// ) {

// }

impl<S: Stream<Item = Result<Chunk, DownloadError>>> Stream for OrderedStream<S> {
    type Item = Result<Chunk, DownloadError>;

    fn poll_next(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        let this = self.project();

        if let Some(expected_prefix) = this.expected_prefix {
            if let Some(buf_chunk) = this.buf.remove(&expected_prefix) {
                *this.expected_prefix = expected_prefix.next();
                return std::task::Poll::Ready(Some(Ok(buf_chunk)));
            }
        }
        let next = ready!(this.stream.poll_next(cx));

        match next {
            Some(Ok(chunk)) => match this.expected_prefix {
                Some(expected_prefix) if expected_prefix != &chunk.prefix => {
                    this.buf.insert(chunk.prefix, chunk);
                    std::task::Poll::Pending
                }
                Some(_) => {
                    *this.expected_prefix = chunk.prefix.next();
                    std::task::Poll::Ready(Some(Ok(chunk)))
                }
                None => panic!("Unexpected value"),
            },
            Some(Err(err)) => std::task::Poll::Ready(Some(Err(err))),
            None => std::task::Poll::Ready(None),
        }
    }
}
