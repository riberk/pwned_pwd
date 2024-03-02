use std::sync::{
    atomic::{AtomicU16, AtomicU32, AtomicU64, Ordering::SeqCst},
    Arc,
};

use futures::{
    channel::mpsc::{self},
    SinkExt, Stream,
};
use pwned_pwd_core::*;
use tracing::Instrument;
use url::Url;

#[derive(Debug)]
pub struct Downloader {
    base_url: Url,
    max_spawns: u32,
}

#[derive(thiserror::Error, Debug)]
pub enum DownloadErrorKind {
    #[error("Http request error")]
    Reqwest(#[from] reqwest::Error),

    #[error("Parsing error: '{0}'")]
    Parse(#[from] ParseError),

    #[error("Channel send error")]
    SendError(#[from] mpsc::SendError),
}

#[derive(thiserror::Error, Debug)]
#[error("Downloading prefix '{prefix}' error")]
pub struct DownloadError {
    prefix: Prefix,

    kind: DownloadErrorKind,
}

trait IntoDownloadError<T> {
    fn into_download_error(self, prefix: &Prefix) -> Result<T, DownloadError>;
}

impl<T, E: Into<DownloadErrorKind>> IntoDownloadError<T> for Result<T, E> {
    fn into_download_error(self, prefix: &Prefix) -> Result<T, DownloadError> {
        self.map_err(|e| DownloadError {
            prefix: prefix.clone(),
            kind: e.into(),
        })
    }
}

impl Downloader {
    async fn download_by_prefix(base_url: &Url, prefix: Prefix) -> Result<Chunk, DownloadError> {
        let str_prefix = prefix.as_prefix_str();
        async move {
            let url = base_url.join(str_prefix.as_ref()).expect("Invalid url");
            let response = reqwest::get(url).await.into_download_error(&prefix)?;
            let content = response.text().await.into_download_error(&prefix)?;
            let parser = prefix.parser();

            let passwords = content
                .lines()
                .map(|l| parser.parse(l))
                .collect::<Result<Vec<_>, _>>()
                .into_download_error(&prefix)?;

            Ok(Chunk { prefix, passwords })
        }
        .instrument(tracing::info_span!("download_by_prefix"))
        .await
    }

    pub async fn download<Prefixes: Iterator<Item = Prefix> + Send + 'static>(
        &self,
        prefixes: Prefixes,
    ) -> impl Stream<Item = Result<Chunk, DownloadError>> {
        let (sender, pwd_stream) = mpsc::unbounded();

        let prefixes_processed = Arc::new(AtomicU32::new(0));
        let pawwsords_processed = Arc::new(AtomicU64::new(0));
        let running_tasks = Arc::new(AtomicU16::new(0));
        let sender = Arc::new(futures::lock::Mutex::new(sender));

        let max_spawns = self.max_spawns;

        let prefixes = Arc::new(futures::lock::Mutex::new(prefixes));

        let mut futures = Vec::with_capacity(max_spawns as usize);

        for i in 0..max_spawns {
            let sender = sender.clone();
            let url = self.base_url.clone();
            let prefixes_processed = prefixes_processed.clone();
            let passwords_processed = pawwsords_processed.clone();
            let running_tasks = running_tasks.clone();

            let prefixes = prefixes.clone();

            futures.push(
                async move {
                    running_tasks.fetch_add(1, SeqCst);
                    loop {
                        let prefix = {
                            let mut prefixes_guard = prefixes.lock().await;
                            prefixes_guard.next()
                        };

                        let prefix = match prefix {
                            Some(next_prefix) => next_prefix,
                            None => {
                                tracing::debug!("Prefixes are exhausted");
                                break;
                            }
                        };

                        tracing::trace!(
                            "prefix '{}' is downloading",
                            prefix.as_prefix_str().as_ref()
                        );

                        let res = Self::download_by_prefix(&url, prefix).await;

                        tracing::debug!("Prefix '{}' downloaded", prefix.as_prefix_str().as_ref());

                        match res {
                            Ok(chunk) => {
                                let len = chunk.passwords.len();

                                {
                                    let mut sender = sender.lock().await;
                                    tracing::trace!(
                                        "Sending chunk '{}' : {}",
                                        chunk.prefix.as_prefix_str().as_ref(),
                                        len
                                    );

                                    if let Err(e) = sender.send(Ok(chunk)).await {
                                        tracing::warn!("SendError({})", e);
                                        break;
                                    }
                                }

                                prefixes_processed.fetch_add(1, SeqCst);
                                passwords_processed.fetch_add(len as u64, SeqCst);
                            }
                            Err(e) => {
                                tracing::info!("DownloadErr");
                                let mut sender = sender.lock().await;
                                let _ = sender.send(Err(e)).await;
                                sender.close_channel();
                                break;
                            }
                        }
                    }

                    running_tasks.fetch_sub(1, SeqCst);
                    let mut sender = sender.lock().await;
                    if running_tasks.load(SeqCst) == 0 {
                        let _ = sender.close().await;
                    }
                }
                .instrument(tracing::info_span!("downloader", i = i)),
            );
        }

        for f in futures {
            tokio::spawn(f);
        }

        pwd_stream
    }
}

#[cfg(test)]
#[rustfmt::skip]
mod tests {
    use std::collections::HashSet;

    use futures::StreamExt;
    use tracing::Level;

    use super::*;

    #[tokio::test(flavor = "multi_thread", worker_threads = 64)]
    async fn download() {

        let _ = tracing_subscriber::fmt::Subscriber::builder()
        .json()
        .with_max_level(Level::INFO)
        .try_init();

        let downloader = Downloader {
            base_url: "https://api.pwnedpasswords.com/range/".parse().unwrap(),
            max_spawns: 4,
        };

        let stream = downloader.download([
            Prefix::create(0x00000),
            Prefix::create(0x00001),
            Prefix::create(0x00002),
            Prefix::create(0x00003),
            Prefix::create(0x0000F),
            Prefix::create(0x000FF),
            Prefix::create(0x00FFF),
            Prefix::create(0x0FFFF),
            Prefix::create(0xFFFFF),
        ].into_iter().map(|v| v.unwrap())).await;

        let res = stream.map(|r| r.unwrap()).collect::<Vec<_>>().await.into_iter().flat_map(|a| a.passwords).map(|v| hex::encode_upper(v.sha1)).collect::<HashSet<_>>();

        assert!(!res.is_empty());

        assert!(res.contains("00000010F4B38525354491E099EB1796278544B1"));
        assert!(res.contains("000010005DE2A9668A41F6A508AFB6A6FC4A5610"));
        assert!(res.contains("000020072ED4C9CF6E5F4398708CCD099B89AB8F"));
        assert!(res.contains("00003098AE6E23BAF2BC1D865DD127158732E061"));
        assert!(res.contains("0000F0B6A0B74B9EA8D0D365AD29C2C4FED6C4E4"));
        assert!(res.contains("000FF0C130B4F0411E99C98FDFE7C9C9C0F60432"));
        assert!(res.contains("00FFF09A21FA6CAFCD102A60E593A4512CE92B8A"));
        assert!(res.contains("0FFFFFFEE390785490887CF0D523654A793B3832"));
        assert!(res.contains("FFFFF9D7385261CA008A9777A93D86A6AB997F57"));

        
    }
}
