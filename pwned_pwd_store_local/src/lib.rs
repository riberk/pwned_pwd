use std::cmp::Ordering;
use std::fs::{remove_file, rename, File, OpenOptions};
use std::io::{self, prelude::*, BufWriter};
use std::path::PathBuf;

use futures::StreamExt;
use futures::{future::BoxFuture, Stream};
use pwned_pwd_core::PwnedPwd;
use pwned_pwd_store::Store;

/// What should we do when pwned passwords file exists
#[derive(Debug, Clone)]
pub enum ExistenceBehaviour {
    /// Removes old file and then creates new file and writes into in
    /// The behaviour is useful when you there is no additional space
    /// to download a second version
    /// But during download an original file is not available!
    /// And if the download is interrupted, the original file will be deleted anyway
    RemoveOldThenCreateNew,

    /// Downloads a file into the download_path then replace an original
    /// If the download_path is None then the file_path from a LocalStore will be used
    /// The download_path MUST be on the same mountpoint with a LocalStore.file_path
    /// because an old file will be renamed into a new file after a download
    DownloadThenReplace { download_path: Option<PathBuf> },
}

impl Default for ExistenceBehaviour {
    fn default() -> Self {
        Self::DownloadThenReplace {
            download_path: None,
        }
    }
}

struct PwdFile {
    file: BufWriter<File>,
    path: PathBuf,
    move_on_complete_to: Option<PathBuf>,
}

impl PwdFile {
    fn write(&mut self, pwd: PwnedPwd) -> io::Result<()> {
        self.file.write_all(&pwd.sha1)
    }

    fn complete(mut self) -> io::Result<()> {
        self.file.flush()?;
        drop(self.file);

        if let Some(move_to) = self.move_on_complete_to {
            rename(&self.path, &move_to)?;
        }

        Ok(())
    }
}

pub struct LocalStore {
    file_path: PathBuf,
    existence_behaviour: ExistenceBehaviour,
    buff_capacity: Option<usize>,
}

impl LocalStore {
    const DEFAULT_BUF_SIZE: usize = 8 * 1024;

    fn open_write(&self) -> io::Result<PwdFile> {
        let (path, move_on_complete_to) = match &self.existence_behaviour {
            ExistenceBehaviour::RemoveOldThenCreateNew => (self.file_path.clone(), None),
            ExistenceBehaviour::DownloadThenReplace { download_path } => {
                let path = download_path
                    .as_deref()
                    .map(|p| p.to_path_buf())
                    .unwrap_or_else(|| self.file_path.with_file_name("download_tmp"));
                (path, Some(self.file_path.clone()))
            }
        };

        if path.exists() {
            remove_file(&path)?
        }

        let mut options = OpenOptions::new();
        options.create_new(true);
        options.write(true);
        options.read(true);

        let file = BufWriter::with_capacity(
            self.buff_capacity.unwrap_or(Self::DEFAULT_BUF_SIZE),
            options.open(&path)?,
        );

        Ok(PwdFile {
            file,
            path,
            move_on_complete_to,
        })
    }

    fn open_read(&self) -> io::Result<File> {
        let mut options = OpenOptions::new();
        options.read(true);
        options.open(&self.file_path)
    }
}

/// A store which saves ordered password hashes as bytes into a file and searches in it with binary search
impl Store for LocalStore {
    type Error = std::io::Error;

    fn save<
        'a,
        S: 'a + Stream<Item = pwned_pwd_core::PwnedPwd> + std::marker::Unpin + std::marker::Send,
    >(
        &'a self,
        mut s: S,
    ) -> BoxFuture<'a, Result<(), Self::Error>> {
        Box::pin(async move {
            let mut pwd_file = self.open_write()?;

            while let Some(pwned_pwd) = s.next().await {
                pwd_file.write(pwned_pwd)?;
            }

            pwd_file.complete()?;
            Ok(())
        })
    }

    fn exists<'a>(&'a self, val: [u8; 20]) -> BoxFuture<'a, Result<bool, Self::Error>> {
        Box::pin(async move {
            let mut file = self.open_read()?;
            exists(&mut file, val)
        })
    }
}

fn exists<T: Seek + Read>(data: &mut T, x: [u8; 20]) -> Result<bool, std::io::Error> {
    let mut size = data.seek(io::SeekFrom::End(0))? / 20;
    let mut left = 0u64;
    let mut right = size;
    let mut buf = [0u8; 20];

    while left < right {
        let mid = left + size / 2;

        data.seek(io::SeekFrom::Start(mid * 20))?;
        data.read_exact(&mut buf)?;

        let cmp = (&buf).cmp(&x);

        left = if cmp == Ordering::Less { mid + 1 } else { left };
        right = if cmp == Ordering::Greater { mid } else { right };

        if cmp == Ordering::Equal {
            return Ok(true);
        }

        size = right - left;
    }

    Ok(false)
}

#[cfg(test)]
mod tests {
    use std::{env::temp_dir, io::Cursor};

    use futures::SinkExt;
    use hex_literal::hex;

    use super::*;

    #[test]
    fn exists_even_found() {
        let data = hex!(
            "
            21BD4004DDDC80AE4683948C5A1C5903584D8087
            21BD400C53D0B33029D7FE4FB08D3D1C9832D2ED
            21BD40110328459B74EC3CC4ADCE47093DA97FD0
            21BD4011CFFB38DFAD7E2FB4EE6ECED2ABCBBA0D
            21BD401223249190CD4C2B5E2537329726EC5667
            21BD4021BFAACC3E46C4FC74BE8E7D2FDF7CF698
            21BD4026DC435DCAB3564A0FD64AD921D827E146
            21BD4026F2E5BA164D1B277D9AF5085249F414DB
            21BD402A437B1A6FA37515B549B5D830E838CCC4
            21BD402C77AFF03FC91842C503DB0BB83AB1BBE6
            21BD402CDE32C2D1295997B3CE1475C828BA20CE
            21BD402EE1FBAB40E737BDB81EDF820EB621B1A9
            21BD4030368B0426D8F5497810ACC3AAFE6FC5F1
            21BD403D9886FA118CE12F02212EEE72B3C3BD4A
        "
        );

        let mut cursor = Cursor::new(data);

        assert!(exists(
            &mut cursor,
            hex!("21BD4004DDDC80AE4683948C5A1C5903584D8087")
        )
        .unwrap());
        assert!(exists(
            &mut cursor,
            hex!("21BD400C53D0B33029D7FE4FB08D3D1C9832D2ED")
        )
        .unwrap());
        assert!(exists(
            &mut cursor,
            hex!("21BD40110328459B74EC3CC4ADCE47093DA97FD0")
        )
        .unwrap());
        assert!(exists(
            &mut cursor,
            hex!("21BD4011CFFB38DFAD7E2FB4EE6ECED2ABCBBA0D")
        )
        .unwrap());
        assert!(exists(
            &mut cursor,
            hex!("21BD401223249190CD4C2B5E2537329726EC5667")
        )
        .unwrap());
        assert!(exists(
            &mut cursor,
            hex!("21BD4021BFAACC3E46C4FC74BE8E7D2FDF7CF698")
        )
        .unwrap());
        assert!(exists(
            &mut cursor,
            hex!("21BD4026DC435DCAB3564A0FD64AD921D827E146")
        )
        .unwrap());
        assert!(exists(
            &mut cursor,
            hex!("21BD4026F2E5BA164D1B277D9AF5085249F414DB")
        )
        .unwrap());
        assert!(exists(
            &mut cursor,
            hex!("21BD402A437B1A6FA37515B549B5D830E838CCC4")
        )
        .unwrap());
        assert!(exists(
            &mut cursor,
            hex!("21BD402C77AFF03FC91842C503DB0BB83AB1BBE6")
        )
        .unwrap());
        assert!(exists(
            &mut cursor,
            hex!("21BD402CDE32C2D1295997B3CE1475C828BA20CE")
        )
        .unwrap());
        assert!(exists(
            &mut cursor,
            hex!("21BD402EE1FBAB40E737BDB81EDF820EB621B1A9")
        )
        .unwrap());
        assert!(exists(
            &mut cursor,
            hex!("21BD4030368B0426D8F5497810ACC3AAFE6FC5F1")
        )
        .unwrap());
        assert!(exists(
            &mut cursor,
            hex!("21BD403D9886FA118CE12F02212EEE72B3C3BD4A")
        )
        .unwrap());
    }

    #[test]
    fn exists_odd_found() {
        let data = hex!(
            "
            21BD4004DDDC80AE4683948C5A1C5903584D8087
            21BD400C53D0B33029D7FE4FB08D3D1C9832D2ED
            21BD40110328459B74EC3CC4ADCE47093DA97FD0
            21BD4011CFFB38DFAD7E2FB4EE6ECED2ABCBBA0D
            21BD401223249190CD4C2B5E2537329726EC5667
            21BD4021BFAACC3E46C4FC74BE8E7D2FDF7CF698
            21BD4026DC435DCAB3564A0FD64AD921D827E146
            21BD4026F2E5BA164D1B277D9AF5085249F414DB
            21BD402A437B1A6FA37515B549B5D830E838CCC4
            21BD402C77AFF03FC91842C503DB0BB83AB1BBE6
            21BD402CDE32C2D1295997B3CE1475C828BA20CE
            21BD402EE1FBAB40E737BDB81EDF820EB621B1A9
            21BD4030368B0426D8F5497810ACC3AAFE6FC5F1
        "
        );

        let mut cursor = Cursor::new(data);

        assert!(exists(
            &mut cursor,
            hex!("21BD4004DDDC80AE4683948C5A1C5903584D8087")
        )
        .unwrap());
        assert!(exists(
            &mut cursor,
            hex!("21BD400C53D0B33029D7FE4FB08D3D1C9832D2ED")
        )
        .unwrap());
        assert!(exists(
            &mut cursor,
            hex!("21BD40110328459B74EC3CC4ADCE47093DA97FD0")
        )
        .unwrap());
        assert!(exists(
            &mut cursor,
            hex!("21BD4011CFFB38DFAD7E2FB4EE6ECED2ABCBBA0D")
        )
        .unwrap());
        assert!(exists(
            &mut cursor,
            hex!("21BD401223249190CD4C2B5E2537329726EC5667")
        )
        .unwrap());
        assert!(exists(
            &mut cursor,
            hex!("21BD4021BFAACC3E46C4FC74BE8E7D2FDF7CF698")
        )
        .unwrap());
        assert!(exists(
            &mut cursor,
            hex!("21BD4026DC435DCAB3564A0FD64AD921D827E146")
        )
        .unwrap());
        assert!(exists(
            &mut cursor,
            hex!("21BD4026F2E5BA164D1B277D9AF5085249F414DB")
        )
        .unwrap());
        assert!(exists(
            &mut cursor,
            hex!("21BD402A437B1A6FA37515B549B5D830E838CCC4")
        )
        .unwrap());
        assert!(exists(
            &mut cursor,
            hex!("21BD402C77AFF03FC91842C503DB0BB83AB1BBE6")
        )
        .unwrap());
        assert!(exists(
            &mut cursor,
            hex!("21BD402CDE32C2D1295997B3CE1475C828BA20CE")
        )
        .unwrap());
        assert!(exists(
            &mut cursor,
            hex!("21BD402EE1FBAB40E737BDB81EDF820EB621B1A9")
        )
        .unwrap());
        assert!(exists(
            &mut cursor,
            hex!("21BD4030368B0426D8F5497810ACC3AAFE6FC5F1")
        )
        .unwrap());
    }

    #[test]
    fn exists_odd_not_found() {
        let data = hex!(
            "
            21BD4004DDDC80AE4683948C5A1C5903584D8087
            21BD400C53D0B33029D7FE4FB08D3D1C9832D2ED
            21BD40110328459B74EC3CC4ADCE47093DA97FD0
            21BD4011CFFB38DFAD7E2FB4EE6ECED2ABCBBA0D
            21BD401223249190CD4C2B5E2537329726EC5667
            21BD4021BFAACC3E46C4FC74BE8E7D2FDF7CF698
            21BD4026DC435DCAB3564A0FD64AD921D827E146
            21BD4026F2E5BA164D1B277D9AF5085249F414DB
            21BD402A437B1A6FA37515B549B5D830E838CCC4
            21BD402C77AFF03FC91842C503DB0BB83AB1BBE6
            21BD402CDE32C2D1295997B3CE1475C828BA20CE
            21BD402EE1FBAB40E737BDB81EDF820EB621B1A9
            21BD4030368B0426D8F5497810ACC3AAFE6FC5F1
        "
        );

        let mut cursor = Cursor::new(data);
        assert!(!exists(
            &mut cursor,
            hex!("21BD4004DDDC80AE4683948C5A1C5903584D8086")
        )
        .unwrap());
        assert!(!exists(
            &mut cursor,
            hex!("21BD4004DDDC80AE4683948C5A1C5903584D8088")
        )
        .unwrap());
        assert!(!exists(
            &mut cursor,
            hex!("21BD400C53D0B33029D7FE4FB08D3D1C9832D2EC")
        )
        .unwrap());
        assert!(!exists(
            &mut cursor,
            hex!("21BD400C53D0B33029D7FE4FB08D3D1C9832D2EE")
        )
        .unwrap());
        assert!(!exists(
            &mut cursor,
            hex!("21BD40110328459B74EC3CC4ADCE47093DA97FCF")
        )
        .unwrap());
        assert!(!exists(
            &mut cursor,
            hex!("21BD40110328459B74EC3CC4ADCE47093DA97FD1")
        )
        .unwrap());
        assert!(!exists(
            &mut cursor,
            hex!("21BD4011CFFB38DFAD7E2FB4EE6ECED2ABCBBA0C")
        )
        .unwrap());
        assert!(!exists(
            &mut cursor,
            hex!("21BD4011CFFB38DFAD7E2FB4EE6ECED2ABCBBA0E")
        )
        .unwrap());
        assert!(!exists(
            &mut cursor,
            hex!("21BD401223249190CD4C2B5E2537329726EC5666")
        )
        .unwrap());
        assert!(!exists(
            &mut cursor,
            hex!("21BD401223249190CD4C2B5E2537329726EC5668")
        )
        .unwrap());
        assert!(!exists(
            &mut cursor,
            hex!("21BD4021BFAACC3E46C4FC74BE8E7D2FDF7CF697")
        )
        .unwrap());
        assert!(!exists(
            &mut cursor,
            hex!("21BD4021BFAACC3E46C4FC74BE8E7D2FDF7CF699")
        )
        .unwrap());
        assert!(!exists(
            &mut cursor,
            hex!("21BD4026DC435DCAB3564A0FD64AD921D827E145")
        )
        .unwrap());
        assert!(!exists(
            &mut cursor,
            hex!("21BD4026DC435DCAB3564A0FD64AD921D827E147")
        )
        .unwrap());
        assert!(!exists(
            &mut cursor,
            hex!("21BD4026F2E5BA164D1B277D9AF5085249F414DA")
        )
        .unwrap());
        assert!(!exists(
            &mut cursor,
            hex!("21BD4026F2E5BA164D1B277D9AF5085249F414DC")
        )
        .unwrap());
        assert!(!exists(
            &mut cursor,
            hex!("21BD402A437B1A6FA37515B549B5D830E838CCC3")
        )
        .unwrap());
        assert!(!exists(
            &mut cursor,
            hex!("21BD402A437B1A6FA37515B549B5D830E838CCC5")
        )
        .unwrap());
        assert!(!exists(
            &mut cursor,
            hex!("21BD402C77AFF03FC91842C503DB0BB83AB1BBE5")
        )
        .unwrap());
        assert!(!exists(
            &mut cursor,
            hex!("21BD402C77AFF03FC91842C503DB0BB83AB1BBE7")
        )
        .unwrap());
        assert!(!exists(
            &mut cursor,
            hex!("21BD402CDE32C2D1295997B3CE1475C828BA20CD")
        )
        .unwrap());
        assert!(!exists(
            &mut cursor,
            hex!("21BD402CDE32C2D1295997B3CE1475C828BA20CF")
        )
        .unwrap());
        assert!(!exists(
            &mut cursor,
            hex!("21BD402EE1FBAB40E737BDB81EDF820EB621B1A8")
        )
        .unwrap());
        assert!(!exists(
            &mut cursor,
            hex!("21BD402EE1FBAB40E737BDB81EDF820EB621B1AA")
        )
        .unwrap());
        assert!(!exists(
            &mut cursor,
            hex!("21BD4030368B0426D8F5497810ACC3AAFE6FC5F0")
        )
        .unwrap());
        assert!(!exists(
            &mut cursor,
            hex!("21BD4030368B0426D8F5497810ACC3AAFE6FC5F2")
        )
        .unwrap());
    }

    #[test]
    fn exists_even_not_found() {
        let data = hex!(
            "
            21BD4004DDDC80AE4683948C5A1C5903584D8087
            21BD400C53D0B33029D7FE4FB08D3D1C9832D2ED
            21BD40110328459B74EC3CC4ADCE47093DA97FD0
            21BD4011CFFB38DFAD7E2FB4EE6ECED2ABCBBA0D
            21BD401223249190CD4C2B5E2537329726EC5667
            21BD4021BFAACC3E46C4FC74BE8E7D2FDF7CF698
            21BD4026DC435DCAB3564A0FD64AD921D827E146
            21BD4026F2E5BA164D1B277D9AF5085249F414DB
            21BD402A437B1A6FA37515B549B5D830E838CCC4
            21BD402C77AFF03FC91842C503DB0BB83AB1BBE6
            21BD402CDE32C2D1295997B3CE1475C828BA20CE
            21BD402EE1FBAB40E737BDB81EDF820EB621B1A9
            21BD4030368B0426D8F5497810ACC3AAFE6FC5F1
            21BD403D9886FA118CE12F02212EEE72B3C3BD4A
        "
        );

        let mut cursor = Cursor::new(data);
        assert!(!exists(
            &mut cursor,
            hex!("21BD4004DDDC80AE4683948C5A1C5903584D8086")
        )
        .unwrap());
        assert!(!exists(
            &mut cursor,
            hex!("21BD4004DDDC80AE4683948C5A1C5903584D8088")
        )
        .unwrap());
        assert!(!exists(
            &mut cursor,
            hex!("21BD400C53D0B33029D7FE4FB08D3D1C9832D2EC")
        )
        .unwrap());
        assert!(!exists(
            &mut cursor,
            hex!("21BD400C53D0B33029D7FE4FB08D3D1C9832D2EE")
        )
        .unwrap());
        assert!(!exists(
            &mut cursor,
            hex!("21BD40110328459B74EC3CC4ADCE47093DA97FCF")
        )
        .unwrap());
        assert!(!exists(
            &mut cursor,
            hex!("21BD40110328459B74EC3CC4ADCE47093DA97FD1")
        )
        .unwrap());
        assert!(!exists(
            &mut cursor,
            hex!("21BD4011CFFB38DFAD7E2FB4EE6ECED2ABCBBA0C")
        )
        .unwrap());
        assert!(!exists(
            &mut cursor,
            hex!("21BD4011CFFB38DFAD7E2FB4EE6ECED2ABCBBA0E")
        )
        .unwrap());
        assert!(!exists(
            &mut cursor,
            hex!("21BD401223249190CD4C2B5E2537329726EC5666")
        )
        .unwrap());
        assert!(!exists(
            &mut cursor,
            hex!("21BD401223249190CD4C2B5E2537329726EC5668")
        )
        .unwrap());
        assert!(!exists(
            &mut cursor,
            hex!("21BD4021BFAACC3E46C4FC74BE8E7D2FDF7CF697")
        )
        .unwrap());
        assert!(!exists(
            &mut cursor,
            hex!("21BD4021BFAACC3E46C4FC74BE8E7D2FDF7CF699")
        )
        .unwrap());
        assert!(!exists(
            &mut cursor,
            hex!("21BD4026DC435DCAB3564A0FD64AD921D827E145")
        )
        .unwrap());
        assert!(!exists(
            &mut cursor,
            hex!("21BD4026DC435DCAB3564A0FD64AD921D827E147")
        )
        .unwrap());
        assert!(!exists(
            &mut cursor,
            hex!("21BD4026F2E5BA164D1B277D9AF5085249F414DA")
        )
        .unwrap());
        assert!(!exists(
            &mut cursor,
            hex!("21BD4026F2E5BA164D1B277D9AF5085249F414DC")
        )
        .unwrap());
        assert!(!exists(
            &mut cursor,
            hex!("21BD402A437B1A6FA37515B549B5D830E838CCC3")
        )
        .unwrap());
        assert!(!exists(
            &mut cursor,
            hex!("21BD402A437B1A6FA37515B549B5D830E838CCC5")
        )
        .unwrap());
        assert!(!exists(
            &mut cursor,
            hex!("21BD402C77AFF03FC91842C503DB0BB83AB1BBE5")
        )
        .unwrap());
        assert!(!exists(
            &mut cursor,
            hex!("21BD402C77AFF03FC91842C503DB0BB83AB1BBE7")
        )
        .unwrap());
        assert!(!exists(
            &mut cursor,
            hex!("21BD402CDE32C2D1295997B3CE1475C828BA20CD")
        )
        .unwrap());
        assert!(!exists(
            &mut cursor,
            hex!("21BD402CDE32C2D1295997B3CE1475C828BA20CF")
        )
        .unwrap());
        assert!(!exists(
            &mut cursor,
            hex!("21BD402EE1FBAB40E737BDB81EDF820EB621B1A8")
        )
        .unwrap());
        assert!(!exists(
            &mut cursor,
            hex!("21BD402EE1FBAB40E737BDB81EDF820EB621B1AA")
        )
        .unwrap());
        assert!(!exists(
            &mut cursor,
            hex!("21BD4030368B0426D8F5497810ACC3AAFE6FC5F0")
        )
        .unwrap());
        assert!(!exists(
            &mut cursor,
            hex!("21BD4030368B0426D8F5497810ACC3AAFE6FC5F2")
        )
        .unwrap());
        assert!(!exists(
            &mut cursor,
            hex!("21BD403D9886FA118CE12F02212EEE72B3C3BD49")
        )
        .unwrap());
        assert!(!exists(
            &mut cursor,
            hex!("21BD403D9886FA118CE12F02212EEE72B3C3BD4B")
        )
        .unwrap());
    }

    #[tokio::test]
    async fn store_exists() {
        let data = hex!(
            "
            21BD4004DDDC80AE4683948C5A1C5903584D8087
            21BD400C53D0B33029D7FE4FB08D3D1C9832D2ED
            21BD40110328459B74EC3CC4ADCE47093DA97FD0
            21BD4011CFFB38DFAD7E2FB4EE6ECED2ABCBBA0D
            21BD401223249190CD4C2B5E2537329726EC5667
            21BD4021BFAACC3E46C4FC74BE8E7D2FDF7CF698
            21BD4026DC435DCAB3564A0FD64AD921D827E146
            21BD4026F2E5BA164D1B277D9AF5085249F414DB
            21BD402A437B1A6FA37515B549B5D830E838CCC4
            21BD402C77AFF03FC91842C503DB0BB83AB1BBE6
            21BD402CDE32C2D1295997B3CE1475C828BA20CE
            21BD402EE1FBAB40E737BDB81EDF820EB621B1A9
            21BD4030368B0426D8F5497810ACC3AAFE6FC5F1
            21BD403D9886FA118CE12F02212EEE72B3C3BD4A
        "
        );
        let mut tmp_file_path = temp_dir();
        tmp_file_path.push("pwned_pwd_tests_store_exists");

        let mut file = File::create(&tmp_file_path).expect("unable to create file");
        file.write_all(&data).expect("unable to write to file");
        file.flush().expect("flush error");
        drop(file);

        let store = LocalStore {
            file_path: tmp_file_path,
            existence_behaviour: Default::default(),
            buff_capacity: None,
        };

        assert!(store
            .exists(hex!("21BD4004DDDC80AE4683948C5A1C5903584D8087"))
            .await
            .unwrap());
        assert!(store
            .exists(hex!("21BD401223249190CD4C2B5E2537329726EC5667"))
            .await
            .unwrap());
        assert!(store
            .exists(hex!("21BD402A437B1A6FA37515B549B5D830E838CCC4"))
            .await
            .unwrap());
        assert!(store
            .exists(hex!("21BD403D9886FA118CE12F02212EEE72B3C3BD4A"))
            .await
            .unwrap());
        assert!(!store
            .exists(hex!("21BD403D9886FA118CE12F02212EEE72B3C3BD4B"))
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn store_save() {
        let (mut sender, receiver) = futures::channel::mpsc::channel::<PwnedPwd>(256 * 1024);
        sender
            .send(PwnedPwd {
                sha1: hex!("21BD4004DDDC80AE4683948C5A1C5903584D8087"),
            })
            .await
            .unwrap();
        sender
            .send(PwnedPwd {
                sha1: hex!("21BD400C53D0B33029D7FE4FB08D3D1C9832D2ED"),
            })
            .await
            .unwrap();
        sender
            .send(PwnedPwd {
                sha1: hex!("21BD40110328459B74EC3CC4ADCE47093DA97FD0"),
            })
            .await
            .unwrap();
        sender
            .send(PwnedPwd {
                sha1: hex!("21BD4011CFFB38DFAD7E2FB4EE6ECED2ABCBBA0D"),
            })
            .await
            .unwrap();
        sender.close_channel();

        let mut tmp_file_path = temp_dir();
        tmp_file_path.push("pwned_pwd_tests_store_save");

        if tmp_file_path.exists() {
            remove_file(&tmp_file_path).unwrap();
        }

        let store = LocalStore {
            file_path: tmp_file_path,
            existence_behaviour: Default::default(),
            buff_capacity: None,
        };

        store.save(receiver).await.expect("unable to save");

        let mut file = File::open(&store.file_path).expect("Unable to open the file");
        let mut file_data = Vec::new();
        file.read_to_end(&mut file_data).unwrap();

        assert_eq!(
            hex!(
                "
            21BD4004DDDC80AE4683948C5A1C5903584D8087
            21BD400C53D0B33029D7FE4FB08D3D1C9832D2ED
            21BD40110328459B74EC3CC4ADCE47093DA97FD0
            21BD4011CFFB38DFAD7E2FB4EE6ECED2ABCBBA0D
        "
            ),
            file_data.as_slice()
        );
    }
}
