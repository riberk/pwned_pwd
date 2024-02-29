pub struct Downloader {}

// impl Downloader {
//     pub async fn download(&self) -> impl Stream<Item = PwnedPwd> {

//         let (p, r) = mpsc::channel(2048);

//         let text = reqwest::get(&self.base_uri).await.unwrap().text().await.unwrap();

//         while let Some(r) = stream.next().await {
//             let bytes = r.unwrap();

//         }

//         r
//     }
// }
