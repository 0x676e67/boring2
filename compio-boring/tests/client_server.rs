use boring::ssl::{SslConnector, SslMethod};
use compio::io::AsyncReadExt;
use compio::net::TcpStream;
use compio_io::AsyncWrite;
use std::net::ToSocketAddrs;

#[compio::test]
async fn google() {
    let addr = "google.com:443".to_socket_addrs().unwrap().next().unwrap();
    let stream = TcpStream::connect(&addr).await.unwrap();

    let config = SslConnector::builder(SslMethod::tls())
        .unwrap()
        .build()
        .configure()
        .unwrap();

    let mut stream = compio_boring2::connect(config, "google.com", stream)
        .await
        .unwrap();

    stream.write(b"GET / HTTP/1.0\r\n\r\n").await.unwrap();
    stream.flush().await.unwrap();
    let (_, buf) = stream.read_to_end(vec![]).await.unwrap();
    stream.shutdown().await.unwrap();
    let response = String::from_utf8_lossy(&buf);
    let response = response.trim_end();

    // any response code is fine
    assert!(response.starts_with("HTTP/1.0 "));
    assert!(response.ends_with("</html>") || response.ends_with("</HTML>"));
}
