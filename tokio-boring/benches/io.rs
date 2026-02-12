use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use std::io::Cursor;
use std::pin::Pin;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::runtime::Runtime;

use boring::ssl::{SslConnector, SslMethod, SslVerifyMode};
use rustls::{ClientConfig, ServerConfig};
use rustls_pemfile::{certs, private_key};
use tokio_boring2::SslStream as BoringSslStream;
use tokio_rustls::{TlsAcceptor, TlsConnector};

const CERT_PEM: &[u8] = include_bytes!("../tests/cert.pem");
const KEY_PEM: &[u8] = include_bytes!("../tests/key.pem");

const SIZES: &[usize] = &[
    1024,      // 1KB
    4096,      // 4KB
    10_000,    // 10KB
    16384,     // 16KB
    65536,     // 64KB
    100_000,   // 100KB
    262144,    // 256KB
    1_000_000, // 1MB
    2_000_000, // 2MB
];

fn setup_boring_client() -> SslConnector {
    let mut connector = SslConnector::builder(SslMethod::tls()).unwrap();
    connector.set_verify(SslVerifyMode::NONE);
    connector.build()
}

fn setup_rustls_server() -> Arc<ServerConfig> {
    let cert_chain = certs(&mut Cursor::new(CERT_PEM))
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let key = private_key(&mut Cursor::new(KEY_PEM)).unwrap().unwrap();

    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)
        .unwrap();

    Arc::new(config)
}

fn setup_rustls_client() -> Arc<ClientConfig> {
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let config = ClientConfig::builder_with_provider(provider.into())
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerifier))
        .with_no_client_auth();

    Arc::new(config)
}

#[derive(Debug)]
struct NoVerifier;

impl rustls::client::danger::ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer,
        _intermediates: &[rustls::pki_types::CertificateDer],
        _server_name: &rustls::pki_types::ServerName,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

async fn boring_write_benchmark(size: usize) {
    let server_config = setup_rustls_server();
    let connector = setup_boring_client();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server = tokio::spawn(async move {
        let acceptor = TlsAcceptor::from(server_config);
        let (stream, _) = listener.accept().await.unwrap();
        let mut stream = acceptor.accept(stream).await.unwrap();

        let mut buf = vec![0u8; size];
        while stream.read_exact(&mut buf).await.is_ok() {
            // Just consume data
        }
    });

    let client = tokio::spawn(async move {
        let stream = TcpStream::connect(addr).await.unwrap();
        let ssl = boring::ssl::Ssl::new(connector.context()).unwrap();
        let mut stream = BoringSslStream::new(ssl, stream).unwrap();
        Pin::new(&mut stream).connect().await.unwrap();

        let data = vec![1u8; size];
        for _ in 0..100 {
            stream.write_all(&data).await.unwrap();
        }
        stream.shutdown().await.ok();
    });

    client.await.unwrap();
    server.abort();
}

async fn boring_read_benchmark(size: usize) {
    let server_config = setup_rustls_server();
    let connector = setup_boring_client();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server = tokio::spawn(async move {
        let acceptor = TlsAcceptor::from(server_config);
        let (stream, _) = listener.accept().await.unwrap();
        let mut stream = acceptor.accept(stream).await.unwrap();

        let data = vec![1u8; size];
        for _ in 0..100 {
            stream.write_all(&data).await.unwrap();
        }
        stream.shutdown().await.ok();
    });

    let client = tokio::spawn(async move {
        let stream = TcpStream::connect(addr).await.unwrap();
        let ssl = boring::ssl::Ssl::new(connector.context()).unwrap();
        let mut stream = BoringSslStream::new(ssl, stream).unwrap();
        Pin::new(&mut stream).connect().await.unwrap();

        let mut buf = vec![0u8; size];
        for _ in 0..100 {
            stream.read_exact(&mut buf).await.unwrap();
        }
    });

    client.await.unwrap();
    server.await.unwrap();
}

async fn rustls_write_benchmark(size: usize) {
    let server_config = setup_rustls_server();
    let client_config = setup_rustls_client();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server = tokio::spawn(async move {
        let acceptor = TlsAcceptor::from(server_config);
        let (stream, _) = listener.accept().await.unwrap();
        let mut stream = acceptor.accept(stream).await.unwrap();

        let mut buf = vec![0u8; size];
        while stream.read_exact(&mut buf).await.is_ok() {
            // Just consume data
        }
    });

    let client = tokio::spawn(async move {
        let connector = TlsConnector::from(client_config);
        let stream = TcpStream::connect(addr).await.unwrap();
        let domain = rustls::pki_types::ServerName::try_from("localhost").unwrap();
        let mut stream = connector.connect(domain, stream).await.unwrap();

        let data = vec![1u8; size];
        for _ in 0..100 {
            stream.write_all(&data).await.unwrap();
        }
        stream.shutdown().await.ok();
    });

    client.await.unwrap();
    server.abort();
}

async fn rustls_read_benchmark(size: usize) {
    let server_config = setup_rustls_server();
    let client_config = setup_rustls_client();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server = tokio::spawn(async move {
        let acceptor = TlsAcceptor::from(server_config);
        let (stream, _) = listener.accept().await.unwrap();
        let mut stream = acceptor.accept(stream).await.unwrap();

        let data = vec![1u8; size];
        for _ in 0..100 {
            stream.write_all(&data).await.unwrap();
        }
        stream.shutdown().await.ok();
    });

    let client = tokio::spawn(async move {
        let connector = TlsConnector::from(client_config);
        let stream = TcpStream::connect(addr).await.unwrap();
        let domain = rustls::pki_types::ServerName::try_from("localhost").unwrap();
        let mut stream = connector.connect(domain, stream).await.unwrap();

        let mut buf = vec![0u8; size];
        for _ in 0..100 {
            stream.read_exact(&mut buf).await.unwrap();
        }
    });

    client.await.unwrap();
    server.await.unwrap();
}

fn benchmark_tls_write(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let mut group = c.benchmark_group("tls_write");

    for &size in SIZES {
        group.throughput(Throughput::Bytes((size * 100) as u64));

        group.bench_with_input(BenchmarkId::new("boring", size), &size, |b, &size| {
            b.to_async(&rt)
                .iter(|| async { boring_write_benchmark(std::hint::black_box(size)).await });
        });

        group.bench_with_input(BenchmarkId::new("rustls", size), &size, |b, &size| {
            b.to_async(&rt)
                .iter(|| async { rustls_write_benchmark(std::hint::black_box(size)).await });
        });
    }

    group.finish();
}

fn benchmark_tls_read(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let mut group = c.benchmark_group("tls_read");

    for &size in SIZES {
        group.throughput(Throughput::Bytes((size * 100) as u64));

        group.bench_with_input(BenchmarkId::new("boring", size), &size, |b, &size| {
            b.to_async(&rt)
                .iter(|| async { boring_read_benchmark(std::hint::black_box(size)).await });
        });

        group.bench_with_input(BenchmarkId::new("rustls", size), &size, |b, &size| {
            b.to_async(&rt)
                .iter(|| async { rustls_read_benchmark(std::hint::black_box(size)).await });
        });
    }

    group.finish();
}

criterion_group!(benches, benchmark_tls_write, benchmark_tls_read);
criterion_main!(benches);
