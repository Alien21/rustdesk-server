use hbb_common::{
    anyhow::{anyhow, Context},
    bail,
    bytes::BytesMut,
    futures::SinkExt,
    tcp::{DynTcpStream, FramedStream},
    sodiumoxide::{
        base64,
        crypto::{box_, hash::sha256, secretbox, sign},
        randombytes,
    },
    tokio::{
        self,
        io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf},
    },
    ResultType,
};
use serde::{de::DeserializeOwned, Serialize};
use std::{
    io,
    net::SocketAddr,
    pin::Pin,
    task::{Context as TaskContext, Poll},
};

const RECORD_MAX: usize = 64 * 1024;
const HANDSHAKE_MAX: usize = 4096;
const DOMAIN: &[u8] = b"rustdesk-access-kx-v1\0";

const UPGRADE: &[u8] = b"\0RustDesk-Private-Access-v1";
pub const UPGRADE_FRAME: &[u8] = b"\x6c\0RustDesk-Private-Access-v1";

pub fn is_upgrade(bytes: &[u8]) -> bool {
    bytes == UPGRADE
}

struct BufferedIo<S> {
    stream: S,
    prefix: BytesMut,
}

impl<S: AsyncRead + Unpin> AsyncRead for BufferedIo<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.prefix.is_empty() {
            let count = out.remaining().min(this.prefix.len());
            out.put_slice(&this.prefix.split_to(count));
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.stream).poll_read(cx, out)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for BufferedIo<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().stream).poll_write(cx, bytes)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_shutdown(cx)
    }
}

async fn into_buffered(mut stream: FramedStream) -> ResultType<BufferedIo<DynTcpStream>> {
    if stream.is_secured() {
        bail!("private access upgrade must precede legacy encryption");
    }
    stream.0.flush().await?;
    let parts = stream.0.into_parts();
    Ok(BufferedIo {
        stream: parts.io,
        prefix: parts.read_buf,
    })
}

// The dispatcher already consumed the upgrade frame; subsequent bytes are raw KX/records.
pub async fn accept_framed(
    stream: FramedStream,
    server_sk: &sign::SecretKey,
) -> ResultType<AccessStream> {
    accept(into_buffered(stream).await?, server_sk).await
}

pub async fn connect_framed(
    mut stream: FramedStream,
    server_key: &[u8],
) -> ResultType<AccessStream> {
    if stream.is_secured() {
        bail!("private access upgrade must precede legacy encryption");
    }
    stream.send_raw(UPGRADE.to_vec()).await?;
    connect_raw(into_buffered(stream).await?, server_key).await
}

#[derive(serde_derive::Serialize, serde_derive::Deserialize)]
struct Hello {
    version: u32,
    key: String,
    nonce: String,
    #[serde(default)]
    signature: String,
}

pub fn encode(bytes: &[u8]) -> String {
    base64::encode(bytes, base64::Variant::Original)
}

pub fn decode(value: &str) -> ResultType<Vec<u8>> {
    base64::decode(value, base64::Variant::Original).map_err(|_| anyhow!("invalid base64"))
}

async fn write_json<W: AsyncWrite + Unpin, T: Serialize>(
    stream: &mut W,
    value: &T,
    max: usize,
) -> ResultType<()> {
    let bytes = serde_json::to_vec(value)?;
    if bytes.is_empty() || bytes.len() > max {
        bail!("access message too large");
    }
    stream
        .write_all(&(bytes.len() as u32).to_be_bytes())
        .await?;
    stream.write_all(&bytes).await?;
    stream.flush().await?;
    Ok(())
}

async fn read_json<R: AsyncRead + Unpin, T: DeserializeOwned>(
    stream: &mut R,
    max: usize,
) -> ResultType<T> {
    let len = stream.read_u32().await? as usize;
    if len == 0 || len > max {
        bail!("invalid access message length");
    }
    let mut bytes = vec![0; len];
    stream.read_exact(&mut bytes).await?;
    Ok(serde_json::from_slice(&bytes)?)
}

pub async fn send_json<W: AsyncWrite + Unpin, T: Serialize>(
    stream: &mut W,
    value: &T,
) -> ResultType<()> {
    write_json(stream, value, RECORD_MAX).await
}

pub async fn recv_json<R: AsyncRead + Unpin, T: DeserializeOwned>(stream: &mut R) -> ResultType<T> {
    read_json(stream, RECORD_MAX).await
}

pub struct AccessStream {
    stream: DuplexStream,
    binding: [u8; 32],
}

impl AccessStream {
    pub fn binding(&self) -> [u8; 32] {
        self.binding
    }

    fn new<S>(stream: S, shared: box_::PrecomputedKey, transcript: Vec<u8>, client: bool) -> Self
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static,
    {
        let binding = sha256::hash(&transcript).0;
        let derive = |label: &[u8]| {
            let mut bytes = Vec::from(DOMAIN);
            bytes.extend_from_slice(label);
            bytes.extend_from_slice(&shared.0);
            bytes.extend_from_slice(&binding);
            secretbox::Key(sha256::hash(&bytes).0)
        };
        let c2s = derive(b"client-to-server");
        let s2c = derive(b"server-to-client");
        let (tx, rx) = if client { (c2s, s2c) } else { (s2c, c2s) };
        let (application, tunnel) = tokio::io::duplex(RECORD_MAX * 2);
        tokio::spawn(async move {
            let (network_read, network_write) = tokio::io::split(stream);
            let (plain_read, plain_write) = tokio::io::split(tunnel);
            tokio::select! {
                _ = encrypt_records(plain_read, network_write, tx) => {},
                _ = decrypt_records(network_read, plain_write, rx) => {},
            }
        });
        Self {
            stream: application,
            binding,
        }
    }
}

fn nonce(counter: u64) -> secretbox::Nonce {
    let mut bytes = [0; secretbox::NONCEBYTES];
    bytes[16..].copy_from_slice(&counter.to_le_bytes());
    secretbox::Nonce(bytes)
}

async fn encrypt_records<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    mut input: R,
    mut output: W,
    key: secretbox::Key,
) -> ResultType<()> {
    let mut buffer = vec![0; RECORD_MAX];
    let mut counter = 0_u64;
    loop {
        let count = input.read(&mut buffer).await?;
        if count == 0 {
            return Ok(());
        }
        let encrypted = secretbox::seal(&buffer[..count], &nonce(counter), &key);
        counter = counter
            .checked_add(1)
            .context("encrypted record counter exhausted")?;
        output
            .write_all(&(encrypted.len() as u32).to_be_bytes())
            .await?;
        output.write_all(&encrypted).await?;
        output.flush().await?;
    }
}

async fn decrypt_records<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    mut input: R,
    mut output: W,
    key: secretbox::Key,
) -> ResultType<()> {
    let mut counter = 0_u64;
    loop {
        let len = input.read_u32().await? as usize;
        if len <= secretbox::MACBYTES || len > RECORD_MAX + secretbox::MACBYTES {
            bail!("invalid encrypted record length");
        }
        let mut encrypted = vec![0; len];
        input.read_exact(&mut encrypted).await?;
        let plain = secretbox::open(&encrypted, &nonce(counter), &key)
            .map_err(|_| anyhow!("encrypted record authentication failed"))?;
        counter = counter
            .checked_add(1)
            .context("encrypted record counter exhausted")?;
        output.write_all(&plain).await?;
        output.flush().await?;
    }
}

pub async fn accept<S>(mut stream: S, server_sk: &sign::SecretKey) -> ResultType<AccessStream>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static,
{
    let (pk, sk) = box_::gen_keypair();
    let challenge = randombytes::randombytes(32);
    let mut transcript = Vec::from(DOMAIN);
    transcript.extend_from_slice(&pk.0);
    transcript.extend_from_slice(&challenge);
    write_json(
        &mut stream,
        &Hello {
            version: 1,
            key: encode(&pk.0),
            nonce: encode(&challenge),
            signature: encode(sign::sign_detached(&transcript, server_sk).as_ref()),
        },
        HANDSHAKE_MAX,
    )
    .await?;
    let hello: Hello = read_json(&mut stream, HANDSHAKE_MAX).await?;
    if hello.version != 1 {
        bail!("unsupported access protocol");
    }
    let client_pk =
        box_::PublicKey::from_slice(&decode(&hello.key)?).context("invalid client exchange key")?;
    let client_nonce = decode(&hello.nonce)?;
    if client_nonce.len() != 32 {
        bail!("invalid client exchange nonce");
    }
    transcript.extend_from_slice(&client_pk.0);
    transcript.extend_from_slice(&client_nonce);
    Ok(AccessStream::new(
        stream,
        box_::precompute(&client_pk, &sk),
        transcript,
        false,
    ))
}

pub async fn connect<S>(stream: S, server_key: &[u8]) -> ResultType<AccessStream>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static,
{
    let address = SocketAddr::from(([0, 0, 0, 0], 0));
    connect_framed(FramedStream::from(stream, address), server_key).await
}

async fn connect_raw<S>(mut stream: S, server_key: &[u8]) -> ResultType<AccessStream>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static,
{
    let hello: Hello = read_json(&mut stream, HANDSHAKE_MAX).await?;
    if hello.version != 1 {
        bail!("unsupported access protocol");
    }
    let server_key =
        sign::PublicKey::from_slice(server_key).context("invalid server signing key")?;
    let server_pk =
        box_::PublicKey::from_slice(&decode(&hello.key)?).context("invalid server exchange key")?;
    let challenge = decode(&hello.nonce)?;
    if challenge.len() != 32 {
        bail!("invalid server exchange nonce");
    }
    let mut transcript = Vec::from(DOMAIN);
    transcript.extend_from_slice(&server_pk.0);
    transcript.extend_from_slice(&challenge);
    let signature = sign::Signature::from_bytes(&decode(&hello.signature)?)
        .map_err(|_| anyhow!("invalid server signature"))?;
    if !sign::verify_detached(&signature, &transcript, &server_key) {
        bail!("access server signature mismatch");
    }
    let (pk, sk) = box_::gen_keypair();
    let client_nonce = randombytes::randombytes(32);
    write_json(
        &mut stream,
        &Hello {
            version: 1,
            key: encode(&pk.0),
            nonce: encode(&client_nonce),
            signature: String::new(),
        },
        HANDSHAKE_MAX,
    )
    .await?;
    transcript.extend_from_slice(&pk.0);
    transcript.extend_from_slice(&client_nonce);
    Ok(AccessStream::new(
        stream,
        box_::precompute(&server_pk, &sk),
        transcript,
        true,
    ))
}

impl AsyncRead for AccessStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_read(cx, out)
    }
}

impl AsyncWrite for AccessStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().stream).poll_write(cx, bytes)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hbb_common::{
        bytes::Bytes,
        bytes_codec::BytesCodec,
        protobuf::Message,
        rendezvous_proto::RendezvousMessage,
        tokio::net::TcpStream,
        tokio_util::codec::Encoder,
    };

    #[tokio::test]
    async fn large_bidirectional_stream_delivers_final_reply_before_drop() {
        hbb_common::sodiumoxide::init().unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            let (server_key, server_secret) = sign::gen_keypair();
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let size = RECORD_MAX * 3 + 137;
            let server = tokio::spawn(async move {
                let (raw, _) = listener.accept().await.unwrap();
                let mut framed = FramedStream::from(raw, address);
                assert!(is_upgrade(&framed.next().await.unwrap().unwrap()));
                let mut stream = accept_framed(framed, &server_secret).await.unwrap();
                let request: serde_json::Value = recv_json(&mut stream).await.unwrap();
                assert_eq!(request["op"], "roundtrip");
                let (mut reader, mut writer) = tokio::io::split(stream);
                let mut received = vec![0; size];
                let sent = vec![0xa5; size];
                tokio::try_join!(reader.read_exact(&mut received), writer.write_all(&sent))
                    .unwrap();
                assert_eq!(received, vec![0x5a; size]);
                send_json(&mut writer, &serde_json::json!({"reply":"complete"}))
                    .await
                    .unwrap();
            });
            let raw = TcpStream::connect(address).await.unwrap();
            let mut stream = connect(raw, &server_key.0).await.unwrap();
            send_json(&mut stream, &serde_json::json!({"op":"roundtrip"}))
                .await
                .unwrap();
            let (mut reader, mut writer) = tokio::io::split(stream);
            let mut received = vec![0; size];
            let sent = vec![0x5a; size];
            tokio::try_join!(reader.read_exact(&mut received), writer.write_all(&sent)).unwrap();
            assert_eq!(received, vec![0xa5; size]);
            let reply: serde_json::Value = recv_json(&mut reader).await.unwrap();
            assert_eq!(reply["reply"], "complete");
            server.await.unwrap();
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn handshake_rejects_a_different_server_signing_key() {
        hbb_common::sodiumoxide::init().unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            let (_, server_secret) = sign::gen_keypair();
            let (wrong_key, _) = sign::gen_keypair();
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let server = tokio::spawn(async move {
                let (raw, _) = listener.accept().await.unwrap();
                let mut framed = FramedStream::from(raw, address);
                assert!(is_upgrade(&framed.next().await.unwrap().unwrap()));
                accept_framed(framed, &server_secret).await.is_err()
            });
            let raw = TcpStream::connect(address).await.unwrap();
            assert!(connect(raw, &wrong_key.0).await.is_err());
            assert!(server.await.unwrap());
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn encrypted_records_reject_tampering_replay_and_oversized_lengths() {
        hbb_common::sodiumoxide::init().unwrap();
        let key = secretbox::gen_key();
        let encrypted = secretbox::seal(b"authenticated record", &nonce(0), &key);
        let mut record = (encrypted.len() as u32).to_be_bytes().to_vec();
        record.extend_from_slice(&encrypted);

        let mut tampered = record.clone();
        *tampered.last_mut().unwrap() ^= 1;
        let mut received = Vec::new();
        assert!(
            decrypt_records(tampered.as_slice(), &mut received, key.clone())
                .await
                .is_err()
        );
        assert!(received.is_empty());

        let replayed = [record.as_slice(), record.as_slice()].concat();
        assert!(
            decrypt_records(replayed.as_slice(), &mut received, key.clone())
                .await
                .is_err()
        );
        assert_eq!(received, b"authenticated record");

        let oversized = ((RECORD_MAX + secretbox::MACBYTES + 1) as u32).to_be_bytes();
        received.clear();
        assert!(decrypt_records(oversized.as_slice(), &mut received, key)
            .await
            .is_err());
        assert!(received.is_empty());
    }
    #[test]
    fn upgrade_marker_is_exact_and_not_a_legacy_protobuf() {
        let mut encoded = BytesMut::new();
        BytesCodec::new().encode(Bytes::copy_from_slice(UPGRADE), &mut encoded).unwrap();
        assert_eq!(&encoded[..], UPGRADE_FRAME);
        assert!(is_upgrade(UPGRADE));
        assert!(!is_upgrade(&UPGRADE[1..]));
        assert!(!is_upgrade(&[UPGRADE, b"extra"].concat()));
        assert!(RendezvousMessage::parse_from_bytes(UPGRADE).is_err());
        let mut legacy = RendezvousMessage::new();
        legacy.set_register_peer(Default::default());
        let bytes = legacy.write_to_bytes().unwrap();
        assert!(!is_upgrade(&bytes));
        assert!(RendezvousMessage::parse_from_bytes(&bytes).is_ok());
    }

    #[tokio::test]
    async fn fragmented_upgrade_preserves_read_ahead_and_pending_framed_writes() {
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            let (mut remote, local) = tokio::io::duplex(4096);
            let address = SocketAddr::from(([127, 0, 0, 1], 1));
            let mut framed = FramedStream::from(local, address);
            let mut wire = BytesMut::new();
            BytesCodec::new()
                .encode(Bytes::copy_from_slice(UPGRADE), &mut wire)
                .unwrap();
            wire.extend_from_slice(b"raw handshake read ahead");
            let writer = tokio::spawn(async move {
                remote.write_all(&wire[..2]).await.unwrap();
                tokio::task::yield_now().await;
                remote.write_all(&wire[2..]).await.unwrap();
                remote
            });
            assert!(is_upgrade(&framed.next().await.unwrap().unwrap()));
            let remote = writer.await.unwrap();
            framed.0.feed(Bytes::from_static(b"queued frame")).await.unwrap();
            let mut raw = into_buffered(framed).await.unwrap();
            let mut tail = [0; 24];
            raw.read_exact(&mut tail).await.unwrap();
            assert_eq!(&tail, b"raw handshake read ahead");
            let mut remote = FramedStream::from(remote, address);
            assert_eq!(&remote.next().await.unwrap().unwrap()[..], b"queued frame");
            raw.write_all(b"raw write").await.unwrap();
            let mut remote = into_buffered(remote).await.unwrap();
            let mut written = [0; 9];
            remote.read_exact(&mut written).await.unwrap();
            assert_eq!(&written, b"raw write");
        })
        .await
        .unwrap();
    }

}
