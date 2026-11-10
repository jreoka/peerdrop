use crate::crypto::SessionKeys;
use serde::{Deserialize, Serialize};
use std::io;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const PROTOCOL_VERSION: u32 = 1;
pub const MAX_FRAME_SIZE: usize = 128 * 1024; // 128 KB max encrypted frame
pub const CHUNK_SIZE: usize = 64 * 1024; // 64 KB plaintext data chunk

#[derive(Serialize, Deserialize, Debug)]
pub struct AuthChallengeMsg {
    pub version: u32,
    pub challenge: [u8; 32],
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AuthResponseMsg {
    pub response: [u8; 32],
    pub peer_challenge: [u8; 32],
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AuthFinalMsg {
    pub response: [u8; 32],
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TransferMeta {
    pub name: String,
    pub is_directory: bool,
    pub total_bytes: u64,
    pub file_count: usize,
    pub sha256: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ReceiverDecision {
    pub accepted: bool,
    pub reason: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct TransferFinish {
    pub sha256: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct TransferAck {
    pub verified: bool,
    pub message: String,
}

// Framing helpers for encrypted stream:
// Each frame on the wire is:
// [4 bytes big-endian length of ciphertext] + [ciphertext bytes]

pub async fn write_encrypted_frame<W>(
    writer: &mut W,
    keys: &SessionKeys,
    chunk_index: u64,
    direction: u8,
    plaintext: &[u8],
) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let ciphertext = keys
        .encrypt_chunk(chunk_index, direction, plaintext)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    let len = ciphertext.len() as u32;
    writer.write_all(&len.to_be_bytes()).await?;
    writer.write_all(&ciphertext).await?;
    writer.flush().await?;
    Ok(())
}

pub async fn read_encrypted_frame<R>(
    reader: &mut R,
    keys: &SessionKeys,
    chunk_index: u64,
    direction: u8,
) -> io::Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;

    // Minimum ciphertext size is 16 bytes (Poly1305 authentication tag)
    if !(16..=MAX_FRAME_SIZE).contains(&len) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Frame size {} is outside valid bounds [16, {}]", len, MAX_FRAME_SIZE),
        ));
    }

    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf).await?;

    keys.decrypt_chunk(chunk_index, direction, &buf)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

pub async fn send_json_msg<W, T>(
    writer: &mut W,
    keys: &SessionKeys,
    chunk_index: u64,
    direction: u8,
    msg: &T,
) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
    T: Serialize,
{
    let json_bytes = serde_json::to_vec(msg)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    write_encrypted_frame(writer, keys, chunk_index, direction, &json_bytes).await
}

pub async fn recv_json_msg<R, T>(
    reader: &mut R,
    keys: &SessionKeys,
    chunk_index: u64,
    direction: u8,
) -> io::Result<T>
where
    R: AsyncRead + Unpin,
    T: for<'de> Deserialize<'de>,
{
    let plaintext = read_encrypted_frame(reader, keys, chunk_index, direction).await?;
    serde_json::from_slice(&plaintext)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    #[tokio::test]
    async fn test_encrypted_frame_roundtrip() {
        let (mut client, mut server) = duplex(1024);
        let client_keys = SessionKeys::from_code("secret").unwrap();
        let server_keys = SessionKeys::from_code("secret").unwrap();

        let payload = b"Hello over duplex!";
        let write_fut = write_encrypted_frame(&mut client, &client_keys, 5, 0, payload);
        let read_fut = read_encrypted_frame(&mut server, &server_keys, 5, 0);

        let (w_res, r_res) = tokio::join!(write_fut, read_fut);
        assert!(w_res.is_ok());
        assert_eq!(r_res.unwrap(), payload);
    }

    #[tokio::test]
    async fn test_json_msg_roundtrip() {
        let (mut client, mut server) = duplex(1024);
        let client_keys = SessionKeys::from_code("secret").unwrap();
        let server_keys = SessionKeys::from_code("secret").unwrap();

        let meta = TransferMeta {
            name: "test.txt".into(),
            is_directory: false,
            total_bytes: 1234,
            file_count: 1,
            sha256: "deadbeef".into(),
        };

        let write_fut = send_json_msg(&mut client, &client_keys, 1, 0, &meta);
        let read_fut = recv_json_msg::<_, TransferMeta>(&mut server, &server_keys, 1, 0);

        let (w_res, r_res) = tokio::join!(write_fut, read_fut);
        assert!(w_res.is_ok());
        let received = r_res.unwrap();
        assert_eq!(received.name, meta.name);
        assert_eq!(received.total_bytes, meta.total_bytes);
    }

    #[tokio::test]
    async fn test_frame_size_overflow_rejected() {
        let (mut client, mut server) = duplex(1024);
        let server_keys = SessionKeys::from_code("secret").unwrap();

        // Write length larger than MAX_FRAME_SIZE
        let huge_len = (MAX_FRAME_SIZE + 1) as u32;
        client.write_all(&huge_len.to_be_bytes()).await.unwrap();

        let res = read_encrypted_frame(&mut server, &server_keys, 0, 0).await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn test_frame_size_underflow_rejected() {
        let (mut client, mut server) = duplex(1024);
        let server_keys = SessionKeys::from_code("secret").unwrap();

        // Write length smaller than 16 bytes
        let tiny_len = 10u32;
        client.write_all(&tiny_len.to_be_bytes()).await.unwrap();

        let res = read_encrypted_frame(&mut server, &server_keys, 0, 0).await;
        assert!(res.is_err());
    }
}
