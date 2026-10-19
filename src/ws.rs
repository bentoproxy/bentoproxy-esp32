//! Minimal RFC 6455 client over an already-established byte stream.
//!
//! The socket is non-blocking, so bytes arrive in arbitrary chunks: a frame
//! header can be split across reads. The previous version called read_exact()
//! per frame, which consumed part of a header and then returned WouldBlock,
//! dropping those bytes and desyncing the connection permanently. Everything
//! here parses out of a persistent buffer instead, so a partial frame simply
//! stays buffered until the rest arrives.

use std::io::{Read, Write};

use anyhow::{anyhow, Result};
use bentoproxy_protocol::Frame;
use log::{debug, info, warn};

const OP_CONTINUATION: u8 = 0x0;
const OP_BINARY: u8 = 0x2;
const OP_CLOSE: u8 = 0x8;
const OP_PING: u8 = 0x9;
const OP_PONG: u8 = 0xA;

/// Payload cap for a single message. The orchestrator never sends more, and
/// without a limit a bad length prefix would try to allocate past free heap.
const MAX_PAYLOAD: usize = 64 * 1024;
/// Outgoing buffer reserved once per connection: one relay frame (8KB, see
/// RELAY_BUFFER) plus the protocol and WebSocket headers.
const TX_CAPACITY: usize = 8 * 1024 + 64;
/// bentoproxy-protocol frame header: type, flags, stream id, payload length.
const PROTOCOL_HEADER: usize = 10;

/// A WebSocket client connection.
pub struct WsConn<S> {
    stream: S,
    /// Bytes received but not yet consumed by a complete frame.
    rx: Vec<u8>,
    /// Payload of a fragmented message assembled so far.
    fragment: Vec<u8>,
    /// Reused outgoing frame buffer: the relay sends thousands of frames a
    /// second under load, and a fresh allocation per frame fragments the heap.
    tx: Vec<u8>,
    /// Heap, not an array: this struct lives on the main task's stack.
    scratch: Vec<u8>,
    /// Descriptor to wait on when a write would block; None falls back to
    /// sleeping, for streams without one.
    wait_fd: Option<i32>,
}

impl<S: Read + Write> WsConn<S> {
    /// Perform the opening handshake, then wrap the stream.
    ///
    /// The key is random per connection and the server's Sec-WebSocket-Accept
    /// is verified, so a stray HTTP endpoint cannot be mistaken for a peer.
    pub fn connect(mut stream: S, host: &str, path: &str) -> Result<Self> {
        let key = random_key();

        let request = format!(
            "GET {path} HTTP/1.1\r\n\
             Host: {host}\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Key: {key}\r\n\
             Sec-WebSocket-Version: 13\r\n\
             \r\n"
        );
        stream.write_all(request.as_bytes())?;
        stream.flush()?;

        // The handshake runs while the socket is still blocking, but a server
        // may still split the response, so read until the header terminator.
        let mut response = Vec::new();
        let mut buf = [0u8; 256];
        loop {
            let n = stream.read(&mut buf)?;
            if n == 0 {
                return Err(anyhow!("connection closed during handshake"));
            }
            response.extend_from_slice(&buf[..n]);
            if response.windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
            if response.len() > 4096 {
                return Err(anyhow!("handshake response too large"));
            }
        }

        let text = String::from_utf8_lossy(&response);
        if !text.contains("101 Switching Protocols") {
            return Err(anyhow!("handshake rejected: {}", text.lines().next().unwrap_or("")));
        }

        let expected = accept_key(&key);
        let accepted = text
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.trim()
                    .eq_ignore_ascii_case("sec-websocket-accept")
                    .then(|| value.trim().to_string())
            })
            .ok_or_else(|| anyhow!("handshake response has no Sec-WebSocket-Accept"))?;

        if accepted != expected {
            return Err(anyhow!("handshake key mismatch: peer is not a WebSocket server"));
        }

        info!("WebSocket handshake complete");
        Ok(Self {
            stream,
            rx: Vec::with_capacity(4096),
            fragment: Vec::new(),
            // Sized up front for the largest relay frame, while the heap is
            // fresh after the handshake. Growing it later can fail once WiFi
            // buffers have fragmented the heap.
            tx: Vec::with_capacity(TX_CAPACITY),
            scratch: vec![0u8; 2048],
            wait_fd: None,
        })
    }

    /// Read whatever is available and return a frame once one is complete.
    ///
    /// `Ok(None)` means "nothing complete yet" — the normal case on a
    /// non-blocking socket — and never loses buffered bytes.
    pub fn poll_frame(&mut self) -> Result<Option<Frame>> {
        self.fill()?;

        loop {
            match self.take_message()? {
                Some((OP_BINARY, payload)) | Some((OP_CONTINUATION, payload)) => {
                    return Frame::from_bytes(payload.into())
                        .map(Some)
                        .map_err(|e| anyhow!("frame parse error: {:?}", e));
                }
                Some((OP_PING, payload)) => {
                    // A pong must echo the ping's payload.
                    debug!("WebSocket PING received, replying with PONG");
                    self.send_control(OP_PONG, &payload)?;
                }
                Some((OP_PONG, _)) => debug!("WebSocket PONG received"),
                Some((OP_CLOSE, _)) => return Err(anyhow!("peer sent WebSocket CLOSE")),
                Some((opcode, _)) => warn!("ignoring unknown WebSocket opcode {opcode:#x}"),
                None => return Ok(None),
            }
        }
    }

    /// The underlying stream, for switching blocking mode after the
    /// handshake has completed.
    pub fn get_mut(&mut self) -> &mut S {
        &mut self.stream
    }

    pub fn get_ref(&self) -> &S {
        &self.stream
    }

    /// Let blocked writes wait on this descriptor instead of sleeping.
    pub fn set_wait_fd(&mut self, fd: Option<i32>) {
        self.wait_fd = fd;
    }

    /// Send a protocol frame as one masked binary message.
    pub fn send_frame(&mut self, frame: &Frame) -> Result<()> {
        self.send_message(OP_BINARY, &frame.to_bytes())
    }

    /// Send relayed bytes as a DATA frame without copying them anywhere first.
    ///
    /// The general path builds a Frame (one copy), serialises it (a second)
    /// and masks it into the send buffer (a third), each a fresh heap
    /// allocation the size of the payload. On the hot path that churned the
    /// heap until a 16KB allocation failed with 160KB nominally free. Here the
    /// protocol header and payload are masked straight into the reused buffer.
    pub fn send_data(&mut self, stream_id: u32, payload: &[u8]) -> Result<()> {
        let mut header = [0u8; PROTOCOL_HEADER];
        header[0] = bentoproxy_protocol::FrameType::Data as u8;
        header[1] = 0; // no flags
        header[2..6].copy_from_slice(&stream_id.to_le_bytes());
        header[6..10].copy_from_slice(&(payload.len() as u32).to_le_bytes());

        self.send_parts(OP_BINARY, &header, payload)
    }

    fn send_control(&mut self, opcode: u8, payload: &[u8]) -> Result<()> {
        self.send_message(opcode, payload)
    }

    fn send_message(&mut self, opcode: u8, payload: &[u8]) -> Result<()> {
        self.send_parts(opcode, &[], payload)
    }

    /// Write one masked message whose payload is `head` followed by `body`,
    /// so callers can prepend a header without concatenating first.
    fn send_parts(&mut self, opcode: u8, head: &[u8], body: &[u8]) -> Result<()> {
        // Split the borrow so the reusable buffer and the stream can be held
        // at once.
        let Self { stream, tx, wait_fd, .. } = self;

        let build_started = std::time::Instant::now();
        tx.clear();
        tx.push(0x80 | opcode); // FIN + opcode

        // RFC 6455: every client frame is masked.
        let len = head.len() + body.len();
        if len < 126 {
            tx.push(0x80 | len as u8);
        } else if len < 65536 {
            tx.push(0x80 | 126);
            tx.extend_from_slice(&(len as u16).to_be_bytes());
        } else {
            tx.push(0x80 | 127);
            tx.extend_from_slice(&(len as u64).to_be_bytes());
        }

        let mask = random_bytes();
        tx.extend_from_slice(&mask);

        // Copy, then mask in place a word at a time. Byte-at-a-time masking
        // ran over every relayed byte on the critical write path.
        let start = tx.len();
        tx.extend_from_slice(head);
        tx.extend_from_slice(body);
        apply_mask(&mut tx[start..], mask);
        crate::profile::build_done(build_started);

        // One write for header and payload together: two writes per frame put
        // a small packet on the wire ahead of each payload.
        let started = std::time::Instant::now();
        write_all_nonblocking(stream, tx, *wait_fd)?;
        stream.flush()?;
        crate::profile::write_done(started);
        Ok(())
    }

    /// Pull available bytes into the buffer; WouldBlock just means "no more".
    fn fill(&mut self) -> Result<()> {
        loop {
            match self.stream.read(&mut self.scratch) {
                Ok(0) => return Err(anyhow!("connection closed by peer")),
                Ok(n) => {
                    self.rx.extend_from_slice(&self.scratch[..n]);
                    if n < self.scratch.len() {
                        return Ok(());
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => return Ok(()),
                Err(e) => return Err(e.into()),
            }
        }
    }

    /// Consume one complete message from the buffer, if there is one.
    ///
    /// Fragmented messages are assembled here, so callers only ever see whole
    /// messages. Returns the opcode of the message's first frame.
    fn take_message(&mut self) -> Result<Option<(u8, Vec<u8>)>> {
        let Some((fin, opcode, payload, consumed)) = parse_frame(&self.rx)? else {
            return Ok(None);
        };
        self.rx.drain(..consumed);

        // Control frames are never fragmented and may arrive mid-message.
        if opcode & 0x8 != 0 {
            return Ok(Some((opcode, payload)));
        }

        if fin && self.fragment.is_empty() {
            return Ok(Some((opcode, payload)));
        }

        self.fragment.extend_from_slice(&payload);
        if self.fragment.len() > MAX_PAYLOAD {
            return Err(anyhow!("fragmented message exceeds {MAX_PAYLOAD} bytes"));
        }
        if fin {
            return Ok(Some((OP_BINARY, std::mem::take(&mut self.fragment))));
        }
        Ok(None)
    }
}

/// Parse one frame from `buf`, returning (fin, opcode, payload, bytes consumed).
fn parse_frame(buf: &[u8]) -> Result<Option<(bool, u8, Vec<u8>, usize)>> {
    if buf.len() < 2 {
        return Ok(None);
    }

    let fin = buf[0] & 0x80 != 0;
    let opcode = buf[0] & 0x0F;
    let masked = buf[1] & 0x80 != 0;
    let short_len = (buf[1] & 0x7F) as usize;

    let mut offset = 2;
    let payload_len = match short_len {
        126 => {
            if buf.len() < offset + 2 {
                return Ok(None);
            }
            let len = u16::from_be_bytes([buf[offset], buf[offset + 1]]) as usize;
            offset += 2;
            len
        }
        127 => {
            if buf.len() < offset + 8 {
                return Ok(None);
            }
            let mut len_bytes = [0u8; 8];
            len_bytes.copy_from_slice(&buf[offset..offset + 8]);
            offset += 8;
            u64::from_be_bytes(len_bytes) as usize
        }
        n => n,
    };

    if payload_len > MAX_PAYLOAD {
        return Err(anyhow!("payload of {payload_len} bytes exceeds limit"));
    }

    // A server must not mask, but handle it rather than corrupting the payload.
    let mask = if masked {
        if buf.len() < offset + 4 {
            return Ok(None);
        }
        let m = [buf[offset], buf[offset + 1], buf[offset + 2], buf[offset + 3]];
        offset += 4;
        Some(m)
    } else {
        None
    };

    if buf.len() < offset + payload_len {
        return Ok(None); // Wait for the rest; buffered bytes stay put.
    }

    let mut payload = buf[offset..offset + payload_len].to_vec();
    if let Some(m) = mask {
        for (i, byte) in payload.iter_mut().enumerate() {
            *byte ^= m[i % 4];
        }
    }

    Ok(Some((fin, opcode, payload, offset + payload_len)))
}

/// How long to keep retrying a blocked write before calling the link dead.
///
/// A half-open connection — the far side gone, a NAT entry dropped by a guest
/// network — leaves writes returning WouldBlock forever with no error. Without
/// a deadline the relay spins here and the node never reconnects: it vanishes
/// from the orchestrator until someone power-cycles it.
const WRITE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(20);

/// Write every byte, yielding briefly when the socket is full.
fn write_all_nonblocking<W: Write>(
    stream: &mut W,
    mut buf: &[u8],
    wait_fd: Option<i32>,
) -> Result<()> {
    let deadline = std::time::Instant::now() + WRITE_TIMEOUT;

    while !buf.is_empty() {
        let call_started = std::time::Instant::now();
        let result = stream.write(buf);
        crate::profile::tls_call_done(call_started);
        match result {
            Ok(0) => return Err(anyhow!("write returned 0 bytes")),
            Ok(n) => buf = &buf[n..],
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                crate::profile::write_stalled();
                if std::time::Instant::now() > deadline {
                    return Err(anyhow!(
                        "socket accepted nothing for {}s; treating the link as dead",
                        WRITE_TIMEOUT.as_secs()
                    ));
                }
                // Wait until the socket can take more, rather than sleeping a
                // whole scheduler tick. Writable only: waiting on readable too
                // returned at once whenever the orchestrator had sent anything,
                // which spun this loop ~35,000 times in 20s. A WANT_READ during
                // a write is rare and the timeout bounds it.
                let wait_started = std::time::Instant::now();
                match wait_fd {
                    Some(fd) => {
                        let mut write = crate::wait::FdSet::new();
                        write.add(fd);
                        crate::wait::wait(
                            crate::wait::FdSet::new(),
                            write,
                            std::time::Duration::from_millis(50),
                        );
                    }
                    None => std::thread::sleep(std::time::Duration::from_millis(1)),
                }
                crate::profile::wait_done(wait_started);
            }
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

/// XOR a WebSocket mask over `buf`, which starts at mask phase 0.
///
/// Works a 32-bit word at a time over the aligned middle of the buffer, with
/// the mask rotated to keep its byte phase, and byte-wise over the unaligned
/// ends. Verified identical to byte-wise masking at every alignment and frame
/// size the relay produces.
fn apply_mask(buf: &mut [u8], mask: [u8; 4]) {
    // SAFETY: every bit pattern is a valid u32; align_to_mut only re-slices.
    let (prefix, words, suffix) = unsafe { buf.align_to_mut::<u32>() };

    let p = prefix.len();
    for (i, b) in prefix.iter_mut().enumerate() {
        *b ^= mask[i % 4];
    }

    let rotated = [mask[p % 4], mask[(p + 1) % 4], mask[(p + 2) % 4], mask[(p + 3) % 4]];
    let word_mask = u32::from_ne_bytes(rotated);
    for w in words.iter_mut() {
        *w ^= word_mask;
    }

    let offset = p + words.len() * 4;
    for (i, b) in suffix.iter_mut().enumerate() {
        *b ^= mask[(offset + i) % 4];
    }
}

fn random_bytes() -> [u8; 4] {
    let r = unsafe { esp_idf_sys::esp_random() };
    r.to_le_bytes()
}

/// A fresh 16-byte nonce, base64-encoded, as required per connection.
fn random_key() -> String {
    let mut nonce = [0u8; 16];
    for chunk in nonce.chunks_mut(4) {
        chunk.copy_from_slice(&random_bytes());
    }
    base64_encode(&nonce)
}

/// The server's expected Sec-WebSocket-Accept: base64(sha1(key + GUID)).
fn accept_key(key: &str) -> String {
    const GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    let mut input = Vec::with_capacity(key.len() + GUID.len());
    input.extend_from_slice(key.as_bytes());
    input.extend_from_slice(GUID.as_bytes());
    base64_encode(&sha1(&input))
}

fn base64_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity((data.len() + 2) / 3 * 4);

    for chunk in data.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;

        out.push(ALPHABET[(n >> 18) as usize & 63] as char);
        out.push(ALPHABET[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 { ALPHABET[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if chunk.len() > 2 { ALPHABET[n as usize & 63] as char } else { '=' });
    }

    out
}

/// SHA-1, needed only to validate the handshake.
fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h: [u32; 5] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];

    let mut message = data.to_vec();
    let bit_len = (data.len() as u64) * 8;
    message.push(0x80);
    while message.len() % 64 != 56 {
        message.push(0);
    }
    message.extend_from_slice(&bit_len.to_be_bytes());

    for block in message.chunks(64) {
        let mut w = [0u32; 80];
        for (i, word) in block.chunks(4).enumerate() {
            w[i] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }

        let (mut a, mut b, mut c, mut d, mut e) = (h[0], h[1], h[2], h[3], h[4]);
        for (i, &word) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | (!b & d), 0x5A827999),
                20..=39 => (b ^ c ^ d, 0x6ED9EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDC),
                _ => (b ^ c ^ d, 0xCA62C1D6),
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(word);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
    }

    let mut out = [0u8; 20];
    for (i, word) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha1_matches_known_vectors() {
        assert_eq!(
            sha1(b"abc"),
            [
                0xA9, 0x99, 0x3E, 0x36, 0x47, 0x06, 0x81, 0x6A, 0xBA, 0x3E, 0x25, 0x71, 0x78, 0x50,
                0xC2, 0x6C, 0x9C, 0xD0, 0xD8, 0x9D
            ]
        );
    }

    #[test]
    fn accept_key_matches_rfc6455_example() {
        // RFC 6455 section 1.3.
        assert_eq!(accept_key("dGhlIHNhbXBsZSBub25jZQ=="), "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
    }

    #[test]
    fn base64_handles_padding() {
        assert_eq!(base64_encode(b"a"), "YQ==");
        assert_eq!(base64_encode(b"ab"), "YWI=");
        assert_eq!(base64_encode(b"abc"), "YWJj");
    }

    #[test]
    fn partial_frames_are_not_consumed() {
        // Header says 4 bytes of payload but only 2 have arrived.
        let buf = [0x82, 0x04, 0xDE, 0xAD];
        assert!(parse_frame(&buf).unwrap().is_none());
    }

    #[test]
    fn parses_a_complete_unmasked_frame() {
        let buf = [0x82, 0x04, 0xDE, 0xAD, 0xBE, 0xEF, 0x99];
        let (fin, opcode, payload, consumed) = parse_frame(&buf).unwrap().unwrap();
        assert!(fin);
        assert_eq!(opcode, OP_BINARY);
        assert_eq!(payload, vec![0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(consumed, 6, "trailing byte belongs to the next frame");
    }
}
