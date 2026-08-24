//! A hermetic AirPlay receiver, speaking real HAP over a real TCP socket.
//!
//! Port of `tests/fake_device/airplay.py::FakeAirPlayService` and the `AirPlayServerAuth` routes it
//! inherits (`pyatv/protocols/airplay/server_auth.py:150-264`). The crypto is
//! [`pyatv_pairing::server::ReferenceAccessory`], which is pyatv's `server_auth.py` accessory with
//! its fixed key material; this file only adds the HTTP routing that sits on top.
//!
//! Routing rules, all of them upstream's:
//!
//! | Route | Rule |
//! |---|---|
//! | `/pair-pin-start` | always `200`, empty body, echoes `CSeq` (`server_auth.py:153-162`) |
//! | `/pair-setup` | `X-Apple-HKP: 3` or `4` runs pair-setup, anything else is `501` (`server_auth.py:164-178`) |
//! | `/pair-verify` | `X-Apple-HKP: 3` runs pair-verify, anything else is `501` (`server_auth.py:232-242`) |
//! | anything else | `404` (`pyatv/support/http.py:590`) |
//!
//! The `Content-Type` on a pair-setup reply is `application/x-apple-binary-plist` even though the
//! body is TLV8. That is what pyatv's accessory sends (`server_auth.py:201,227`) and a controller
//! that trusts it rather than the body would break against a real device, so it is reproduced
//! verbatim rather than corrected.

use std::fmt::Write as _;
use std::net::SocketAddr;
use std::sync::Arc;

use pyatv_pairing::server::ReferenceAccessory;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

/// A running fake receiver. Dropping it stops the accept loop.
#[derive(Debug)]
pub struct FakeAirPlayDevice {
    address: SocketAddr,
    accessory: Arc<Mutex<ReferenceAccessory>>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for FakeAirPlayDevice {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl FakeAirPlayDevice {
    /// Bind to an ephemeral loopback port and start serving.
    ///
    /// `pin` is what the device would be showing on screen.
    pub async fn start(pin: u32) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("binding a loopback port must succeed in tests");
        let address = listener
            .local_addr()
            .expect("a bound listener must have an address");

        let accessory = Arc::new(Mutex::new(ReferenceAccessory::with_pin(pin)));
        let served = Arc::clone(&accessory);

        let task = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let accessory = Arc::clone(&served);
                tokio::spawn(async move {
                    serve(stream, accessory).await;
                });
            }
        });

        Self {
            address,
            accessory,
            task,
        }
    }

    /// Where a controller should connect.
    pub fn address(&self) -> SocketAddr {
        self.address
    }

    /// The accessory's state, for asserting on what it accepted.
    pub fn accessory(&self) -> Arc<Mutex<ReferenceAccessory>> {
        Arc::clone(&self.accessory)
    }
}

/// Serve one connection until the peer goes away.
async fn serve(mut stream: TcpStream, accessory: Arc<Mutex<ReferenceAccessory>>) {
    let mut buffer = Vec::new();

    loop {
        let mut chunk = [0u8; 4096];
        let Ok(read) = stream.read(&mut chunk).await else {
            return;
        };
        if read == 0 {
            return;
        }
        buffer.extend_from_slice(&chunk[..read]);

        while let Some((request, consumed)) = parse_request(&buffer) {
            buffer.drain(..consumed);

            let response = {
                let mut accessory = accessory.lock().await;
                handle(&request, &mut accessory)
            };
            if stream.write_all(&response).await.is_err() {
                return;
            }
        }
    }
}

/// One parsed request: path, headers and body.
struct FakeRequest {
    path: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl FakeRequest {
    /// Case-insensitive header lookup, matching upstream's `CaseInsensitiveDict`.
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

/// Parse one request off the front of `input`, `Content-Length`-framed like everything else here.
fn parse_request(input: &[u8]) -> Option<(FakeRequest, usize)> {
    let boundary = input.windows(4).position(|window| window == b"\r\n\r\n")?;
    let body_start = boundary + 4;

    let header_block = std::str::from_utf8(&input[..boundary]).ok()?;
    let mut lines = header_block.split("\r\n");
    let start_line = lines.next()?;
    let path = start_line.split(' ').nth(1)?.to_owned();

    let headers: Vec<(String, String)> = lines
        .filter(|line| !line.is_empty())
        .filter_map(|line| {
            line.split_once(':')
                .map(|(name, value)| (name.trim().to_owned(), value.trim().to_owned()))
        })
        .collect();

    let length: usize = headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("Content-Length"))
        .map_or(Ok(0), |(_, value)| value.parse())
        .ok()?;

    let body = input.get(body_start..body_start + length)?.to_vec();

    Some((
        FakeRequest {
            path,
            headers,
            body,
        },
        body_start + length,
    ))
}

/// Route one request, exactly as `AirPlayServerAuth` does.
fn handle(request: &FakeRequest, accessory: &mut ReferenceAccessory) -> Vec<u8> {
    let cseq = request.header("CSeq").unwrap_or("1").to_owned();
    let hkp = request.header("X-Apple-HKP");

    match request.path.as_str() {
        "/pair-pin-start" => response(200, "OK", &cseq, None, &[]),
        "/pair-setup" => match hkp {
            // Both HAP and transient run the same handler; the accessory tells them apart from the
            // `Flags` TLV in M1, as `_m1_setup(transient=…)` does upstream.
            Some("3" | "4") => match accessory.handle_pair_setup(&request.body) {
                Ok(tlv) => response(
                    200,
                    "OK",
                    &cseq,
                    Some("application/x-apple-binary-plist"),
                    &tlv,
                ),
                Err(error) => response(500, &error.to_string(), &cseq, None, &[]),
            },
            _ => response(501, "Not implemented", &cseq, None, &[]),
        },
        "/pair-verify" => match hkp {
            Some("3") => match accessory.handle_pair_verify(&request.body) {
                Ok(tlv) => response(200, "OK", &cseq, Some("application/octet-stream"), &tlv),
                Err(error) => response(500, &error.to_string(), &cseq, None, &[]),
            },
            _ => response(501, "Not implemented", &cseq, None, &[]),
        },
        _ => response(404, "File not found", &cseq, None, &[]),
    }
}

/// Serialise a response the way `format_response` does (`pyatv/support/http.py:143-167`):
/// `Server` first, then the caller's headers, then `Content-Length` only for a non-empty body.
fn response(
    code: u16,
    message: &str,
    cseq: &str,
    content_type: Option<&str>,
    body: &[u8],
) -> Vec<u8> {
    let mut head =
        format!("HTTP/1.1 {code} {message}\r\nServer: pyatv-rs-fake/1.0\r\nCSeq: {cseq}\r\n");
    if let Some(content_type) = content_type {
        let _ = write!(head, "Content-Type: {content_type}\r\n");
    }
    if !body.is_empty() {
        let _ = write!(head, "Content-Length: {}\r\n", body.len());
    }
    head.push_str("\r\n");

    let mut out = head.into_bytes();
    out.extend_from_slice(body);
    out
}
