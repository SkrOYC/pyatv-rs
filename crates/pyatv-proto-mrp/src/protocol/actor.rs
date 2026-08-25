//! The background tasks that own the transport.
//!
//! Two of them: a reader that does nothing but drain [`MrpTransport::recv`] into a channel, and an
//! actor that owns the outstanding-request table and performs every write. Splitting them keeps
//! the reader out of any `select!`, so a partially-read frame can never be dropped by cancellation
//! — the failure mode that a single-task design has to reason carefully about and this one cannot
//! have.
//!
//! Together they reproduce `MrpConnection.data_received` plus `MrpProtocol.message_received`
//! (`pyatv/protocols/mrp/connection.py:137-173`, `protocol.py:283-294`).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use pyatv_core::interface::DeviceListener;
use tokio::sync::{mpsc, oneshot};
use uuid::Uuid;

use crate::message::MrpMessage;
use crate::state::MrpState;
use crate::transport::MrpTransport;
use crate::{Error, Result};

/// What a caller asks the actor to do.
#[derive(Debug)]
pub enum Request {
    /// Write a message and expect no response.
    Send {
        /// The message to write.
        message: MrpMessage,
        /// Where the write result goes.
        reply: oneshot::Sender<Result<()>>,
    },
    /// Write a message and hold the reply slot open until the response arrives.
    Exchange {
        /// The message to write.
        message: MrpMessage,
        /// Correlation key, either the stamped identifier or the synthetic `type_<n>` form.
        key: String,
        /// Where the response goes.
        reply: oneshot::Sender<Result<MrpMessage>>,
    },
    /// Drop an outstanding entry whose caller gave up.
    Cancel {
        /// The key to forget.
        key: String,
    },
    /// Close the transport and stop.
    Shutdown {
        /// Where the teardown result goes.
        reply: oneshot::Sender<Result<()>>,
    },
}

/// Drain the transport into `inbound` until it closes or fails.
///
/// The channel closing is what tells the actor the connection has ended.
pub async fn read_loop(
    transport: Arc<dyn MrpTransport>,
    inbound: mpsc::Sender<Result<MrpMessage>>,
) {
    loop {
        match transport.recv().await {
            Ok(Some(message)) => {
                if inbound.send(Ok(message)).await.is_err() {
                    return;
                }
            }
            Ok(None) => return,
            Err(error) => {
                let _ = inbound.send(Err(error)).await;
                return;
            }
        }
    }
}

/// Why the actor stopped, so a caller can tell a clean close from a dropped connection.
#[derive(Debug)]
pub enum Stopped {
    /// [`Request::Shutdown`] was served.
    OnRequest,
    /// Every handle to the request channel was dropped.
    Abandoned,
    /// The device closed the connection.
    PeerClosed,
    /// The connection failed.
    ConnectionLost(Error),
}

/// Owns one MRP connection for the lifetime of a session.
#[derive(Debug)]
pub struct Actor {
    transport: Arc<dyn MrpTransport>,
    state: Arc<MrpState>,
    requests: mpsc::Receiver<Request>,
    inbound: mpsc::Receiver<Result<MrpMessage>>,
    outstanding: HashMap<String, oneshot::Sender<Result<MrpMessage>>>,
    listener: Option<Arc<dyn DeviceListener>>,
}

impl Actor {
    /// Wrap a connected transport.
    #[must_use]
    pub fn new(
        transport: Arc<dyn MrpTransport>,
        state: Arc<MrpState>,
        requests: mpsc::Receiver<Request>,
        inbound: mpsc::Receiver<Result<MrpMessage>>,
        listener: Option<Arc<dyn DeviceListener>>,
    ) -> Self {
        Self {
            transport,
            state,
            requests,
            inbound,
            outstanding: HashMap::new(),
            listener,
        }
    }

    /// Serve until the caller shuts down or the connection ends.
    pub async fn run(mut self) {
        let stopped = self.serve().await;

        // The two `serve` exits that are *not* a caller's `close()` still have to release the
        // transport: a peer that closed the read side leaves the write half open, and a failed
        // connection leaves the socket — or, for the tunnel, the data channel's frame loop and the
        // AirPlay session behind it — running with nothing driving them. Upstream reaches the same
        // place through `connection_lost` → `MrpProtocol.stop()` (`protocol.py:170-181`).
        if matches!(stopped, Stopped::PeerClosed | Stopped::ConnectionLost(_))
            && let Err(error) = self.transport.close().await
        {
            tracing::debug!(%error, "the MRP transport did not close cleanly after the peer left");
        }

        if !self.outstanding.is_empty() {
            // `if self._outstanding: _LOGGER.warning("There were %d outstanding requests", ...)`
            // (`protocol.py:176-180`).
            tracing::warn!(
                count = self.outstanding.len(),
                "the MRP connection ended with outstanding requests"
            );
        }
        for (_, reply) in self.outstanding.drain() {
            let _ = reply.send(Err(Error::Closed));
        }

        match (&stopped, self.listener.as_ref()) {
            (Stopped::ConnectionLost(error), Some(listener)) => {
                listener.connection_lost(&error.to_string());
            }
            (Stopped::PeerClosed, Some(listener)) => listener.connection_closed(),
            _ => {}
        }
        tracing::debug!(?stopped, "the MRP protocol actor stopped");
    }

    async fn serve(&mut self) -> Stopped {
        loop {
            tokio::select! {
                // Biased towards requests so an already-queued inbound message cannot starve a
                // caller; the message stays in its channel for the next round either way.
                biased;

                request = self.requests.recv() => match request {
                    Some(Request::Shutdown { reply }) => {
                        let _ = reply.send(self.transport.close().await);
                        return Stopped::OnRequest;
                    }
                    Some(request) => self.handle_request(request).await,
                    None => {
                        let _ = self.transport.close().await;
                        return Stopped::Abandoned;
                    }
                },

                incoming = self.inbound.recv() => match incoming {
                    Some(Ok(message)) => self.dispatch(message),
                    Some(Err(error)) => return Stopped::ConnectionLost(error),
                    None => return Stopped::PeerClosed,
                },
            }
        }
    }

    async fn handle_request(&mut self, request: Request) {
        if let Request::Send { message, .. } | Request::Exchange { message, .. } = &request {
            tracing::trace!(
                message_type = message.message_type(),
                kind = ?message.message_type_enum(),
                bytes = message.bytes().len(),
                "sending an MRP message"
            );
        }

        match request {
            Request::Send { message, reply } => {
                let _ = reply.send(self.transport.send(&message).await);
            }
            Request::Exchange {
                message,
                key,
                reply,
            } => match self.transport.send(&message).await {
                Ok(()) => {
                    if let Some(replaced) = self.outstanding.insert(key, reply) {
                        // Only reachable for `type_<n>`-keyed crypto-pairing exchanges, which are
                        // serialised by construction; a second one means a caller bug.
                        let _ = replaced.send(Err(Error::InvalidState(
                            "a second request replaced this one on the same correlation key",
                        )));
                    }
                }
                Err(error) => {
                    let _ = reply.send(Err(error));
                }
            },
            Request::Cancel { key } => {
                drop(self.outstanding.remove(&key));
            }
            Request::Shutdown { .. } => unreachable!("handled in `serve`"),
        }
    }

    /// Resolve an outstanding request, or hand the message to the shared state.
    ///
    /// `message_received` (`protocol.py:283-294`): the correlation key is the identifier when
    /// there is one and `"type_" + str(type)` when there is not, and anything nobody is waiting
    /// for is dispatched to the type-based listeners instead.
    fn dispatch(&mut self, message: MrpMessage) {
        let key = message.correlation_key();
        // At `trace`, because on a live tunnel this fires for every push the device makes — which
        // is also exactly when it is worth having: it is the only view of what a real device sends
        // unprompted, and diagnosing an unrecognised message type without it means guessing.
        tracing::trace!(
            message_type = message.message_type(),
            kind = ?message.message_type_enum(),
            bytes = message.bytes().len(),
            correlated = self.outstanding.contains_key(&key),
            "received an MRP message"
        );

        if let Some(reply) = self.outstanding.remove(&key) {
            let _ = reply.send(Ok(message));
            return;
        }

        if let Err(error) = self.state.handle(&message) {
            tracing::warn!(
                %error,
                message_type = message.message_type(),
                "could not apply an inbound MRP message"
            );
        }
    }
}

/// Send a message through the actor and wait for its response.
///
/// Shared by [`crate::protocol::MrpProtocol::send_and_receive`] and the heartbeat, which needs the
/// same round trip without a handle to the protocol.
///
/// # Errors
///
/// Returns [`Error::Timeout`] if the device does not answer within `timeout`, or [`Error::Closed`]
/// if the actor has stopped.
pub async fn exchange(
    requests: &mpsc::Sender<Request>,
    mut message: MrpMessage,
    tag: bool,
    timeout: Duration,
) -> Result<MrpMessage> {
    if tag {
        message.set_identifier(Uuid::new_v4().to_string().to_uppercase())?;
    }
    let key = message.correlation_key();
    let what = describe(&message);

    let (reply, response) = oneshot::channel();
    requests
        .send(Request::Exchange {
            message,
            key: key.clone(),
            reply,
        })
        .await
        .map_err(|_| Error::Closed)?;

    match tokio::time::timeout(timeout, response).await {
        Ok(Ok(result)) => {
            let response = result?;
            if response.error_code() != 0 {
                // Upstream never inspects `errorCode` on an inbound message, so failing here would
                // reject exchanges pyatv accepts. Surfacing it as a warning keeps the information
                // without inventing a stricter contract than the device's own behaviour supports;
                // callers that do want to be strict have `MrpMessage::check_error_code`.
                tracing::warn!(
                    code = response.error_code(),
                    message_type = response.message_type(),
                    "device answered with a non-zero errorCode"
                );
            }
            Ok(response)
        }
        Ok(Err(_)) => Err(Error::Closed),
        Err(_) => {
            // Do not leave the entry behind: a timed-out request would otherwise pin its slot in
            // the outstanding table for the life of the connection.
            let _ = requests.send(Request::Cancel { key }).await;
            Err(Error::Timeout(what))
        }
    }
}

/// A short description of a message, for timeout diagnostics.
fn describe(message: &MrpMessage) -> String {
    message.message_type_enum().map_or_else(
        || format!("message type {}", message.message_type()),
        |it| format!("{it:?}"),
    )
}
