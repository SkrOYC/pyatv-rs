//! The periodic liveness round trip.
//!
//! Port of `heartbeater` (`pyatv/core/protocol.py:34-76`) as `MrpProtocol.enable_heartbeat` uses it
//! (`protocol.py:188-205`): a bare `GENERIC_MESSAGE` sent with `send_and_receive`, so the *round
//! trip* is the liveness check rather than a fire-and-forget ping.
//!
//! Two details are easy to lose in translation and are reproduced deliberately:
//!
//! * The message object is built **once**, before the loop. Each round trip restamps its
//!   `identifier` but keeps the same `uniqueIdentifier`, so a device that tracked those would see
//!   the same value on every heartbeat of a session.
//! * A retry is attempted with **no** delay — "re-attempts are made with no initial delay to more
//!   quickly recover a failed heartbeat" — so a single dropped response costs one round trip, not
//!   a whole interval.
//!
//! The interval is a parameter rather than a constant because heartbeat desync against recent tvOS
//! builds is a live, unresolved issue upstream; a caller that needs to tune it must be able to.

use std::time::Duration;

use tokio::sync::mpsc;

use crate::messages;
use crate::protobuf::protocol_message::Type;
use crate::protocol::HEARTBEAT_RETRIES;
use crate::protocol::actor::{Request, exchange};

/// Send a heartbeat every `interval` until one fails past its retries.
///
/// Returns when the connection should be considered dead; the caller's `failure_func` equivalent is
/// simply that this function closes the transport on its way out (`_failure_func` calls
/// `self.connection.close()`, `protocol.py:196-197`).
pub async fn run(requests: mpsc::Sender<Request>, interval: Duration, timeout: Duration) {
    let message = messages::create(Type::GenericMessage);
    let mut attempts = 0usize;
    let mut count = 0usize;

    loop {
        if attempts == 0 {
            tokio::time::sleep(interval).await;
        }

        match exchange(&requests, message.clone(), true, timeout).await {
            Ok(_) => {
                tracing::trace!(count, "got MRP heartbeat");
                attempts = 0;
            }
            Err(crate::Error::Closed) => {
                tracing::debug!("stopping the MRP heartbeat: the connection is closed");
                return;
            }
            Err(error) => {
                attempts += 1;
                if attempts > HEARTBEAT_RETRIES {
                    tracing::debug!(count, attempts, %error, "MRP heartbeat failed; closing");
                    let (reply, _response) = tokio::sync::oneshot::channel();
                    let _ = requests.send(Request::Shutdown { reply }).await;
                    return;
                }
                tracing::debug!(count, %error, "MRP heartbeat failed; retrying immediately");
            }
        }

        count += 1;
    }
}
