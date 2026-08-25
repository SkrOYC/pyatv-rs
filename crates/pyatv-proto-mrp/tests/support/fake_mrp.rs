//! A hermetic MRP device: real varint framing, real ChaCha20, over a real loopback socket.
//!
//! Port of `FakeMrpService` (`tests/fake_device/mrp.py:379-650`) and the `MrpServerAuth` mixin it
//! inherits (`pyatv/protocols/mrp/server_auth.py`). The crypto is
//! [`pyatv_pairing::server::ReferenceAccessory`]; this file adds MRP's framing and the handlers
//! bring-up and the functional tests need.
//!
//! The framing is transcribed from `mrp.py:407-459` rather than reused from
//! [`pyatv_proto_mrp::transport::direct`], for the same reason upstream's fake re-derives it: a
//! fixture that shares an implementation with the code under test cannot catch a bug in it.

use std::net::SocketAddr;
use std::sync::Arc;

use pyatv_pairing::server::ReferenceAccessory;
use tokio::net::TcpListener;
use tokio::sync::Mutex;

use super::fake_connection::Connection;
use super::fake_state::FakeDeviceState;

/// A running fake device. Dropping it stops the accept loop and every connection.
#[derive(Debug)]
pub struct FakeMrpDevice {
    address: SocketAddr,
    state: Arc<FakeDeviceState>,
    accessory: Arc<Mutex<ReferenceAccessory>>,
    task: tokio::task::JoinHandle<()>,
    connections: Arc<std::sync::Mutex<Vec<tokio::task::JoinHandle<()>>>>,
}

impl Drop for FakeMrpDevice {
    fn drop(&mut self) {
        self.task.abort();
        self.kill_connections();
    }
}

impl FakeMrpDevice {
    /// Bind an ephemeral loopback port and start serving; `pin` is what the device would display.
    pub async fn start(pin: u32) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("binding a loopback port must succeed in tests");
        let address = listener
            .local_addr()
            .expect("a bound listener must have an address");

        let state = Arc::new(FakeDeviceState::new());
        let accessory = Arc::new(Mutex::new(ReferenceAccessory::with_pin(pin)));
        let connections = Arc::new(std::sync::Mutex::new(Vec::new()));

        let served_state = Arc::clone(&state);
        let served_accessory = Arc::clone(&accessory);
        let served_connections = Arc::clone(&connections);
        let task = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let state = Arc::clone(&served_state);
                let accessory = Arc::clone(&served_accessory);
                let handle = tokio::spawn(async move {
                    Connection::new(stream, state, accessory).serve().await;
                });
                if let Ok(mut open) = served_connections.lock() {
                    open.push(handle);
                }
            }
        });

        Self {
            address,
            state,
            accessory,
            task,
            connections,
        }
    }

    /// Where a controller should connect.
    #[must_use]
    pub const fn address(&self) -> SocketAddr {
        self.address
    }

    /// What the device believes, and the use-case helpers that change it.
    #[must_use]
    pub fn state(&self) -> Arc<FakeDeviceState> {
        Arc::clone(&self.state)
    }

    /// The accessory's crypto state, for asserting on what it accepted.
    #[must_use]
    pub fn accessory(&self) -> Arc<Mutex<ReferenceAccessory>> {
        Arc::clone(&self.accessory)
    }

    /// Yank every live connection, as a device losing power would.
    pub fn kill_connections(&self) {
        let Ok(mut open) = self.connections.lock() else {
            return;
        };
        for handle in open.drain(..) {
            handle.abort();
        }
    }
}
