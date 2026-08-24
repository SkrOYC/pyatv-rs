//! The RTI text-input exchange: `_tiStop`, `_tiStart`, then optional `_tiC` events.
//!
//! Port of `text_input_command` (`api.py:409-452`, `docs/research/companion-port-spec.md` §3.6).
//! The one thing that looks like an optimisation and is not: **every** text operation restarts the
//! RTI session first, even a pure read, because the `sessionUUID` and the current text both come
//! out of the fresh `_tiStart` response. Skipping the restart would let a stale UUID reach the
//! device, which silently drops the operation.
//!
//! The `_tiD` payload inside the OPACK envelope is an `NSKeyedArchiver` binary plist, the only
//! place in Companion where a second serialisation format is nested inside `_c`. It is read with
//! [`crate::keyed_archiver`] and written with [`crate::plist_payloads`].

use pyatv_opack::{Value, opack};

use crate::Result;
use crate::api::CompanionApi;
use crate::keyed_archiver::{self, as_data, as_string};
use crate::plist_payloads::{rti_clear_text_payload, rti_input_text_payload};

/// `_tiC`'s RTI version field. Never varied upstream.
const RTI_VERSION: u64 = 1;

impl CompanionApi {
    /// Read, clear and/or append the focused text field's contents in one exchange.
    ///
    /// Returns the field's contents *after* the operation, or `None` when the device answered
    /// `_tiStart` without a `_tiD` — which is how it says nothing has focus.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::Envelope`] if `_tiD` is present but is not a parseable keyed
    /// archive, plus anything [`CompanionApi::send_command`] can return.
    pub async fn text_input_command(
        &self,
        text: &str,
        clear_previous_input: bool,
    ) -> Result<Option<String>> {
        // "restart the text input session so that we have up-to-date data" (`api.py:415-417`).
        self.text_input_stop().await?;
        let response = self.text_input_start().await?;

        let Some(archive) = response.get("_tiD").and_then(Value::as_bytes) else {
            return Ok(None);
        };

        let read = keyed_archiver::read_archive_properties(
            archive,
            &[
                &["sessionUUID"],
                &["documentState", "docSt", "contextBeforeInput"],
            ],
        )?;

        let session_uuid = as_data(read.first().and_then(Option::as_ref))
            .unwrap_or_default()
            .to_vec();
        // `if current_text is None: current_text = ""` (`api.py:429-430`).
        let mut current = as_string(read.get(1).and_then(Option::as_ref))
            .unwrap_or_default()
            .to_owned();

        if clear_previous_input {
            self.send_text_operation(rti_clear_text_payload(&session_uuid))
                .await?;
            current.clear();
        }

        // Deliberately `if text:` and not `if text is not None:` — an empty string sends nothing,
        // which is what makes `text_get()` a pure read (`api.py:442`).
        if !text.is_empty() {
            self.send_text_operation(rti_input_text_payload(&session_uuid, text))
                .await?;
            current.push_str(text);
        }

        Ok(Some(current))
    }

    /// Send one `_tiC` event carrying a keyed-archive payload.
    async fn send_text_operation(&self, payload: Vec<u8>) -> Result<()> {
        self.send_event(
            "_tiC",
            opack! {
                "_tiV" => RTI_VERSION,
                "_tiD" => payload,
            },
        )
        .await
    }
}
