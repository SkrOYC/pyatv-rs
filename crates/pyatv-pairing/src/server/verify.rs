//! Pair-verify M1 and M3 as the accessory sees them.
//!
//! Ported from `pyatv/protocols/mrp/server_auth.py:130-175`.

use crate::{
    Error, Result,
    hkdf_derive::{expand, pairing as salts},
    srp_hap::{
        PAIR_VERIFY_M2_NONCE, PAIR_VERIFY_M3_NONCE, open, seal, sign, verify_signature,
        x25519_public_key, x25519_shared_secret,
    },
    tlv8::{ErrorCode, State, Tlv8, TlvValue},
};

use super::{ReferenceAccessory, concat, error_response};

impl ReferenceAccessory {
    /// M1: ECDH, then prove the accessory's identity (`mrp/server_auth.py:130-171`).
    pub(super) fn verify_m1(&mut self, request: &Tlv8) -> Result<Vec<u8>> {
        let client_public_key = <[u8; 32]>::try_from(&request.require(TlvValue::PublicKey)?[..])
            .map_err(|_| Error::InvalidKey {
                kind: "controller X25519 public",
            })?;

        let public_key = x25519_public_key(&self.seed);
        let shared_secret = x25519_shared_secret(&self.seed, &client_public_key);
        let session_key = expand(
            salts::VERIFY_ENCRYPT_SALT,
            salts::VERIFY_ENCRYPT_INFO,
            &shared_secret,
        )?;

        let signed = concat(&[&public_key, &self.identifier, &client_public_key]);
        let inner = Tlv8::new()
            .with(TlvValue::Identifier, self.identifier.clone())
            .with(
                TlvValue::Signature,
                sign(&self.signing_seed, &signed).to_vec(),
            );

        self.shared_secret = Some(shared_secret.to_vec());
        self.client_ephemeral = Some(client_public_key.to_vec());

        Ok(Tlv8::new()
            .with_byte(TlvValue::SeqNo, State::M2 as u8)
            .with(TlvValue::PublicKey, public_key.to_vec())
            .with(
                TlvValue::EncryptedData,
                seal(&session_key, PAIR_VERIFY_M2_NONCE, &inner.encode())?,
            )
            .encode()
            .to_vec())
    }

    /// M3: check the controller's identity, then acknowledge (`mrp/server_auth.py:173-175`).
    pub(super) fn verify_m3(&mut self, request: &Tlv8) -> Result<Vec<u8>> {
        let shared_secret = self
            .shared_secret
            .clone()
            .ok_or(Error::OutOfOrder("pair-verify M1 has not been handled"))?;

        let session_key = expand(
            salts::VERIFY_ENCRYPT_SALT,
            salts::VERIFY_ENCRYPT_INFO,
            &shared_secret,
        )?;
        let inner = Tlv8::decode(&open(
            &session_key,
            PAIR_VERIFY_M3_NONCE,
            request.require(TlvValue::EncryptedData)?,
        )?)?;

        let client_id = inner.require(TlvValue::Identifier)?.clone();
        let signature = inner.require(TlvValue::Signature)?.clone();

        let Some(pairing) = self
            .pairings
            .iter()
            .find(|pairing| pairing.client_id == client_id[..])
        else {
            return Ok(error_response(State::M4, ErrorCode::Authentication));
        };

        let client_ephemeral = self
            .client_ephemeral
            .clone()
            .ok_or(Error::OutOfOrder("pair-verify M1 has not been handled"))?;

        // The controller signs its own ephemeral key first: controllerPK | controllerID |
        // accessoryPK (`pyatv/auth/hap_srp.py:109-113`) — the mirror of what the accessory signed
        // in M2, not the same tuple relabelled.
        let signed = concat(&[
            &client_ephemeral,
            &client_id,
            &x25519_public_key(&self.seed),
        ]);
        if !verify_signature(&pairing.ltpk, &signed, &signature) {
            return Ok(error_response(State::M4, ErrorCode::Authentication));
        }

        Ok(Tlv8::new()
            .with_byte(TlvValue::SeqNo, State::M4 as u8)
            .encode()
            .to_vec())
    }
}
