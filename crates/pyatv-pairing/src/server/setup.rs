//! Pair-setup M1, M3 and M5 as the accessory sees them.
//!
//! Ported from `pyatv/protocols/mrp/server_auth.py:177-239`, with the transient branch from
//! `pyatv/protocols/airplay/server_auth.py:310-352`.

use crate::{
    Error, Result,
    hkdf_derive::{expand, pairing as salts},
    srp_encoding::minimal_be,
    srp_hap::{
        MODULUS_LEN, PAIR_SETUP_M5_NONCE, PAIR_SETUP_M6_NONCE, PAIR_SETUP_USERNAME, open,
        random_seed, seal, sign, verify_signature,
    },
    tlv8::{ErrorCode, State, Tlv8, TlvValue},
};

use super::{
    HapClient, HapServer, ReferenceAccessory, SetupSession, TRANSIENT_PIN, concat, error_response,
};

impl ReferenceAccessory {
    /// M1: publish the salt and `B` (`mrp/server_auth.py:177-186`).
    pub(super) fn setup_m1(&mut self, request: &Tlv8) -> Vec<u8> {
        let transient = request
            .get(TlvValue::Flags)
            .and_then(|flags| flags.first())
            .is_some_and(|flags| flags & crate::tlv8::FLAG_TRANSIENT_PAIRING != 0);

        let pin = if transient { TRANSIENT_PIN } else { self.pin };
        let mut salt = [0u8; 16];
        salt.copy_from_slice(&random_seed()[..16]);

        let verifier = HapClient::new().compute_verifier(
            PAIR_SETUP_USERNAME,
            format!("{pin:04}").as_bytes(),
            &salt,
        );
        let public_key = HapServer::new().compute_public_ephemeral(&self.seed, &verifier);

        self.setup = Some(SetupSession {
            salt,
            verifier,
            transient,
            session_key: None,
        });

        Tlv8::new()
            .with_byte(TlvValue::SeqNo, State::M2 as u8)
            .with(TlvValue::Salt, salt.to_vec())
            .with(TlvValue::PublicKey, public_key)
            .encode()
            .to_vec()
    }

    /// M3: check the controller's SRP proof and answer with the accessory's
    /// (`mrp/server_auth.py:188-205`).
    pub(super) fn setup_m3(&mut self, request: &Tlv8) -> Result<Vec<u8>> {
        let session = self
            .setup
            .as_mut()
            .ok_or(Error::OutOfOrder("pair-setup M1 has not been handled"))?;

        // Same normalise-then-range-check as the controller applies to `B`
        // (`crate::srp_hap::HapSrpClient::process_challenge`): `srptools` hashes `A` as an integer,
        // and `srp`'s `Server::process_reply` panics inside `crypto_bigint`'s `Resize` on a value
        // wider than `N` rather than returning an error.
        let client_public_key = minimal_be(request.require(TlvValue::PublicKey)?).to_vec();
        if client_public_key.len() > MODULUS_LEN {
            return Err(Error::SrpPublicKey { peer: "controller" });
        }
        let client_proof = request.require(TlvValue::Proof)?.clone();

        // `g_no_pad = true` is the HAP profile. The crate's own doc comment on
        // `Server::new_with_options` says the opposite; `docs/research/crate-verification-2026-08-24.md`
        // §1 disproved it empirically.
        let verifier = HapServer::new_with_options(true)
            .process_reply(
                PAIR_SETUP_USERNAME,
                &session.salt,
                &self.seed,
                &session.verifier,
                &client_public_key,
            )
            .map_err(|_| Error::SrpPublicKey { peer: "controller" })?;

        let Ok(session_key) = verifier.verify_client(&client_proof) else {
            self.setup = None;
            return Ok(Tlv8::new()
                .with_byte(TlvValue::SeqNo, State::M4 as u8)
                .with_byte(TlvValue::Error, ErrorCode::Authentication as u8)
                .encode()
                .to_vec());
        };

        session.session_key = Some(session_key.to_vec());
        if session.transient {
            // Transient pairing stops here and keys the transport from `K` itself
            // (`airplay/server_auth.py:322-352`).
            self.shared_secret = Some(session_key.to_vec());
        }

        Ok(Tlv8::new()
            .with_byte(TlvValue::SeqNo, State::M4 as u8)
            .with(TlvValue::Proof, verifier.proof().to_vec())
            .encode()
            .to_vec())
    }

    /// M5: record the controller's identity and return the accessory's
    /// (`mrp/server_auth.py:207-239`).
    pub(super) fn setup_m5(&mut self, request: &Tlv8) -> Result<Vec<u8>> {
        let session_key = self
            .setup
            .as_ref()
            .and_then(|session| session.session_key.clone())
            .ok_or(Error::OutOfOrder("pair-setup M3 has not been accepted"))?;

        let encrypt_key = expand(
            salts::SETUP_ENCRYPT_SALT,
            salts::SETUP_ENCRYPT_INFO,
            &session_key,
        )?;
        let inner = Tlv8::decode(&open(
            &encrypt_key,
            PAIR_SETUP_M5_NONCE,
            request.require(TlvValue::EncryptedData)?,
        )?)?;

        let client_id = inner.require(TlvValue::Identifier)?.clone();
        let client_ltpk = inner.require(TlvValue::PublicKey)?.clone();
        let signature = inner.require(TlvValue::Signature)?.clone();

        let controller_x = expand(
            salts::CONTROLLER_SIGN_SALT,
            salts::CONTROLLER_SIGN_INFO,
            &session_key,
        )?;
        if !verify_signature(
            &client_ltpk,
            &concat(&[&controller_x, &client_id, &client_ltpk]),
            &signature,
        ) {
            return Ok(error_response(State::M6, ErrorCode::Authentication));
        }

        self.register_pairing(&client_id, &client_ltpk);

        let accessory_x = expand(
            salts::ACCESSORY_SIGN_SALT,
            salts::ACCESSORY_SIGN_INFO,
            &session_key,
        )?;
        let public_key = self.public_key();
        let signed = concat(&[&accessory_x, &self.identifier, &public_key]);

        let inner = Tlv8::new()
            .with(TlvValue::Identifier, self.identifier.clone())
            .with(TlvValue::PublicKey, public_key.to_vec())
            .with(
                TlvValue::Signature,
                sign(&self.signing_seed, &signed).to_vec(),
            );

        Ok(Tlv8::new()
            .with_byte(TlvValue::SeqNo, State::M6 as u8)
            .with(
                TlvValue::EncryptedData,
                seal(&encrypt_key, PAIR_SETUP_M6_NONCE, &inner.encode())?,
            )
            .encode()
            .to_vec())
    }
}
