//! Cross-implementation known-answer tests for pair-verify and transport keys in the HAP pairing
//! crypto.
//!
//! Sibling of `hap_srp_kat.rs`, which covers SRP and pair-setup and documents where these vectors
//! come from and what they deliberately do not compare; read that file's header first. This file
//! covers pair-verify, the per-channel HKDF salt/info literals, and transient pairing, sharing the
//! same `tests/kat/mod.rs` loader.

use pyatv_pairing::{
    TransientPairSetup,
    hkdf_derive::{data_stream_salt, expand, pairing as salts, transport},
    srp_hap::{
        PAIR_VERIFY_M2_NONCE, PAIR_VERIFY_M3_NONCE, open, seal, sign, verify_signature,
        x25519_public_key, x25519_shared_secret,
    },
    tlv8::{Tlv8, TlvValue},
};

mod kat;
use kat::Kat;

/// The session seed `gen_hap_srp_kat.py` pins in place of `random.randint(0, 2**64)`
/// (`pyatv/protocols/airplay/ap2_session.py:156`).
const DATA_STREAM_SEED: u64 = 3_141_592_653_589_793;

// ---------------------------------------------------------------------------------------------
// Pair-verify
// ---------------------------------------------------------------------------------------------

/// ECDH, the `Pair-Verify-Encrypt` key and both encrypted handshake frames, as isolated primitives.
#[test]
fn the_pair_verify_key_schedule_matches_pyatv() {
    let kat = Kat::load();
    let controller_secret = kat.array("pair_verify/controller_x25519_secret");
    let accessory_secret = kat.array("pair_verify/accessory_x25519_secret");
    let controller_public = kat.array("pair_verify/controller_x25519_public");
    let accessory_public = kat.array("pair_verify/accessory_x25519_public");

    assert_eq!(x25519_public_key(&controller_secret), controller_public);
    assert_eq!(x25519_public_key(&accessory_secret), accessory_public);

    let shared = x25519_shared_secret(&controller_secret, &accessory_public);
    assert_eq!(shared, kat.array("pair_verify/shared_secret"));
    assert_eq!(
        x25519_shared_secret(&accessory_secret, &controller_public),
        shared
    );

    let verify_key = expand(
        salts::VERIFY_ENCRYPT_SALT,
        salts::VERIFY_ENCRYPT_INFO,
        &shared,
    )
    .unwrap();
    assert_eq!(verify_key, kat.array("pair_verify/verify_encrypt_key"));

    assert_eq!(
        seal(
            &verify_key,
            PAIR_VERIFY_M2_NONCE,
            &kat.bytes("pair_verify/m2_inner_tlv")
        )
        .unwrap(),
        kat.bytes("pair_verify/m2_encrypted")
    );
    assert_eq!(
        seal(
            &verify_key,
            PAIR_VERIFY_M3_NONCE,
            &kat.bytes("pair_verify/m3_inner_tlv")
        )
        .unwrap(),
        kat.bytes("pair_verify/m3_encrypted")
    );
}

/// The two signed payloads are mirror images — "your key, your name, my key" inbound and "my key,
/// my name, your key" outbound — and getting them the same way round is the classic pair-verify
/// bug. Both are rebuilt here and checked against pyatv's bytes.
#[test]
fn the_pair_verify_signed_payloads_are_mirrored() {
    let kat = Kat::load();
    let controller_public = kat.bytes("pair_verify/controller_x25519_public");
    let accessory_public = kat.bytes("pair_verify/accessory_x25519_public");
    let controller_id = kat.text("pair_verify/controller_pairing_id").as_bytes();
    let accessory_id = kat.text("pair_verify/accessory_pairing_id").as_bytes();

    let mut inbound = accessory_public.clone();
    inbound.extend_from_slice(accessory_id);
    inbound.extend_from_slice(&controller_public);
    assert_eq!(inbound, kat.bytes("pair_verify/m2_signed_payload"));
    assert!(verify_signature(
        &kat.bytes("pair_verify/accessory_ltpk"),
        &inbound,
        &kat.bytes("pair_verify/m2_signature")
    ));

    let mut outbound = controller_public;
    outbound.extend_from_slice(controller_id);
    outbound.extend_from_slice(&accessory_public);
    assert_eq!(outbound, kat.bytes("pair_verify/m3_signed_payload"));
    assert_eq!(
        sign(&kat.array("pair_verify/controller_ltsk"), &outbound),
        kat.bytes("pair_verify/m3_signature")[..]
    );
}

/// The controller state machine driven by pyatv's M2/M4, with the ephemeral pinned so the exchange
/// is replayable. Also checks every transport channel's derived keys against pyatv's.
#[cfg(feature = "test-server")]
#[test]
fn the_pair_verify_state_machine_reproduces_pyatvs_m3_and_transport_keys() {
    use pyatv_pairing::{HapCredentials, PairVerify};

    let kat = Kat::load();
    let credentials = HapCredentials {
        ltpk: kat.bytes("pair_verify/accessory_ltpk"),
        ltsk: kat.bytes("pair_verify/controller_ltsk"),
        atv_id: kat
            .text("pair_verify/accessory_pairing_id")
            .as_bytes()
            .to_vec(),
        client_id: kat
            .text("pair_verify/controller_pairing_id")
            .as_bytes()
            .to_vec(),
    };

    let (mut verifier, m1) = PairVerify::start_with(
        credentials,
        kat.array("pair_verify/controller_x25519_secret"),
    );
    let m1 = Tlv8::decode(&m1).unwrap();
    assert_eq!(
        field(&m1, TlvValue::PublicKey),
        kat.bytes("pair_verify/controller_x25519_public")
    );

    let m3 = Tlv8::decode(
        &verifier
            .handle_m2(&kat.bytes("pair_verify/m2_message"))
            .expect("pyatv's M2 must be accepted"),
    )
    .unwrap();
    let inner = Tlv8::decode(
        &open(
            &kat.array("pair_verify/verify_encrypt_key"),
            PAIR_VERIFY_M3_NONCE,
            &field(&m3, TlvValue::EncryptedData),
        )
        .expect("pyatv's Pair-Verify-Encrypt key must open this port's M3"),
    )
    .unwrap();
    assert_eq!(
        field(&inner, TlvValue::Identifier),
        kat.text("pair_verify/controller_pairing_id").as_bytes()
    );
    assert_eq!(
        field(&inner, TlvValue::Signature),
        kat.bytes("pair_verify/m3_signature")
    );

    assert_eq!(
        verifier.shared_secret(),
        Some(&kat.bytes("transport_keys/pair_verify_ikm")[..])
    );
    verifier
        .handle_m4(&kat.bytes("pair_verify/m4_message"))
        .expect("pyatv's M4 must be accepted");

    for channel in kat.channels("transport_keys/channels") {
        let keys = verifier
            .encryption_keys(&channel.salt, &channel.output_info, &channel.input_info)
            .unwrap();
        assert_eq!(keys.output_key, channel.output_key, "{}", channel.name);
        assert_eq!(keys.input_key, channel.input_key, "{}", channel.name);
    }
}

// ---------------------------------------------------------------------------------------------
// Transport keys and transient pairing
// ---------------------------------------------------------------------------------------------

/// The salt and info literals this crate exposes must be the ones pyatv passed when it produced the
/// vector, including the deliberate read/write swap on the AirPlay event channel and the session
/// seed appended to the data-stream salt.
#[test]
fn the_channel_salt_and_info_literals_are_pyatvs() {
    let kat = Kat::load();

    for channel in kat.channels("transport_keys/channels") {
        let expected = match channel.name.as_str() {
            "mrp" => (
                transport::MRP.salt.to_owned(),
                transport::MRP.write_info,
                transport::MRP.read_info,
            ),
            "companion" => (
                transport::COMPANION.salt.to_owned(),
                transport::COMPANION.write_info,
                transport::COMPANION.read_info,
            ),
            "airplay_control" => (
                transport::AIRPLAY_CONTROL.salt.to_owned(),
                transport::AIRPLAY_CONTROL.write_info,
                transport::AIRPLAY_CONTROL.read_info,
            ),
            // Reversed on purpose: the receiver opens this socket, so pyatv hands the two info
            // strings to `setup_channel` the other way round (`ap2_session.py:137-148`).
            "airplay_events" => (
                transport::AIRPLAY_EVENTS.salt.to_owned(),
                transport::AIRPLAY_EVENTS.read_info,
                transport::AIRPLAY_EVENTS.write_info,
            ),
            "airplay_data_stream" => (
                data_stream_salt(DATA_STREAM_SEED),
                transport::AIRPLAY_DATA_STREAM.write_info,
                transport::AIRPLAY_DATA_STREAM.read_info,
            ),
            other => panic!("the vector grew an unmapped channel: {other}"),
        };

        assert_eq!(
            (
                channel.salt.as_str(),
                channel.output_info.as_str(),
                channel.input_info.as_str()
            ),
            (expected.0.as_str(), expected.1, expected.2),
            "{}",
            channel.name
        );
    }
}

/// Transient pairing keys the transport from the SRP session key `K`, never from an ECDH output
/// (`hap-pairing-port-spec.md` §4.4). pyatv has no test for this path at all, so this vector is the
/// only independent evidence the port's version of it agrees with pyatv's.
#[test]
fn transient_pairing_reproduces_pyatvs_messages_and_keys() {
    let kat = Kat::load();
    let (mut setup, _) =
        TransientPairSetup::start_with(kat.array("transient/srp/client_ephemeral_secret"));

    let m3 = Tlv8::decode(
        &setup
            .handle_m2(&kat.bytes("transient/srp/m2_message"))
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        field(&m3, TlvValue::PublicKey),
        kat.bytes("transient/srp/client_public_a")
    );
    assert_eq!(
        field(&m3, TlvValue::Proof),
        kat.bytes("transient/srp/client_proof_m1")
    );

    setup
        .handle_m4(&kat.bytes("transient/srp/m4_message"))
        .expect("pyatv's M4 proof must verify");

    for channel in kat.channels("transient/transport_keys/channels") {
        let keys = setup
            .encryption_keys(&channel.salt, &channel.output_info, &channel.input_info)
            .unwrap();

        // The IKM is a 64-byte SHA-512 output, not a 32-byte X25519 secret. That difference *is*
        // the flow.
        assert_eq!(keys.shared_secret, kat.bytes("transient/srp/session_key_k"));
        assert_eq!(keys.output_key, channel.output_key, "{}", channel.name);
        assert_eq!(keys.input_key, channel.input_key, "{}", channel.name);
    }
}

/// Read a TLV entry that the vector says must be present.
fn field(tlv: &Tlv8, tag: TlvValue) -> Vec<u8> {
    tlv.get(tag)
        .unwrap_or_else(|| panic!("the message is missing a {tag:?} entry"))
        .to_vec()
}
