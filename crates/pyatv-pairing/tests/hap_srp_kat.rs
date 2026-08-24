//! Cross-implementation known-answer tests for the HAP pairing crypto.
//!
//! `tests/hap_pairing.rs` runs this port's controller against this port's own reference accessory,
//! which proves the two halves agree with each other and nothing more. The vectors loaded here come
//! from somewhere else entirely: `tests/kat/gen_hap_srp_kat.py` drives **pyatv itself**, on pyatv's
//! own dependencies (`srptools` for SRP6a, `cryptography` for HKDF-SHA512/Ed25519/X25519,
//! `chacha20poly1305-reuseable` for the AEAD), with every source of randomness pinned. That closes
//! `docs/research/hap-pairing-port-spec.md` §11 finding 6, which flagged that no byte-level SRP
//! vector existed anywhere in pyatv's tree and that one would have to be generated.
//!
//! Regenerate with the command in the generator's header comment; the script is deterministic, so a
//! regenerated file must be byte-identical.
//!
//! # What these tests deliberately do not compare
//!
//! Nothing here asserts on whole TLV8 messages this port *produced*. TLV8 encoding is
//! insertion-ordered and the layout of an outbound message is a detail of the state machines, so
//! every comparison is either against a value that is not a TLV (a key, a signature, a proof, a
//! ciphertext over a plaintext the vector supplies verbatim) or against *parsed fields* of a TLV.
//! Messages that pyatv encoded are fed to the decoder as-is, which is a bonus interop check in the
//! inbound direction.

use pyatv_pairing::{
    PairSetup, TransientPairSetup,
    hkdf_derive::{data_stream_salt, expand, pairing as salts, transport},
    pairing::PairSetupOptions,
    srp_hap::{
        HapSrpClient, PAIR_SETUP_M5_NONCE, PAIR_SETUP_M6_NONCE, PAIR_SETUP_USERNAME,
        PAIR_VERIFY_M2_NONCE, PAIR_VERIFY_M3_NONCE, ed25519_public_key, handshake_nonce, open,
        seal, sign, verify_signature, x25519_public_key, x25519_shared_secret,
    },
    tlv8::{Tlv8, TlvValue},
};

mod kat;
use kat::Kat;

/// The session seed `gen_hap_srp_kat.py` pins in place of `random.randint(0, 2**64)`
/// (`pyatv/protocols/airplay/ap2_session.py:156`).
const DATA_STREAM_SEED: u64 = 3_141_592_653_589_793;

// ---------------------------------------------------------------------------------------------
// SRP
// ---------------------------------------------------------------------------------------------

/// The core vector: given pyatv's `a`, PIN, salt and `B`, this port must produce pyatv's `A`, `M1`
/// and `K`, and must accept pyatv's `M2`.
#[test]
fn the_srp_exchange_reproduces_pyatvs_a_m1_and_k() {
    let kat = Kat::load();
    let mut client = HapSrpClient::with_pin(
        kat.text("srp/pin"),
        kat.array("srp/client_ephemeral_secret"),
    );

    assert_eq!(PAIR_SETUP_USERNAME, kat.text("srp/username").as_bytes());
    assert_eq!(client.public_key(), kat.bytes("srp/client_public_a"));

    let proof = client
        .process_challenge(&kat.bytes("srp/salt"), &kat.bytes("srp/server_public_b"))
        .expect("pyatv's B must be accepted");

    assert_eq!(proof, kat.bytes("srp/client_proof_m1"));
    assert_eq!(client.client_proof(), Some(&proof[..]));
    assert_eq!(
        client.session_key(),
        Some(&kat.bytes("srp/session_key_k")[..])
    );
    client
        .verify_device_proof(&kat.bytes("srp/server_proof_m2"))
        .expect("pyatv's M2 must verify");
}

/// The single biggest interop gotcha in the whole stack, pinned against an independent
/// implementation: `srptools` hashes `g` **unpadded** in M1, RustCrypto's `Client::process_reply`
/// hashes it padded to `len(N)`, and only the first is what a real accessory accepts.
///
/// The vector carries both forms, so this test can show the two really do differ for these inputs,
/// that this port emits the unpadded one, and that the padded one is exactly what the ergonomic
/// `srp` API would have produced — i.e. the diagnosis in `srp_hap`'s module documentation is right
/// and the workaround is still necessary.
#[test]
fn the_m1_proof_uses_the_unpadded_generator() {
    use sha2::Sha512;
    use srp::{
        Client, Group,
        groups::G3072,
        utils::{compute_hash_n_xor_hash_g, compute_hash_n_xor_hash_pad_g},
    };

    let kat = Kat::load();
    let unpadded = kat.bytes("srp/client_proof_m1");
    let padded = kat.bytes("srp/client_proof_m1_padded_g");
    assert_ne!(unpadded, padded, "the vector's negative control is vacuous");

    assert_eq!(
        compute_hash_n_xor_hash_g::<Sha512>(&G3072::generator()),
        kat.bytes("srp/hash_n_xor_hash_g")
    );
    assert_eq!(
        compute_hash_n_xor_hash_pad_g::<Sha512>(&G3072::generator()),
        kat.bytes("srp/hash_n_xor_hash_pad_g")
    );

    let mut client = HapSrpClient::with_pin(
        kat.text("srp/pin"),
        kat.array("srp/client_ephemeral_secret"),
    );
    let ours = client
        .process_challenge(&kat.bytes("srp/salt"), &kat.bytes("srp/server_public_b"))
        .expect("pyatv's B must be accepted");
    assert_eq!(ours, unpadded);

    let default_api = Client::<G3072, Sha512>::new()
        .process_reply(
            &kat.bytes("srp/client_ephemeral_secret"),
            PAIR_SETUP_USERNAME,
            kat.text("srp/pin").as_bytes(),
            &kat.bytes("srp/salt"),
            &kat.bytes("srp/server_public_b"),
        )
        .expect("pyatv's B must be accepted");
    assert_eq!(
        default_api.proof(),
        padded,
        "`srp` changed its default M1; re-read srp_hap's module documentation"
    );
    assert_eq!(
        default_api.key(),
        kat.bytes("srp/premaster_secret_s"),
        "the premaster secret is shared with `srptools`; only the proof differs"
    );
}

// ---------------------------------------------------------------------------------------------
// SRP: the leading-zero public values
// ---------------------------------------------------------------------------------------------

/// The three exchanges in the main vector file all have a full-width `A` and `B` — the generator
/// asserts it, because they were meant to be the representative case. That leaves the ~1-in-256
/// case untested, and it is the one where `srptools`' minimal-length integer encoding stops
/// agreeing with "hash the bytes you were given": pyatv parses `B` as an integer and hashes it in
/// its shortest big-endian form, and puts the same shortest form of `A` on the wire.
///
/// `gen_hap_srp_kat.py --leading-zero` searches a deterministic seed sequence for a client `a` and
/// a server `b` that produce short public values, then emits three exchanges — short `A`, short
/// `B`, and both — through the same pyatv code path as the main vectors. This port has to
/// reproduce pyatv's `A`, `M1`, `K` and `M2` for all three.
#[test]
fn leading_zero_public_values_reproduce_pyatvs_a_m1_and_m2() {
    let kat = Kat::load_leading_zero();

    for case in ["leading_zero_a", "leading_zero_b", "leading_zero_both"] {
        let srp = format!("{case}/srp");
        let expected_a = kat.bytes(&format!("{srp}/client_public_a"));
        let expected_b = kat.bytes(&format!("{srp}/server_public_b"));

        // The vector really exercises what it claims: a short value is 383 bytes, not 384.
        assert_eq!(
            expected_a.len(),
            kat.length(&format!("{case}/client_public_a_len")),
            "{case}: A"
        );
        assert_eq!(
            expected_b.len(),
            kat.length(&format!("{case}/server_public_b_len")),
            "{case}: B"
        );
        assert_ne!(expected_a[0], 0, "{case}: pyatv never sends a padded A");
        assert_ne!(expected_b[0], 0, "{case}: pyatv never sends a padded B");

        let mut client = HapSrpClient::with_pin(
            kat.text(&format!("{srp}/pin")),
            kat.array(&format!("{srp}/client_ephemeral_secret")),
        );

        // `A` on the wire is the minimal form, so a 383-byte value stays 383 bytes.
        assert_eq!(client.public_key(), expected_a, "{case}: A on the wire");

        let proof = client
            .process_challenge(&kat.bytes(&format!("{srp}/salt")), &expected_b)
            .unwrap_or_else(|error| panic!("{case}: pyatv's B must be accepted: {error}"));

        assert_eq!(
            proof,
            kat.bytes(&format!("{srp}/client_proof_m1")),
            "{case}: M1"
        );
        assert_eq!(
            client.session_key(),
            Some(&kat.bytes(&format!("{srp}/session_key_k"))[..]),
            "{case}: K"
        );
        client
            .verify_device_proof(&kat.bytes(&format!("{srp}/server_proof_m2")))
            .unwrap_or_else(|error| panic!("{case}: pyatv's M2 must verify: {error}"));
    }
}

/// A device that zero-pads `B` out to the modulus width is describing the same integer, so it must
/// produce the same `M1` — that is the whole point of normalising rather than hashing the slice.
/// Conversely, *hashing* the padded form is what a naive port does, and this pins that it really
/// would produce a different proof: without that assertion the test above could pass for a port
/// that never normalises anything.
#[test]
fn padding_b_changes_nothing_but_hashing_the_padding_would() {
    use sha2::Sha512;
    use srp::{Group, groups::G3072, utils::compute_m1_rfc5054};

    let kat = Kat::load_leading_zero();
    let srp = "leading_zero_b/srp";

    let minimal_b = kat.bytes(&format!("{srp}/server_public_b"));
    let mut padded_b = vec![0u8];
    padded_b.extend_from_slice(&minimal_b);
    assert_eq!(padded_b.len(), 384);

    let expected_m1 = kat.bytes(&format!("{srp}/client_proof_m1"));
    let salt = kat.bytes(&format!("{srp}/salt"));
    let seed: [u8; 32] = kat.array(&format!("{srp}/client_ephemeral_secret"));

    let mut from_padded = HapSrpClient::with_pin(kat.text(&format!("{srp}/pin")), seed);
    assert_eq!(
        from_padded.process_challenge(&salt, &padded_b).unwrap(),
        expected_m1,
        "a zero-padded B is the same integer and must give pyatv's M1"
    );

    // The negative control: hashing the padded slice, as `srp`'s own API would if handed the wire
    // bytes untouched, gives a proof no accessory would accept.
    let naive = compute_m1_rfc5054::<Sha512>(
        &G3072::generator(),
        true,
        PAIR_SETUP_USERNAME,
        &salt,
        &kat.bytes(&format!("{srp}/client_public_a")),
        &padded_b,
        &kat.bytes(&format!("{srp}/session_key_k")),
    );
    assert_ne!(
        naive.as_slice(),
        &expected_m1[..],
        "the control is vacuous: padding B made no difference to the hash"
    );
}

/// The same thing one level up: driven through the whole state machine from pyatv's own M2 and M4
/// bytes, the short `A` has to go into the M3 `PublicKey` TLV unpadded. A port that widened `A` to
/// the modulus would still compute a self-consistent `M1` and only fail against a real device.
#[test]
fn the_state_machine_puts_a_short_a_on_the_wire_unpadded() {
    let kat = Kat::load_leading_zero();

    for case in ["leading_zero_a", "leading_zero_both"] {
        let srp = format!("{case}/srp");
        let seed: [u8; 32] = kat.array(&format!("{srp}/client_ephemeral_secret"));

        let (mut setup, _) = PairSetup::start_with(
            PairSetupOptions {
                pin: Some(kat.text(&format!("{srp}/pin")).parse().unwrap()),
                ..PairSetupOptions::default()
            },
            seed,
            b"leading-zero-client".to_vec(),
        );

        let m3 = Tlv8::decode(
            &setup
                .handle_m2(&kat.bytes(&format!("{srp}/m2_message")))
                .unwrap_or_else(|error| panic!("{case}: {error}")),
        )
        .unwrap();

        let public_key = field(&m3, TlvValue::PublicKey);
        assert_eq!(public_key.len(), 383, "{case}: A stays minimal on the wire");
        assert_eq!(
            public_key,
            kat.bytes(&format!("{srp}/client_public_a")),
            "{case}: A"
        );
        assert_eq!(
            field(&m3, TlvValue::Proof),
            kat.bytes(&format!("{srp}/client_proof_m1")),
            "{case}: M1"
        );

        setup
            .handle_m4(&kat.bytes(&format!("{srp}/m4_message")))
            .unwrap_or_else(|error| panic!("{case}: pyatv's M4 proof must verify: {error}"));
    }
}

// ---------------------------------------------------------------------------------------------
// Pair-setup
// ---------------------------------------------------------------------------------------------

/// Every HKDF derivation, Ed25519 signature and AEAD frame of pair-setup M5/M6, checked as isolated
/// primitives against pyatv's values. The plaintexts come from the vector, so nothing here depends
/// on how this port orders TLV entries.
#[test]
fn the_pair_setup_key_schedule_matches_pyatv() {
    let kat = Kat::load();
    let session_key = kat.bytes("srp/session_key_k");

    let controller_sign_key = expand(
        salts::CONTROLLER_SIGN_SALT,
        salts::CONTROLLER_SIGN_INFO,
        &session_key,
    )
    .unwrap();
    let setup_encrypt_key = expand(
        salts::SETUP_ENCRYPT_SALT,
        salts::SETUP_ENCRYPT_INFO,
        &session_key,
    )
    .unwrap();
    let accessory_sign_key = expand(
        salts::ACCESSORY_SIGN_SALT,
        salts::ACCESSORY_SIGN_INFO,
        &session_key,
    )
    .unwrap();

    assert_eq!(
        controller_sign_key,
        kat.array("pair_setup/controller_sign_key")
    );
    assert_eq!(setup_encrypt_key, kat.array("pair_setup/setup_encrypt_key"));
    assert_eq!(
        accessory_sign_key,
        kat.array("pair_setup/accessory_sign_key")
    );

    // The signed payload is `iOSDeviceX | iOSDevicePairingID | iOSDeviceLTPK`; rebuilding it here
    // and comparing against pyatv's is what pins the field order.
    let seed = kat.array("pair_setup/controller_seed");
    let public_key = ed25519_public_key(&seed);
    assert_eq!(public_key, kat.array("pair_setup/controller_ltpk"));

    let mut payload = controller_sign_key.to_vec();
    payload.extend_from_slice(kat.text("pair_setup/controller_pairing_id").as_bytes());
    payload.extend_from_slice(&public_key);
    assert_eq!(payload, kat.bytes("pair_setup/m5_signed_payload"));
    assert_eq!(
        sign(&seed, &payload),
        kat.bytes("pair_setup/m5_signature")[..]
    );

    assert_eq!(
        handshake_nonce(PAIR_SETUP_M5_NONCE),
        *b"\x00\x00\x00\x00PS-Msg05"
    );
    assert_eq!(
        seal(
            &setup_encrypt_key,
            PAIR_SETUP_M5_NONCE,
            &kat.bytes("pair_setup/m5_inner_tlv")
        )
        .unwrap(),
        kat.bytes("pair_setup/m5_encrypted")
    );
    assert_eq!(
        open(
            &setup_encrypt_key,
            PAIR_SETUP_M6_NONCE,
            &kat.bytes("pair_setup/m6_encrypted")
        )
        .unwrap(),
        kat.bytes("pair_setup/m6_inner_tlv")
    );
}

/// The accessory's M6 signature, which pyatv decodes and never checks (`hap_srp.py:229` is a
/// literal `# TODO`). This port does check it, so the vector has to prove the payload it builds is
/// the one the accessory actually signed.
#[test]
fn the_accessory_m6_signature_verifies_against_the_vector() {
    let kat = Kat::load();
    let accessory_ltpk = kat.bytes("pair_setup/accessory_ltpk");

    let mut payload = kat.bytes("pair_setup/accessory_sign_key");
    payload.extend_from_slice(kat.text("pair_setup/accessory_pairing_id").as_bytes());
    payload.extend_from_slice(&accessory_ltpk);

    assert_eq!(payload, kat.bytes("pair_setup/m6_signed_payload"));
    assert!(verify_signature(
        &accessory_ltpk,
        &payload,
        &kat.bytes("pair_setup/m6_signature")
    ));
}

/// The whole controller state machine, driven by pyatv's own M2/M4/M6 bytes.
#[test]
fn the_pair_setup_state_machine_reproduces_pyatvs_messages() {
    let kat = Kat::load();
    let seed = kat.array("pair_setup/controller_seed");
    let client_id = kat
        .text("pair_setup/controller_pairing_id")
        .as_bytes()
        .to_vec();

    let (mut setup, _) = PairSetup::start_with(
        PairSetupOptions {
            pin: Some(kat.text("srp/pin").parse().unwrap()),
            ..PairSetupOptions::default()
        },
        seed,
        client_id.clone(),
    );

    let m3 = Tlv8::decode(&setup.handle_m2(&kat.bytes("srp/m2_message")).unwrap()).unwrap();
    assert_eq!(
        field(&m3, TlvValue::PublicKey),
        kat.bytes("srp/client_public_a")
    );
    assert_eq!(
        field(&m3, TlvValue::Proof),
        kat.bytes("srp/client_proof_m1")
    );

    let m5 = Tlv8::decode(&setup.handle_m4(&kat.bytes("srp/m4_message")).unwrap()).unwrap();
    let inner = Tlv8::decode(
        &open(
            &kat.array("pair_setup/setup_encrypt_key"),
            PAIR_SETUP_M5_NONCE,
            &field(&m5, TlvValue::EncryptedData),
        )
        .expect("pyatv's Pair-Setup-Encrypt key must open this port's M5"),
    )
    .unwrap();

    assert_eq!(field(&inner, TlvValue::Identifier), client_id);
    assert_eq!(
        field(&inner, TlvValue::PublicKey),
        kat.bytes("pair_setup/controller_ltpk")
    );
    assert_eq!(
        field(&inner, TlvValue::Signature),
        kat.bytes("pair_setup/m5_signature")
    );

    let credentials = setup
        .handle_m6(&kat.bytes("pair_setup/m6_message"))
        .expect("pyatv's M6 must be accepted");
    assert_eq!(credentials.ltpk, kat.bytes("pair_setup/accessory_ltpk"));
    assert_eq!(credentials.ltsk, seed);
    assert_eq!(
        credentials.atv_id,
        kat.text("pair_setup/accessory_pairing_id").as_bytes()
    );
    assert_eq!(credentials.client_id, client_id);
}

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
