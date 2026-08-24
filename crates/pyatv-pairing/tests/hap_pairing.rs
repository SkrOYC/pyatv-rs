//! End-to-end HAP pairing tests: the client state machines against the reference accessory.
//!
//! Everything here is hermetic — no sockets, no device, no captured traffic. The plan comes from
//! `docs/research/hap-pairing-port-spec.md` §12: check the `CLIENT_CREDENTIALS` anchor, verify
//! against it (both sides' long-term keys are fixed in pyatv's source), then run full pair-setup,
//! then the deliberate-failure paths.
//!
//! The tests that need the accessory are behind the `test-server` feature; run them with
//! `cargo nextest run --workspace --all-features`.

use pyatv_pairing::{AuthenticationType, HapCredentials, srp_hap::ed25519_public_key};

/// pyatv's `CLIENT_CREDENTIALS`, which `docs/research/hap-pairing-port-spec.md` §8 verified is
/// exactly what a controller persists after pairing once against the reference accessory.
const CLIENT_CREDENTIALS: &str = concat!(
    "e734ea6c2b6257de72355e472aa05a4c487e6b463c029ed306df2f01b5636b58:",
    "80fd8265b0748da90bc5c5294dabe394d3d47199994ae96ac73ee45c783537b1:",
    "35443739374644332d333533382d343237452d413437422d413332464336434633413641:",
    "34443739374644332d333533382d343237452d413437422d413332464336434633413641"
);

/// Every field of the anchor has to be independently derivable, or it is not an anchor.
///
/// `ltpk` is the Ed25519 public key of the accessory's 32 × `0xAA` seed; `atv_id` and `client_id`
/// are the two UUID strings as ASCII. Only `ltsk` is arbitrary.
#[test]
fn the_pyatv_credentials_anchor_decomposes_as_documented() {
    let credentials = HapCredentials::parse(CLIENT_CREDENTIALS).unwrap();

    assert_eq!(credentials.authentication_type(), AuthenticationType::Hap);
    assert_eq!(credentials.ltpk, ed25519_public_key(&[0xAA; 32]));
    assert_eq!(
        String::from_utf8(credentials.atv_id.clone()).unwrap(),
        "5D797FD3-3538-427E-A47B-A32FC6CF3A6A"
    );
    assert_eq!(
        String::from_utf8(credentials.client_id.clone()).unwrap(),
        "4D797FD3-3538-427E-A47B-A32FC6CF3A6A"
    );
    assert_eq!(credentials.ltsk.len(), 32);
}

/// The on-disk format has to survive a round trip byte for byte, since users paste these strings
/// between pyatv and this port.
#[test]
fn the_credentials_string_round_trips() {
    let credentials = HapCredentials::parse(CLIENT_CREDENTIALS).unwrap();

    assert_eq!(credentials.to_string(), CLIENT_CREDENTIALS);
    assert_eq!(
        HapCredentials::parse(&credentials.to_string()).unwrap(),
        credentials
    );
}

#[cfg(feature = "test-server")]
mod against_reference_accessory {
    use pyatv_pairing::{
        AuthenticationType, Error, HapCredentials, PairSetup, PairVerify, TransientPairSetup,
        hkdf_derive::transport,
        pairing::PairSetupOptions,
        server::{CLIENT_IDENTIFIER, PIN_CODE, ReferenceAccessory},
        srp_hap::{PAIR_SETUP_M5_NONCE, ed25519_public_key, open},
        tlv8::{ErrorCode, FLAG_TRANSIENT_PAIRING, Tlv8, TlvValue},
    };

    use super::CLIENT_CREDENTIALS;

    /// Run pair-setup to completion against `accessory`, using `pin` on the controller side.
    fn run_pair_setup(
        accessory: &mut ReferenceAccessory,
        pin: u32,
    ) -> Result<HapCredentials, Error> {
        let (mut setup, m1) = PairSetup::start(Some(pin));

        let m2 = accessory.handle_pair_setup(&m1)?;
        let m3 = setup.handle_m2(&m2)?;
        let m4 = accessory.handle_pair_setup(&m3)?;
        let m5 = setup.handle_m4(&m4)?;
        let m6 = accessory.handle_pair_setup(&m5)?;

        setup.handle_m6(&m6)
    }

    /// Drive pair-verify and assert both sides derived matching MRP transport keys.
    ///
    /// The two `encryption_keys` calls take the info strings in opposite orders, which is how pyatv
    /// resolves MRP's ambiguous `Write`/`Read` vocabulary: the accessory swaps them at its
    /// `enable_encryption` call site (`pyatv/protocols/mrp/server_auth.py:173-175`). Getting that
    /// backwards is the failure mode that decrypts garbage in exactly one direction.
    fn run_pair_verify(
        accessory: &mut ReferenceAccessory,
        credentials: HapCredentials,
    ) -> Result<(), Error> {
        let (mut verifier, m1) = PairVerify::start(credentials);
        let m2 = accessory.handle_pair_verify(&m1)?;
        let m3 = verifier.handle_m2(&m2)?;
        let m4 = accessory.handle_pair_verify(&m3)?;
        verifier.handle_m4(&m4)?;

        let controller = verifier.encryption_keys(
            transport::MRP.salt,
            transport::MRP.write_info,
            transport::MRP.read_info,
        )?;
        let device = accessory.encryption_keys(
            transport::MRP.salt,
            transport::MRP.read_info,
            transport::MRP.write_info,
        )?;

        assert_eq!(controller.shared_secret, device.shared_secret);
        assert_eq!(controller.shared_secret.len(), 32);
        assert_eq!(controller.output_key, device.input_key);
        assert_eq!(controller.input_key, device.output_key);
        assert_ne!(controller.output_key, controller.input_key);

        Ok(())
    }

    /// The cheapest known-answer test in the spec: both sides' long-term keys come from pyatv's
    /// source, only the ephemerals are random, and pair-verify must still complete.
    #[test]
    fn pair_verify_succeeds_against_the_pyatv_credentials_anchor() {
        let credentials = HapCredentials::parse(CLIENT_CREDENTIALS).unwrap();
        let seed: [u8; 32] = credentials.ltsk.clone().try_into().unwrap();

        let mut accessory = ReferenceAccessory::new();
        accessory.register_pairing(CLIENT_IDENTIFIER.as_bytes(), &ed25519_public_key(&seed));

        run_pair_verify(&mut accessory, credentials).unwrap();
    }

    #[test]
    fn pair_setup_then_pair_verify_agree_on_transport_keys() {
        let mut accessory = ReferenceAccessory::new();
        let credentials = run_pair_setup(&mut accessory, PIN_CODE).unwrap();

        assert_eq!(credentials.authentication_type(), AuthenticationType::Hap);
        assert_eq!(credentials.ltpk, accessory.public_key());
        assert_eq!(credentials.atv_id, accessory.identifier());
        assert_eq!(credentials.ltsk.len(), 32);
        assert_eq!(accessory.pairings().len(), 1);
        assert_eq!(accessory.pairings()[0].client_id, credentials.client_id);

        run_pair_verify(&mut accessory, credentials).unwrap();
    }

    /// The accessory is the only party that can detect a wrong PIN, because it holds the verifier.
    /// The controller has to surface its `Error` TLV rather than plough on — pyatv's client-side
    /// proof check is a tautology and would not catch this on its own.
    #[test]
    fn a_wrong_pin_is_rejected_with_an_authentication_error() {
        let mut accessory = ReferenceAccessory::new();
        let result = run_pair_setup(&mut accessory, 9999);

        assert!(matches!(
            result,
            Err(Error::HapError {
                code: ErrorCode::Authentication
            })
        ));
        assert!(accessory.pairings().is_empty());
    }

    /// pyatv accepts M6 without looking at the signature (`hap_srp.py:229`, a literal `# TODO`), so
    /// an accessory that decrypts M6 correctly but signs with the wrong key is accepted upstream.
    /// Here it must not be.
    #[test]
    fn an_accessory_that_signs_m6_with_the_wrong_key_is_rejected() {
        let mut accessory = ReferenceAccessory::new();
        accessory.corrupt_signatures(true);

        assert!(matches!(
            run_pair_setup(&mut accessory, PIN_CODE),
            Err(Error::SetupSignature)
        ));
    }

    /// The same fault in pair-verify, where pyatv *does* check — this pins that the port has not
    /// regressed the one signature check it inherited.
    #[test]
    fn an_accessory_that_signs_pair_verify_m2_with_the_wrong_key_is_rejected() {
        let credentials = HapCredentials::parse(CLIENT_CREDENTIALS).unwrap();
        let mut accessory = ReferenceAccessory::new();
        accessory.corrupt_signatures(true);

        let (mut verifier, m1) = PairVerify::start(credentials);
        let m2 = accessory.handle_pair_verify(&m1).unwrap();

        assert!(matches!(
            verifier.handle_m2(&m2),
            Err(Error::VerifySignature)
        ));
    }

    /// Transient pairing keys the transport from the SRP session key, never from an ECDH output.
    #[test]
    fn transient_pairing_derives_keys_from_the_srp_session_key() {
        let mut accessory = ReferenceAccessory::new();
        let (mut setup, m1) = TransientPairSetup::start();

        assert_eq!(
            Tlv8::decode(&m1)
                .unwrap()
                .get(TlvValue::Flags)
                .map(|flags| flags[0]),
            Some(FLAG_TRANSIENT_PAIRING)
        );

        let m2 = accessory.handle_pair_setup(&m1).unwrap();
        let m3 = setup.handle_m2(&m2).unwrap();
        let m4 = accessory.handle_pair_setup(&m3).unwrap();
        setup.handle_m4(&m4).unwrap();

        let controller = setup
            .encryption_keys(
                transport::AIRPLAY_CONTROL.salt,
                transport::AIRPLAY_CONTROL.write_info,
                transport::AIRPLAY_CONTROL.read_info,
            )
            .unwrap();
        let device = accessory
            .encryption_keys(
                transport::AIRPLAY_CONTROL.salt,
                transport::AIRPLAY_CONTROL.read_info,
                transport::AIRPLAY_CONTROL.write_info,
            )
            .unwrap();

        // A 64-byte SHA-512 output, not a 32-byte X25519 secret — that difference is the flow.
        assert_eq!(controller.shared_secret.len(), 64);
        assert_eq!(controller.shared_secret, device.shared_secret);
        assert_eq!(controller.output_key, device.input_key);
        assert_eq!(controller.input_key, device.output_key);
        assert!(accessory.pairings().is_empty());
    }

    /// A corrupted M3 proof makes the accessory answer with an error TLV. pyatv's transient client
    /// never reads that response at all (`hap_transient.py:78-82`); this one must.
    #[test]
    fn transient_pairing_surfaces_a_rejected_proof() {
        let mut accessory = ReferenceAccessory::new();
        let (mut setup, m1) = TransientPairSetup::start();

        let m2 = accessory.handle_pair_setup(&m1).unwrap();
        let m3 = Tlv8::decode(&setup.handle_m2(&m2).unwrap()).unwrap();

        let mut proof = m3.get(TlvValue::Proof).unwrap().to_vec();
        proof[0] ^= 0xFF;
        let tampered = m3.with(TlvValue::Proof, proof).encode();

        let m4 = accessory.handle_pair_setup(&tampered).unwrap();
        assert!(matches!(
            setup.handle_m4(&m4),
            Err(Error::HapError {
                code: ErrorCode::Authentication
            })
        ));
    }

    /// Credentials naming a different accessory must be refused before any signature check.
    #[test]
    fn pair_verify_rejects_an_unexpected_accessory_identifier() {
        let mut credentials = HapCredentials::parse(CLIENT_CREDENTIALS).unwrap();
        credentials.atv_id = b"someone-else".to_vec();

        let mut accessory = ReferenceAccessory::new();
        let (mut verifier, m1) = PairVerify::start(credentials);
        let m2 = accessory.handle_pair_verify(&m1).unwrap();

        assert!(matches!(
            verifier.handle_m2(&m2),
            Err(Error::IdentifierMismatch { .. })
        ));
    }

    /// An accessory that has never seen this controller answers M4 with an error rather than an
    /// acknowledgement, and the controller has to notice. pyatv leaves a `# TODO: check status
    /// code` there and reports success regardless.
    #[test]
    fn pair_verify_reports_an_unknown_pairing() {
        let credentials = HapCredentials::parse(CLIENT_CREDENTIALS).unwrap();
        let mut accessory = ReferenceAccessory::new();

        let (mut verifier, m1) = PairVerify::start(credentials);
        let m2 = accessory.handle_pair_verify(&m1).unwrap();
        let m3 = verifier.handle_m2(&m2).unwrap();
        let m4 = accessory.handle_pair_verify(&m3).unwrap();

        assert!(matches!(
            verifier.handle_m4(&m4),
            Err(Error::HapError { .. })
        ));
    }

    /// Drive pair-setup as far as M5 and hand back the accessory's view of it: the decrypted inner
    /// TLV, plus the still-live machines so the caller can finish the exchange.
    ///
    /// The inner payload is the only place `Name` and `additional_data` are observable — they ride
    /// inside the AEAD envelope — so asserting on them means actually opening it, which the
    /// accessory can do because it derived the same `Pair-Setup-Encrypt` key.
    fn m5_inner_tlv(options: PairSetupOptions) -> (ReferenceAccessory, PairSetup, Vec<u8>, Tlv8) {
        let mut accessory = ReferenceAccessory::new();
        let (mut setup, m1) =
            PairSetup::start_with(options, [0x42; 32], b"fixed-client-id".to_vec());

        let m2 = accessory.handle_pair_setup(&m1).unwrap();
        let m3 = setup.handle_m2(&m2).unwrap();
        let m4 = accessory.handle_pair_setup(&m3).unwrap();
        let m5 = setup.handle_m4(&m4).unwrap();

        let encrypted = Tlv8::decode(&m5)
            .unwrap()
            .get(TlvValue::EncryptedData)
            .expect("M5 carries an EncryptedData entry")
            .clone();
        let plaintext = open(
            &accessory.setup_encrypt_key().unwrap(),
            PAIR_SETUP_M5_NONCE,
            &encrypted,
        )
        .expect("the accessory's own key must open M5");

        (accessory, setup, m5, Tlv8::decode(&plaintext).unwrap())
    }

    /// The optional `Name` TLV and `additional_data` ride inside the encrypted M5 payload;
    /// Companion always sends a name, MRP never does, and nothing in pyatv ever sends extra tags.
    ///
    /// Wire order is load-bearing: pyatv builds the dict as `Identifier, PublicKey, Signature`,
    /// then `Name` if present, then merges `additional_data` last (`hap_srp.py:183-198`), and
    /// `write_tlv` walks an insertion-ordered dict. Some accessories parse positionally, so this
    /// asserts the exact tag sequence rather than just membership.
    #[test]
    fn pair_setup_m5_carries_the_name_and_extra_tags_in_pyatvs_order() {
        let (mut accessory, mut setup, m5_bytes, inner) = m5_inner_tlv(PairSetupOptions {
            pin: Some(PIN_CODE),
            name: Some(b"opack-encoded-name".to_vec()),
            additional_data: vec![(0x1B, vec![0x01])],
        });

        assert_eq!(
            inner.tags().collect::<Vec<_>>(),
            vec![
                TlvValue::Identifier as u8,
                TlvValue::PublicKey as u8,
                TlvValue::Signature as u8,
                TlvValue::Name as u8,
                0x1B,
            ]
        );
        assert_eq!(
            inner.get(TlvValue::Identifier).unwrap()[..],
            b"fixed-client-id"[..]
        );
        assert_eq!(
            inner.get(TlvValue::PublicKey).unwrap()[..],
            ed25519_public_key(&[0x42; 32])[..]
        );
        assert_eq!(inner.get(TlvValue::Signature).unwrap().len(), 64);
        assert_eq!(
            inner.get(TlvValue::Name).unwrap()[..],
            b"opack-encoded-name"[..]
        );
        assert_eq!(inner.get_raw(0x1B).unwrap()[..], [0x01][..]);

        // The accessory accepts all of it: the extra tags are ignored, and the signature it checks
        // is over the same identity the `Identifier` entry names.
        let m6 = accessory.handle_pair_setup(&m5_bytes).unwrap();
        let credentials = setup.handle_m6(&m6).unwrap();
        assert_eq!(credentials.client_id, b"fixed-client-id");
        assert_eq!(credentials.ltsk, vec![0x42; 32]);
        assert_eq!(setup.client_id(), b"fixed-client-id");
        assert_eq!(accessory.pairings().len(), 1);
    }

    /// MRP sends no `Name`, so the inner TLV must be exactly the three mandatory entries.
    #[test]
    fn pair_setup_m5_omits_the_name_when_none_is_given() {
        let (_, _, _, inner) = m5_inner_tlv(PairSetupOptions {
            pin: Some(PIN_CODE),
            ..PairSetupOptions::default()
        });

        assert_eq!(
            inner.tags().collect::<Vec<_>>(),
            vec![
                TlvValue::Identifier as u8,
                TlvValue::PublicKey as u8,
                TlvValue::Signature as u8,
            ]
        );
    }

    /// `additional_data` is merged with `dict.update` **after** the mandatory entries
    /// (`hap_srp.py:197-198`), so a caller that reuses one of their tags overwrites it — and Python
    /// `dict[key] = value` leaves the key where it already was rather than moving it to the end.
    /// No pyatv call site does this, but the parameter exists and the semantic is not obvious, so
    /// it is pinned here.
    ///
    /// The consequence is also pinned: overwriting `Identifier` desynchronises it from the
    /// signature, which is computed over the real `client_id`, and the accessory rejects M5. That
    /// is the correct outcome — this port's reference accessory verifies that signature where
    /// pyatv's does not.
    #[test]
    fn additional_data_overwrites_a_mandatory_tag_in_place() {
        let (mut accessory, mut setup, m5, inner) = m5_inner_tlv(PairSetupOptions {
            pin: Some(PIN_CODE),
            name: None,
            additional_data: vec![(TlvValue::Identifier as u8, b"overwritten".to_vec())],
        });

        // Replaced in place: still first, and there is no second `Identifier` entry.
        assert_eq!(
            inner.tags().collect::<Vec<_>>(),
            vec![
                TlvValue::Identifier as u8,
                TlvValue::PublicKey as u8,
                TlvValue::Signature as u8,
            ]
        );
        assert_eq!(
            inner.get(TlvValue::Identifier).unwrap()[..],
            b"overwritten"[..]
        );

        // The signature still covers `fixed-client-id`, so the accessory refuses the pairing.
        let m6 = accessory.handle_pair_setup(&m5).unwrap();
        assert!(matches!(
            setup.handle_m6(&m6),
            Err(Error::HapError {
                code: ErrorCode::Authentication
            })
        ));
        assert!(accessory.pairings().is_empty());
    }

    /// Pairing twice from the same controller identity must produce the same credentials, which is
    /// what makes the Ed25519 seed the stable identity and the UUID a per-attempt label.
    #[test]
    fn a_second_pairing_with_a_fresh_identity_also_verifies() {
        let mut accessory = ReferenceAccessory::new();
        let first = run_pair_setup(&mut accessory, PIN_CODE).unwrap();
        let second = run_pair_setup(&mut accessory, PIN_CODE).unwrap();

        assert_ne!(first.client_id, second.client_id);
        assert_eq!(first.ltpk, second.ltpk);
        assert_eq!(accessory.pairings().len(), 2);

        run_pair_verify(&mut accessory, first).unwrap();
        run_pair_verify(&mut accessory, second).unwrap();
    }
}
