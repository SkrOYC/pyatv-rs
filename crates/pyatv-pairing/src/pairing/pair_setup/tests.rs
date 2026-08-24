//! Unit tests for the pair-setup state machine.
//!
//! Split out of `pair_setup.rs` only to keep both files inside the 500-line module budget in
//! `CLAUDE.md`. This is that module's ordinary `#[cfg(test)] mod tests`, so it still reaches the
//! private fields through `super`.

use super::{PairSetup, PairSetupOptions};
use crate::{
    Error,
    tlv8::{Method, State, Tlv8, TlvValue},
};

#[test]
fn m1_requests_pair_setup_in_state_one() {
    let (_, request) = PairSetup::start(Some(1111));
    let tlv = Tlv8::decode(&request).unwrap();

    assert_eq!(
        tlv.get(TlvValue::Method).map(|value| value[0]),
        Some(Method::PairSetup as u8)
    );
    assert_eq!(
        tlv.get(TlvValue::SeqNo).map(|value| value[0]),
        Some(State::M1 as u8)
    );
}

#[test]
fn m2_without_a_pin_is_refused_before_any_crypto_runs() {
    let (mut setup, _) = PairSetup::start(None);
    let m2 = Tlv8::new()
        .with_byte(TlvValue::SeqNo, State::M2 as u8)
        .with(TlvValue::Salt, vec![0u8; 16])
        .with(TlvValue::PublicKey, vec![1u8; 384])
        .encode();

    assert!(matches!(setup.handle_m2(&m2), Err(Error::MissingPin)));
}

#[test]
fn steps_taken_out_of_order_are_refused() {
    let (mut setup, _) = PairSetup::start_with(
        PairSetupOptions {
            pin: Some(1111),
            ..PairSetupOptions::default()
        },
        [0x11; 32],
        b"client".to_vec(),
    );

    assert!(matches!(setup.handle_m4(&[]), Err(Error::OutOfOrder(_))));
    assert!(matches!(setup.handle_m6(&[]), Err(Error::OutOfOrder(_))));
}

/// A replayed M2 must not restart the SRP exchange. pyatv would happily build a second
/// `SRPClientSession` on the same ephemeral secret and overwrite the first, so a device that
/// re-sends M2 after M3 could steer the controller into signing under a salt of its choosing.
#[test]
fn a_replayed_m2_is_refused() {
    let mut setup = fixed_setup();
    let m2 = Tlv8::new()
        .with_byte(TlvValue::SeqNo, State::M2 as u8)
        .with(TlvValue::Salt, vec![0u8; 16])
        .with(TlvValue::PublicKey, vec![1u8; 384])
        .encode();

    setup.handle_m2(&m2).expect("the first M2 is accepted");
    assert!(matches!(
        setup.handle_m2(&m2),
        Err(Error::OutOfOrder("pair-setup M2 has already been handled"))
    ));
}

/// Likewise for M4: once M5 has gone out, a second M4 must not re-derive the encryption key or
/// re-sign the identity payload.
#[test]
fn a_replayed_m4_is_refused() {
    let mut setup = fixed_setup();
    let m2 = Tlv8::new()
        .with_byte(TlvValue::SeqNo, State::M2 as u8)
        .with(TlvValue::Salt, vec![0u8; 16])
        .with(TlvValue::PublicKey, vec![1u8; 384])
        .encode();
    setup.handle_m2(&m2).expect("M2");

    // The proof has to be the one the client itself derived, since M4 verification is real.
    let proof = expected_device_proof(&setup);
    let m4 = Tlv8::new()
        .with_byte(TlvValue::SeqNo, State::M4 as u8)
        .with(TlvValue::Proof, proof)
        .encode();

    setup.handle_m4(&m4).expect("the first M4 is accepted");
    assert!(matches!(
        setup.handle_m4(&m4),
        Err(Error::OutOfOrder("pair-setup M4 has already been handled"))
    ));
}

/// A `Debug` print must not expose the seed (which becomes `ltsk`), the PIN, or the
/// `Pair-Setup-Encrypt` key.
#[test]
fn debug_redacts_the_long_term_secrets() {
    let mut setup = fixed_setup();
    let m2 = Tlv8::new()
        .with_byte(TlvValue::SeqNo, State::M2 as u8)
        .with(TlvValue::Salt, vec![0u8; 16])
        .with(TlvValue::PublicKey, vec![1u8; 384])
        .encode();
    setup.handle_m2(&m2).expect("M2");

    let rendered = format!("{setup:?}");
    assert!(!rendered.contains(&hex::encode([0x11u8; 32])), "{rendered}");
    assert!(!rendered.contains("1111"), "{rendered}");
    assert!(rendered.contains("<redacted>"));
    assert!(rendered.contains("AwaitingM4"));
}

/// Build a setup whose seed, identifier and PIN are fixed, so assertions can name the bytes.
fn fixed_setup() -> PairSetup {
    PairSetup::start_with(
        PairSetupOptions {
            pin: Some(1111),
            ..PairSetupOptions::default()
        },
        [0x11; 32],
        b"client".to_vec(),
    )
    .0
}

/// The `M2 = H(A | M1 | K)` this client will accept, recomputed the same way it does.
fn expected_device_proof(setup: &PairSetup) -> Vec<u8> {
    use sha2::{Digest, Sha512};

    let srp = setup.srp.as_ref().expect("M2 has been handled");
    let mut hasher = Sha512::new();
    hasher.update(srp.public_key());
    hasher.update(srp.client_proof().expect("a proof exists"));
    hasher.update(srp.session_key().expect("a session key exists"));
    hasher.finalize().to_vec()
}

#[test]
fn a_missing_salt_is_reported_as_a_missing_tlv() {
    let (mut setup, _) = PairSetup::start(Some(1111));
    let m2 = Tlv8::new()
        .with_byte(TlvValue::SeqNo, State::M2 as u8)
        .with(TlvValue::PublicKey, vec![1u8; 384])
        .encode();

    assert!(matches!(
        setup.handle_m2(&m2),
        Err(Error::MissingTlv(TlvValue::Salt))
    ));
}
