#!/usr/bin/env python3
"""Generate cross-implementation known-answer vectors for the HAP pairing stack.

Every value in the emitted JSON is produced by *pyatv's own code* running on
*pyatv's own dependencies* (``srptools`` for SRP6a, ``cryptography`` for
HKDF-SHA512/Ed25519/X25519, ``chacha20poly1305-reuseable`` for the AEAD).
Nothing here re-derives a value by hand: the point of the file is to be an
independent second implementation, so where pyatv has a callable entry point
(``SRPAuthHandler.step1/step2/step3/step4``, ``hkdf_expand``, ``write_tlv``)
this script calls it rather than reimplementing it. The only hand-written parts
are (a) the deterministic *accessory* side, which mirrors
``pyatv/protocols/mrp/server_auth.py`` with the random salt and the random
ephemerals pinned, and (b) the padded-``g`` M1 negative control, which pyatv
never computes because ``srptools`` only ever produces the unpadded form.

Determinism is obtained by pinning every source of randomness:

* ``pyatv.auth.hap_srp.os.urandom`` is replaced with a fixed queue, so
  ``SRPAuthHandler.initialize()`` returns the fixed Ed25519 seed and the fixed
  X25519 ephemeral below.
* ``SRPAuthHandler.pairing_id`` (a ``uuid.uuid4()`` in ``__init__``) is
  overwritten with pyatv's own ``CLIENT_IDENTIFIER`` constant.
* The accessory's SRP salt is fixed instead of coming from
  ``SRPContext.get_user_data_triplet()``.
* The accessory's SRP private ephemeral ``b`` is pinned to ``PRIVATE_KEY``,
  which is what ``pyatv/protocols/mrp/server_auth.py:new_server_session``
  already does (it passes ``keys.auth``).

Note on key collisions: the controller's Ed25519 seed is 32 x 0xAA (the task's
anchor, which is also pyatv's ``PRIVATE_KEY``), so in the *pair-setup* vectors
the controller and the accessory share a long-term keypair. That is harmless
for a KAT -- the two signatures are over different payloads, with different
HKDF salt/info pairs and different identifiers -- and the *pair-verify* vectors
deliberately do not share: they use pyatv's ``CLIENT_CREDENTIALS`` anchor,
whose controller ``ltsk`` (0x80FD8265...) is distinct from the accessory seed.

Usage
-----

    /tmp/pyvenv/bin/pip install srptools cryptography aiohttp zeroconf \
        pydantic requests miniaudio tinytag protobuf chacha20poly1305-reuseable
    PYTHONPATH=/path/to/pyatv \
        /tmp/pyvenv/bin/python crates/pyatv-pairing/tests/kat/gen_hap_srp_kat.py \
        > crates/pyatv-pairing/tests/kat/hap_srp_kat.json

The script is deterministic: re-running it must produce a byte-identical file.
It writes JSON to stdout and progress/assertions to stderr.
"""

from __future__ import annotations

import binascii
import hashlib
import json
import sys
from typing import Any, Dict, List

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from srptools import SRPContext, SRPServerSession, constants
from srptools.utils import hex_from, int_to_bytes

import pyatv.auth.hap_srp as hap_srp
from pyatv.auth.hap_srp import SRPAuthHandler, hkdf_expand
from pyatv.auth.hap_tlv8 import TlvValue, write_tlv
from pyatv.auth.server_auth import (
    CLIENT_IDENTIFIER,
    PIN_CODE,
    PRIVATE_KEY,
    SERVER_IDENTIFIER,
)
from pyatv.support import chacha20

# --------------------------------------------------------------------------
# Pinned inputs
# --------------------------------------------------------------------------

# The controller's Ed25519 seed, which `hap_srp.py:147-149` also reuses verbatim
# as the SRP client ephemeral exponent `a`.
CONTROLLER_SEED = bytes(32 * [0xAA])
# The accessory's SRP private ephemeral `b`; `new_server_session` passes
# `keys.auth`, i.e. the same `PRIVATE_KEY` seed.
ACCESSORY_SRP_PRIVATE = PRIVATE_KEY
# Replaces `SRPContext.generate_salt()`'s 128 random bits.
SRP_SALT = bytes.fromhex("101112131415161718191a1b1c1d1e1f")
# Replaces the controller's `os.urandom(32)` X25519 ephemeral in `initialize()`.
CONTROLLER_X25519_SECRET = bytes(range(0x40, 0x60))
# pyatv's reference accessory reuses its Ed25519 seed as the X25519 scalar and
# never regenerates it (`server_auth.py:generate_keys`).
ACCESSORY_X25519_SECRET = PRIVATE_KEY
# `pyatv/protocols/airplay/ap2_session.py:156` picks this per session; pinned so
# the DataStream salt is reproducible.
DATA_STREAM_SEED = 3141592653589793
# `pyatv/protocols/airplay/auth/hap_transient.py:30`.
TRANSIENT_PIN = 3939

SRP_PRIME = constants.PRIME_3072
SRP_GENERATOR = constants.PRIME_3072_GEN


def hx(data: bytes) -> str:
    return binascii.hexlify(data).decode()


def log(message: str) -> None:
    print(message, file=sys.stderr)


def new_context(password: str | None) -> SRPContext:
    """`hap_srp.py:140-146` / `server_auth.py:50-66`, minus the salt bits."""
    return SRPContext(
        "Pair-Setup",
        password,
        prime=SRP_PRIME,
        generator=SRP_GENERATOR,
        hash_func=hashlib.sha512,
        bits_salt=128,
    )


def fixed_urandom(*values: bytes):
    """A drop-in `os.urandom` that hands out `values` in order."""
    queue = list(values)

    def urandom(count: int) -> bytes:
        assert queue, "fixed_urandom ran out of values"
        value = queue.pop(0)
        assert len(value) == count, f"wanted {count} bytes, pinned {len(value)}"
        return value

    return urandom


class FixedUrandom:
    """Context manager patching the `os` module `hap_srp` resolves at call time."""

    def __init__(self, *values: bytes) -> None:
        self._values = values
        self._saved = None

    def __enter__(self) -> "FixedUrandom":
        self._saved = hap_srp.os.urandom
        hap_srp.os.urandom = fixed_urandom(*self._values)
        return self

    def __exit__(self, *_: Any) -> None:
        hap_srp.os.urandom = self._saved


# --------------------------------------------------------------------------
# SRP: one deterministic pair-setup M1..M4 negotiation
# --------------------------------------------------------------------------


def srp_exchange(pin: int) -> Dict[str, Any]:
    """Drive pyatv's client against a pinned `srptools` server session.

    Returns the vector plus the live `SRPAuthHandler`, so the caller can go on
    to `step3`/`step4` with the same session state.
    """
    salt_hex = hx(SRP_SALT)

    # Accessory: `server_auth.py:new_server_session`, with the random salt and
    # the random `b` pinned. `get_user_data_triplet` is inlined here only
    # because it insists on generating its own salt.
    user_context = new_context(str(pin))
    salt_int = int(salt_hex, 16)
    password_hash = user_context.get_common_password_hash(salt_int)
    verifier_hex = hex_from(user_context.get_common_password_verifier(password_hash))

    server_session = SRPServerSession(
        new_context(None),
        verifier_hex,
        hx(ACCESSORY_SRP_PRIVATE),
    )
    server_public = binascii.unhexlify(server_session.public)
    assert len(server_public) == 384, (
        "the pinned `b` produced a `B` with a leading zero byte; every "
        "implementation renders `B` minimally, but a short `B` makes this "
        "vector unrepresentative -- pick a different `b`"
    )

    # Controller: `SRPAuthHandler.step1`/`step2` verbatim.
    handler = SRPAuthHandler()
    handler.pairing_id = CLIENT_IDENTIFIER.encode()
    with FixedUrandom(CONTROLLER_SEED, CONTROLLER_X25519_SECRET):
        auth_public, verify_public = handler.initialize()
    handler.step1(pin)
    client_public, client_proof = handler.step2(server_public, SRP_SALT)
    assert len(client_public) == 384, "`A` has a leading zero byte; pick another `a`"

    # Accessory checks the controller's M1 and answers with its own M2 proof.
    server_session.process(handler._session.public, salt_hex)
    assert server_session.verify_proof(binascii.hexlify(client_proof)), (
        "the pinned server session rejected pyatv's own M1 -- the two sides "
        "disagree about the SRP profile"
    )
    server_proof = binascii.unhexlify(server_session.key_proof_hash)

    session_key = binascii.unhexlify(handler._session.key)
    assert session_key == binascii.unhexlify(server_session.key), (
        "client and server derived different session keys"
    )

    # Negative control: the RFC 5054 padded-`g` M1 that RustCrypto's
    # `Client::process_reply` computes by default. `srptools` never produces
    # this form, so it is built here from the same context object's primitives.
    context = handler._session._context
    hash_n = context.hash(context._prime)
    hash_g = context.hash(context._gen)
    hash_pad_g = context.hash(context.pad(context._gen))
    n_xor_g = int_to_bytes(hash_n ^ hash_g)
    n_xor_pad_g = int_to_bytes(hash_n ^ hash_pad_g)
    assert len(n_xor_g) == 64, (
        "`H(N) XOR H(g)` has a leading zero byte, so `srptools`' minimal-length "
        "rendering would differ from RustCrypto's fixed 64-byte one"
    )
    assert len(n_xor_g) == len(n_xor_pad_g) == 64
    padded_proof = context.hash(
        hash_n ^ hash_pad_g,
        context.hash(context._user),
        SRP_SALT,
        int(handler._session.public, 16),
        int(server_session.public, 16),
        session_key,
        as_bytes=True,
    )
    assert padded_proof != client_proof, "the padded and unpadded M1 must differ"

    premaster = context.get_client_premaster_secret(
        password_hash,
        int(server_session.public, 16),
        int(handler._session.private, 16),
        context.get_common_secret(
            int(server_session.public, 16), int(handler._session.public, 16)
        ),
    )

    vector = {
        "username": "Pair-Setup",
        "pin": str(pin),
        "client_ephemeral_secret": hx(CONTROLLER_SEED),
        "server_ephemeral_secret": hx(ACCESSORY_SRP_PRIVATE),
        "salt": salt_hex,
        "verifier": verifier_hex,
        "server_public_b": hx(server_public),
        "client_public_a": hx(client_public),
        "premaster_secret_s": hx(int_to_bytes(premaster)),
        "session_key_k": hx(session_key),
        "client_proof_m1": hx(client_proof),
        "server_proof_m2": hx(server_proof),
        "hash_n_xor_hash_g": hx(n_xor_g),
        "hash_n_xor_hash_pad_g": hx(n_xor_pad_g),
        "client_proof_m1_padded_g": hx(padded_proof),
        "m2_message": hx(
            write_tlv(
                {
                    TlvValue.SeqNo: b"\x02",
                    TlvValue.Salt: SRP_SALT,
                    TlvValue.PublicKey: server_public,
                }
            )
        ),
        "m4_message": hx(
            write_tlv({TlvValue.SeqNo: b"\x04", TlvValue.Proof: server_proof})
        ),
    }
    return {
        "vector": vector,
        "handler": handler,
        "session_key": session_key,
        "auth_public": auth_public,
        "verify_public": verify_public,
    }


# --------------------------------------------------------------------------
# Pair-setup M5/M6
# --------------------------------------------------------------------------


def pair_setup_vector(exchange: Dict[str, Any]) -> Dict[str, Any]:
    handler: SRPAuthHandler = exchange["handler"]
    session_key: bytes = exchange["session_key"]
    auth_public: bytes = exchange["auth_public"]

    # `hap_srp.py:step3` computes all of this internally; recomputed here with
    # the same public helper so the individual intermediates can be pinned.
    controller_x = hkdf_expand(
        "Pair-Setup-Controller-Sign-Salt",
        "Pair-Setup-Controller-Sign-Info",
        session_key,
    )
    setup_encrypt_key = hkdf_expand(
        "Pair-Setup-Encrypt-Salt", "Pair-Setup-Encrypt-Info", session_key
    )
    signed_payload = controller_x + handler.pairing_id + auth_public
    signature = Ed25519PrivateKey.from_private_bytes(CONTROLLER_SEED).sign(
        signed_payload
    )
    m5_inner = write_tlv(
        {
            TlvValue.Identifier: handler.pairing_id,
            TlvValue.PublicKey: auth_public,
            TlvValue.Signature: signature,
        }
    )

    m5_encrypted = handler.step3()
    assert m5_encrypted == chacha20.Chacha20Cipher8byteNonce(
        setup_encrypt_key, setup_encrypt_key
    ).encrypt(m5_inner, nonce=b"PS-Msg05"), (
        "step3's own output disagrees with the recomputed intermediates"
    )

    # Accessory side, `mrp/server_auth.py:_m5_setup`.
    accessory_x = hkdf_expand(
        "Pair-Setup-Accessory-Sign-Salt",
        "Pair-Setup-Accessory-Sign-Info",
        session_key,
    )
    accessory_key = Ed25519PrivateKey.from_private_bytes(PRIVATE_KEY)
    accessory_public = accessory_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    accessory_id = SERVER_IDENTIFIER.encode()
    accessory_payload = accessory_x + accessory_id + accessory_public
    accessory_signature = accessory_key.sign(accessory_payload)
    m6_inner = write_tlv(
        {
            TlvValue.Identifier: accessory_id,
            TlvValue.PublicKey: accessory_public,
            TlvValue.Signature: accessory_signature,
        }
    )
    m6_encrypted = chacha20.Chacha20Cipher8byteNonce(
        setup_encrypt_key, setup_encrypt_key
    ).encrypt(m6_inner, nonce=b"PS-Msg06")

    credentials = handler.step4(m6_encrypted)
    assert bytes(credentials.ltpk) == accessory_public
    assert bytes(credentials.ltsk) == CONTROLLER_SEED

    return {
        "controller_seed": hx(CONTROLLER_SEED),
        "controller_ltpk": hx(auth_public),
        "controller_pairing_id": CLIENT_IDENTIFIER,
        "controller_sign_key": hx(controller_x),
        "setup_encrypt_key": hx(setup_encrypt_key),
        "m5_signed_payload": hx(signed_payload),
        "m5_signature": hx(signature),
        "m5_inner_tlv": hx(m5_inner),
        "m5_encrypted": hx(m5_encrypted),
        "accessory_seed": hx(PRIVATE_KEY),
        "accessory_ltpk": hx(accessory_public),
        "accessory_pairing_id": SERVER_IDENTIFIER,
        "accessory_sign_key": hx(accessory_x),
        "m6_signed_payload": hx(accessory_payload),
        "m6_signature": hx(accessory_signature),
        "m6_inner_tlv": hx(m6_inner),
        "m6_encrypted": hx(m6_encrypted),
        "m6_message": hx(
            write_tlv(
                {TlvValue.SeqNo: b"\x06", TlvValue.EncryptedData: m6_encrypted}
            )
        ),
    }


# --------------------------------------------------------------------------
# Pair-verify M1..M4, anchored to pyatv's CLIENT_CREDENTIALS
# --------------------------------------------------------------------------

# `pyatv/auth/server_auth.py:CLIENT_CREDENTIALS`, second field: the controller's
# own long-term Ed25519 seed. Fixed test material with no derivation.
CONTROLLER_LTSK = binascii.unhexlify(
    "80FD8265B0748DA90BC5C5294DABE394D3D47199994AE96AC73EE45C783537B1"
)


def pair_verify_vector() -> Dict[str, Any]:
    handler = SRPAuthHandler()
    handler.pairing_id = CLIENT_IDENTIFIER.encode()
    with FixedUrandom(CONTROLLER_SEED, CONTROLLER_X25519_SECRET):
        _, controller_public = handler.initialize()

    accessory_id = SERVER_IDENTIFIER.encode()
    accessory_key = Ed25519PrivateKey.from_private_bytes(PRIVATE_KEY)
    accessory_ltpk = accessory_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    accessory_x25519 = X25519PrivateKey.from_private_bytes(ACCESSORY_X25519_SECRET)
    accessory_public = accessory_x25519.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    # Accessory side, `mrp/server_auth.py:_m1_verify`.
    shared = accessory_x25519.exchange(X25519PublicKey.from_public_bytes(controller_public))
    verify_encrypt_key = hkdf_expand(
        "Pair-Verify-Encrypt-Salt", "Pair-Verify-Encrypt-Info", shared
    )
    accessory_payload = accessory_public + accessory_id + controller_public
    accessory_signature = accessory_key.sign(accessory_payload)
    m2_inner = write_tlv(
        {
            TlvValue.Identifier: accessory_id,
            TlvValue.Signature: accessory_signature,
        }
    )
    m2_encrypted = chacha20.Chacha20Cipher8byteNonce(
        verify_encrypt_key, verify_encrypt_key
    ).encrypt(m2_inner, nonce=b"PV-Msg02")

    # Controller side, `hap_srp.py:verify1`.
    credentials = hap_srp.HapCredentials(
        accessory_ltpk, CONTROLLER_LTSK, accessory_id, CLIENT_IDENTIFIER.encode()
    )
    m3_encrypted = handler.verify1(credentials, accessory_public, m2_encrypted)

    controller_payload = controller_public + CLIENT_IDENTIFIER.encode() + accessory_public
    controller_signature = Ed25519PrivateKey.from_private_bytes(CONTROLLER_LTSK).sign(
        controller_payload
    )
    m3_inner = write_tlv(
        {
            TlvValue.Identifier: CLIENT_IDENTIFIER.encode(),
            TlvValue.Signature: controller_signature,
        }
    )
    assert m3_encrypted == chacha20.Chacha20Cipher8byteNonce(
        verify_encrypt_key, verify_encrypt_key
    ).encrypt(m3_inner, nonce=b"PV-Msg03"), (
        "verify1's output disagrees with the recomputed M3"
    )

    return {
        "handler": handler,
        "shared_secret": shared,
        "vector": {
            "controller_ltsk": hx(CONTROLLER_LTSK),
            "controller_pairing_id": CLIENT_IDENTIFIER,
            "controller_x25519_secret": hx(CONTROLLER_X25519_SECRET),
            "controller_x25519_public": hx(controller_public),
            "accessory_pairing_id": SERVER_IDENTIFIER,
            "accessory_ltpk": hx(accessory_ltpk),
            "accessory_x25519_secret": hx(ACCESSORY_X25519_SECRET),
            "accessory_x25519_public": hx(accessory_public),
            "shared_secret": hx(shared),
            "verify_encrypt_key": hx(verify_encrypt_key),
            "m2_signed_payload": hx(accessory_payload),
            "m2_signature": hx(accessory_signature),
            "m2_inner_tlv": hx(m2_inner),
            "m2_encrypted": hx(m2_encrypted),
            "m2_message": hx(
                write_tlv(
                    {
                        TlvValue.SeqNo: b"\x02",
                        TlvValue.PublicKey: accessory_public,
                        TlvValue.EncryptedData: m2_encrypted,
                    }
                )
            ),
            "m3_signed_payload": hx(controller_payload),
            "m3_signature": hx(controller_signature),
            "m3_inner_tlv": hx(m3_inner),
            "m3_encrypted": hx(m3_encrypted),
            "m4_message": hx(write_tlv({TlvValue.SeqNo: b"\x04"})),
        },
    }


# --------------------------------------------------------------------------
# Transport keys
# --------------------------------------------------------------------------

# `(channel, salt, output_info, input_info)` exactly as each pyatv call site
# passes them to `SRPAuthHandler.verify2` / `encryption_keys`.
CHANNELS = [
    (
        "mrp",
        "MediaRemote-Salt",
        "MediaRemote-Write-Encryption-Key",
        "MediaRemote-Read-Encryption-Key",
    ),
    ("companion", "", "ClientEncrypt-main", "ServerEncrypt-main"),
    (
        "airplay_control",
        "Control-Salt",
        "Control-Write-Encryption-Key",
        "Control-Read-Encryption-Key",
    ),
    # Reversed on purpose: the receiver opens the event socket
    # (`ap2_session.py:137-148`).
    (
        "airplay_events",
        "Events-Salt",
        "Events-Read-Encryption-Key",
        "Events-Write-Encryption-Key",
    ),
    (
        "airplay_data_stream",
        "DataStream-Salt" + str(DATA_STREAM_SEED),
        "DataStream-Output-Encryption-Key",
        "DataStream-Input-Encryption-Key",
    ),
]


def transport_keys(ikm: bytes) -> List[Dict[str, str]]:
    """`hap_srp.py:verify2` / `hap_transient.py:encryption_keys`."""
    return [
        {
            "channel": channel,
            "salt": salt,
            "output_info": output_info,
            "input_info": input_info,
            "output_key": hx(hkdf_expand(salt, output_info, ikm)),
            "input_key": hx(hkdf_expand(salt, input_info, ikm)),
        }
        for channel, salt, output_info, input_info in CHANNELS
    ]


# --------------------------------------------------------------------------


def main() -> None:
    log("pair-setup SRP exchange (PIN %d)" % PIN_CODE)
    exchange = srp_exchange(PIN_CODE)
    setup = pair_setup_vector(exchange)

    log("pair-verify against CLIENT_CREDENTIALS")
    verify = pair_verify_vector()

    log("transient pair-setup (PIN %d)" % TRANSIENT_PIN)
    transient = srp_exchange(TRANSIENT_PIN)

    document = {
        "_comment": (
            "Cross-implementation known-answer vectors for the HAP pairing "
            "stack, generated by tests/kat/gen_hap_srp_kat.py against pyatv "
            "and its own dependencies (srptools, cryptography, "
            "chacha20poly1305-reuseable). Every field is lowercase hex unless "
            "its name says otherwise. Do not edit by hand: regenerate."
        ),
        "_source": {
            "pyatv": "pyatv/auth/hap_srp.py, pyatv/protocols/mrp/server_auth.py",
            "srp_group": "RFC 5054 3072-bit MODP, generator 5, SHA-512",
        },
        "srp": exchange["vector"],
        "pair_setup": setup,
        "pair_verify": verify["vector"],
        "transport_keys": {
            "pair_verify_ikm": hx(verify["shared_secret"]),
            "channels": transport_keys(verify["shared_secret"]),
        },
        "transient": {
            "pin": str(TRANSIENT_PIN),
            "srp": transient["vector"],
            "transport_keys": {
                "ikm": hx(transient["session_key"]),
                "channels": transport_keys(transient["session_key"]),
            },
        },
    }

    json.dump(document, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    log("done")


if __name__ == "__main__":
    main()
