#!/usr/bin/env python3
"""Generate `companion_kat.json` from pyatv itself.

The Rust port must put the same bytes on the wire as pyatv does, and "the same" has to mean
byte-for-byte: OPACK's back-reference table indexes values by first appearance, so two orderings of
one dictionary serialise differently and a device that pattern-matches on the exact payload would
notice. The only way to be sure is to ask pyatv.

Two families of vector live in the output file:

* `opack` — whole request and event envelopes, packed with `pyatv.support.opack.pack`. The
  dictionaries are transcribed from `pyatv/protocols/companion/api.py` in that file's own key
  order, with `_x` appended last exactly as `CompanionProtocol.send_opack` stamps it
  (`protocol.py:181-183`).
* `plist` — the two RTI `NSKeyedArchiver` payloads, from
  `pyatv.protocols.companion.plist_payloads.rti_text_operations`. Those are compared after decoding
  rather than byte for byte: `plistlib` and the Rust `plist` crate both emit valid binary plists but
  make different, equally legal choices about the offset table, so equal bytes is a stricter
  requirement than the format has.

Regenerate with:

    PYTHONPATH=/path/to/pyatv python3 gen_companion_kat.py > companion_kat.json

Recorded against pyatv b277a4c (release 0.18.0).
"""

import json
import sys

from pyatv.support.opack import pack
from pyatv.protocols.companion.plist_payloads.rti_text_operations import (
    get_rti_clear_text_payload,
    get_rti_input_text_payload,
)

# `SystemInfo` with every field pinned, so the vector is reproducible. `_idsID` is the pairing
# client id from the credentials and `_i` the `rp_id` from settings (`api.py:193-210`).
CLIENT_ID = b"4D797FD3-3538-427E-A47B-A32FC6CF3A6A"

SYSTEM_INFO = {
    "_bf": 0,
    "_cf": 512,
    "_clFl": 128,
    "_i": "aabbccddeeff",
    "_idsID": CLIENT_ID,
    "_pubID": "FF:70:79:61:74:76",
    "_sf": 256,
    "_sv": "170.18",
    "model": "iPhone10,6",
    "name": "pyatv",
}

# `MessageType.Request` is 2 and `MessageType.Event` is 1 (`protocol.py:41-47`).
REQUEST = 2
EVENT = 1

OPACK_VECTORS = [
    {
        "name": "_systemInfo",
        "note": "Bring-up identity; `system_info` (api.py:186-211).",
        "value": {"_i": "_systemInfo", "_t": REQUEST, "_c": SYSTEM_INFO, "_x": 12345},
    },
    {
        "name": "_hidC down",
        "note": "Select pressed; `_hid_command(True, HidCommand.Select)` (api.py:305-309).",
        "value": {
            "_i": "_hidC",
            "_t": REQUEST,
            "_c": {"_hBtS": 1, "_hidC": 6},
            "_x": 12346,
        },
    },
    {
        "name": "_hidC up",
        "note": "Select released; note `_hBtS` is 2, not 0 (api.py:308).",
        "value": {
            "_i": "_hidC",
            "_t": REQUEST,
            "_c": {"_hBtS": 2, "_hidC": 6},
            "_x": 12347,
        },
    },
    {
        "name": "_interest",
        "note": "Media-control subscription; `subscribe_event` (api.py:267-271). An Event, not a "
        "Request, so `_t` is 1 and the device never answers.",
        "value": {
            "_i": "_interest",
            "_t": EVENT,
            "_c": {"_regEvents": ["_iMC"]},
            "_x": 12348,
        },
    },
    {
        "name": "_launchApp bundle",
        "note": "Bundle identifiers go under `_bundleID` (api.py:279-289).",
        "value": {
            "_i": "_launchApp",
            "_t": REQUEST,
            "_c": {"_bundleID": "com.netflix.Netflix"},
            "_x": 12349,
        },
    },
    {
        "name": "_launchApp url",
        "note": "Anything with a URL scheme goes under `_urlS` instead (api.py:281-283).",
        "value": {
            "_i": "_launchApp",
            "_t": REQUEST,
            "_c": {"_urlS": "https://tv.apple.com"},
            "_x": 12350,
        },
    },
]

SESSION_UUID = b"0123456789abcdef"

PLIST_VECTORS = [
    {
        "name": "rti clear text",
        "note": "`get_rti_clear_text_payload` (rti_text_operations.py:14-76).",
        "session_uuid": SESSION_UUID.hex(),
        "text": None,
        "payload": get_rti_clear_text_payload(SESSION_UUID).hex(),
    },
    {
        "name": "rti input text",
        "note": "`get_rti_input_text_payload` (rti_text_operations.py:79-147). The object "
        "numbering differs from the clear shape's.",
        "session_uuid": SESSION_UUID.hex(),
        "text": "hello world",
        "payload": get_rti_input_text_payload(SESSION_UUID, "hello world").hex(),
    },
]


def main() -> None:
    document = {
        "source": "pyatv b277a4c (0.18.0)",
        "opack": [
            {
                "name": vector["name"],
                "note": vector["note"],
                "packed": pack(vector["value"]).hex(),
            }
            for vector in OPACK_VECTORS
        ],
        "plist": PLIST_VECTORS,
    }
    json.dump(document, sys.stdout, indent=2)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
