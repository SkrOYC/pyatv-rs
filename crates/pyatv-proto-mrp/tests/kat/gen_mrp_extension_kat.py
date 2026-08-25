#!/usr/bin/env python3
"""Generate known-answer vectors for MRP's proto2 extension envelope.

Every byte string in the emitted JSON comes from *pyatv's own code* running on
*pyatv's own dependencies* (``protobuf``): where pyatv has a callable entry
point (``pyatv.protocols.mrp.messages.command`` / ``device_information`` /
``crypto_pairing``, and ``protobuf.extract_inner``) this script calls it rather
than hand-building a message. The vectors therefore pin the Rust extension
extractor against the reference implementation, not against itself.

The two vectors pyatv has no helper for -- ``SetStateMessage`` (a
device->client message) and ``RegisterHIDDeviceMessage`` -- are built field by
field against the vendored ``.proto`` definitions, still through the reference
protobuf runtime.

The second half of the file covers the *outbound message factories* the Rust
``messages`` module ports one for one: the bring-up sequence, every command
shape and the HID event payload. Those vectors are what pin the Rust builders
to pyatv byte for byte, extension envelope included.

Determinism: ``pyatv.protocols.mrp.messages.uuid4`` is replaced with a fixed
queue, because ``messages.create()`` stamps every message with
``str(uuid4()).upper()`` as ``uniqueIdentifier``.

Usage
-----

    /tmp/pyvenv/bin/pip install protobuf
    PYTHONPATH=/path/to/pyatv \\
        /tmp/pyvenv/bin/python gen_mrp_extension_kat.py > mrp_extension_kat.json

Regenerate whenever the vendored ``proto/`` corpus is refreshed from upstream.
"""

import json
import sys
import uuid

import google.protobuf

from pyatv import const
from pyatv.auth.hap_tlv8 import TlvValue
from pyatv.protocols.mrp import messages, protobuf
from pyatv.protocols.mrp.protobuf import GetKeyboardSessionMessage_pb2
from pyatv.settings import InfoSettings

# Fixed UUIDs, consumed in order by the patched uuid4 below. Version-4 shaped so
# that anything validating them still sees a plausible value.
FIXED_UUIDS = [
    uuid.UUID(f"11111111-2222-4333-8444-5555555555{index:02d}") for index in range(64)
]

# Fixed pairing identifier, standing in for the per-installation one pyatv
# generates at first run.
PAIRING_ID = "89B3D2B7-9D62-4A5C-9E48-2C4F2A0B1D33"


def patch_uuid() -> None:
    """Make ``messages.create()`` deterministic."""
    pending = iter(FIXED_UUIDS)
    messages.uuid4 = lambda: next(pending)


def set_state_message():
    """Build a SET_STATE_MESSAGE the way a device would send one."""
    message = messages.create(protobuf.SET_STATE_MESSAGE)
    inner = protobuf.extract_inner(message)
    inner.displayName = "Music"
    inner.displayID = "com.apple.TVMusic"
    inner.playbackState = protobuf.PlaybackState.Playing
    inner.playbackStateTimestamp = 1234.5
    inner.nowPlayingInfo.title = "Never Gonna Give You Up"
    inner.nowPlayingInfo.artist = "Rick Astley"
    inner.nowPlayingInfo.album = "Whenever You Need Somebody"
    inner.nowPlayingInfo.duration = 213.0
    inner.nowPlayingInfo.elapsedTime = 42.0
    inner.playerPath.client.bundleIdentifier = "com.apple.TVMusic"
    inner.playerPath.player.identifier = "MediaRemote-DefaultPlayer"
    return message


def register_hid_device_message():
    """Build a REGISTER_HID_DEVICE_MESSAGE with a virtual touch descriptor."""
    message = messages.create(protobuf.REGISTER_HID_DEVICE_MESSAGE)
    inner = protobuf.extract_inner(message)
    inner.deviceDescriptor.absolute = False
    inner.deviceDescriptor.integratedDisplay = False
    inner.deviceDescriptor.screenSizeWidth = 1000.0
    inner.deviceDescriptor.screenSizeHeight = 1000.0
    return message


def get_keyboard_session_message():
    """A GET_KEYBOARD_SESSION_MESSAGE with its *string* extension populated.

    The only non-message extension in the corpus: ``optional string
    getKeyboardSessionMessage = 29``. pyatv's own helper never sets it, so the
    value here is synthetic -- the point is the wire shape of a scalar
    extension, which is what the Rust extractor has to special-case.
    """
    message = messages.get_keyboard_session()
    message.Extensions[GetKeyboardSessionMessage_pb2.getKeyboardSessionMessage] = (
        "keyboard-session-1"
    )
    return message


def vector(name, message, extension, note):
    """Serialise one message into a JSON-ready vector."""
    return {
        "name": name,
        "note": note,
        "type_name": protobuf.ProtocolMessage.Type.Name(message.type),
        "type": message.type,
        "extension_name": extension.name,
        "extension_number": extension.number,
        "unique_identifier": message.uniqueIdentifier,
        "identifier": message.identifier if message.HasField("identifier") else None,
        "error_code": message.errorCode,
        "protocol_message": message.SerializeToString().hex(),
        "inner": (
            value.SerializeToString().hex()
            if hasattr(value := message.Extensions[extension], "SerializeToString")
            else None
        ),
        "inner_string": value if isinstance(value, str) else None,
    }


def bare_vector(name, message, note):
    """Serialise a message that carries no extension payload."""
    return {
        "name": name,
        "note": note,
        "type_name": protobuf.ProtocolMessage.Type.Name(message.type),
        "type": message.type,
        "extension_name": None,
        "extension_number": None,
        "unique_identifier": message.uniqueIdentifier,
        "identifier": message.identifier if message.HasField("identifier") else None,
        "error_code": message.errorCode,
        "protocol_message": message.SerializeToString().hex(),
        "inner": None,
        "inner_string": None,
    }


def build():
    """Produce every vector."""
    patch_uuid()

    return [
        vector(
            "send_command_play",
            messages.command(protobuf.CommandInfo_pb2.Play),
            protobuf.SendCommandMessage_pb2.sendCommandMessage,
            "messages.command(): the client's play request. Extension 6, "
            "type SEND_COMMAND_MESSAGE (1) -- number and type differ.",
        ),
        vector(
            "send_command_seek",
            messages.seek_to_position(90.0),
            protobuf.SendCommandMessage_pb2.sendCommandMessage,
            "messages.seek_to_position(): same extension carrying a nested "
            "CommandOptions submessage.",
        ),
        vector(
            "set_state",
            set_state_message(),
            protobuf.SetStateMessage_pb2.setStateMessage,
            "Device -> client now-playing update. Extension 9, type "
            "SET_STATE_MESSAGE (4).",
        ),
        vector(
            "device_info",
            messages.device_information(InfoSettings(), PAIRING_ID),
            protobuf.DeviceInfoMessage_pb2.deviceInfoMessage,
            "messages.device_information(): the mandatory first message on a "
            "direct MRP socket. Extension 20, type DEVICE_INFO_MESSAGE (15).",
        ),
        vector(
            "device_info_update",
            messages.device_information(InfoSettings(), PAIRING_ID, update=True),
            protobuf.DeviceInfoMessage_pb2.deviceInfoMessage,
            "The alias case: type DEVICE_INFO_UPDATE_MESSAGE (37) reuses "
            "extension 20 (pyatv REUSED_MESSAGES).",
        ),
        vector(
            "crypto_pairing",
            messages.crypto_pairing(
                {TlvValue.Method: b"\x00", TlvValue.SeqNo: b"\x01"}, is_pairing=True
            ),
            protobuf.CryptoPairingMessage_pb2.cryptoPairingMessage,
            "messages.crypto_pairing(): HAP TLV8 pair-setup M1 in a bytes "
            "field. Extension 39, type CRYPTO_PAIRING_MESSAGE (34).",
        ),
        vector(
            "register_hid_device",
            register_hid_device_message(),
            protobuf.RegisterHIDDeviceMessage_pb2.registerHIDDeviceMessage,
            "Extension 11, type REGISTER_HID_DEVICE_MESSAGE (6) -- the "
            "acronym-casing case in pyatv's generator.",
        ),
        vector(
            "get_keyboard_session_string",
            get_keyboard_session_message(),
            GetKeyboardSessionMessage_pb2.getKeyboardSessionMessage,
            "The corpus' only scalar extension: optional string at field 29.",
        ),
        # --- Outbound factories: the bring-up sequence -------------------
        vector(
            "set_connection_state",
            messages.set_connection_state(),
            protobuf.SetConnectionStateMessage_pb2.setConnectionStateMessage,
            "Third message of MrpProtocol.start(); state=Connected (2), sent "
            "fire-and-forget.",
        ),
        vector(
            "client_updates_config",
            messages.client_updates_config(),
            protobuf.ClientUpdatesConfigMessage_pb2.clientUpdatesConfigMessage,
            "Fourth message of start(), with the no-argument defaults: "
            "nowPlayingUpdates off, everything else on.",
        ),
        bare_vector(
            "get_keyboard_session",
            messages.get_keyboard_session(),
            "Fifth message of start(): a bare envelope with no payload at all.",
        ),
        bare_vector(
            "generic_message",
            messages.create(protobuf.GENERIC_MESSAGE),
            "The heartbeat, and the flush round trip after every HID press.",
        ),
        bare_vector(
            "wake_device",
            messages.wake_device(),
            "Power.turn_on()'s only message. wake_device() is a plain create(), so "
            "the wakeDeviceMessage extension is never touched and field 45 does not "
            "appear on the wire at all.",
        ),
        # --- Outbound factories: HID ------------------------------------
        vector(
            "send_hid_event_select_down",
            messages.send_hid_event(1, 0x89, True),
            protobuf.SendHIDEventMessage_pb2.sendHIDEventMessage,
            "Select pressed. The 60-byte hidEventData literal with "
            "usagePage=1, usage=0x89, down=1 at offset 43.",
        ),
        vector(
            "send_hid_event_select_up",
            messages.send_hid_event(1, 0x89, False),
            protobuf.SendHIDEventMessage_pb2.sendHIDEventMessage,
            "Select released; differs from the press in exactly one byte.",
        ),
        vector(
            "send_hid_event_volume_up_down",
            messages.send_hid_event(12, 0xE9, True),
            protobuf.SendHIDEventMessage_pb2.sendHIDEventMessage,
            "A two-byte usage page, to catch a big-endian mistake that a "
            "single-byte page would hide.",
        ),
        # --- Outbound factories: commands -------------------------------
        vector(
            "send_command_pause",
            messages.command(protobuf.CommandInfo_pb2.Pause),
            protobuf.SendCommandMessage_pb2.sendCommandMessage,
            "A plain command: no options submessage at all.",
        ),
        vector(
            "send_command_next",
            messages.command(protobuf.CommandInfo_pb2.NextTrack),
            protobuf.SendCommandMessage_pb2.sendCommandMessage,
            "NextTrack, whose enum value (5) is not its declaration index.",
        ),
        vector(
            "send_command_skip_forward",
            messages.command(protobuf.CommandInfo_pb2.SkipForward, skipInterval=15),
            protobuf.SendCommandMessage_pb2.sendCommandMessage,
            "_skip_command's default: an int assigned to the float "
            "options.skipInterval field.",
        ),
        vector(
            "repeat_all",
            messages.repeat(const.RepeatState.All),
            protobuf.SendCommandMessage_pb2.sendCommandMessage,
            "ChangeRepeatMode with options.sendOptions zeroed first.",
        ),
        vector(
            "shuffle_songs",
            messages.shuffle(const.ShuffleState.Songs),
            protobuf.SendCommandMessage_pb2.sendCommandMessage,
            "ChangeShuffleMode, also with sendOptions zeroed.",
        ),
        # --- Outbound factories: volume, artwork, output devices --------
        vector(
            "set_volume",
            messages.set_volume("E510C430-B01D-45DF-B558-6EA6F8251069", 0.42),
            protobuf.SetVolumeMessage_pb2.setVolumeMessage,
            "Volume travels as a 0..1 float32, not a percentage.",
        ),
        vector(
            "playback_queue_request",
            messages.playback_queue_request(0),
            protobuf.PlaybackQueueRequestMessage_pb2.playbackQueueRequestMessage,
            "The artwork fetch, with pyatv's default width=-1/height=400.",
        ),
        vector(
            "add_output_devices",
            messages.add_output_devices("DEVICE-A", "DEVICE-B"),
            protobuf.ModifyOutputContextRequestMessage_pb2.modifyOutputContextRequestMessage,
            "Both addingDevices and clusterAwareAddingDevices are populated; "
            "writing only one half-applies the change.",
        ),
        vector(
            "remove_output_devices",
            messages.remove_output_devices("DEVICE-A"),
            protobuf.ModifyOutputContextRequestMessage_pb2.modifyOutputContextRequestMessage,
            "The removing pair.",
        ),
        vector(
            "set_output_devices",
            messages.set_output_devices("DEVICE-A"),
            protobuf.ModifyOutputContextRequestMessage_pb2.modifyOutputContextRequestMessage,
            "The setting pair.",
        ),
    ]


def main():
    """Emit the document on stdout."""
    document = {
        "_comment": (
            "Known-answer vectors for MRP's proto2 extension envelope, generated by "
            "tests/kat/gen_mrp_extension_kat.py against pyatv and its own protobuf "
            "runtime. Byte strings are lowercase hex. Do not edit by hand: regenerate."
        ),
        "_source": {
            "pyatv": "pyatv/protocols/mrp/messages.py, pyatv/protocols/mrp/protobuf/__init__.py",
            "pyatv_commit": "b277a4c8222ecdcbaab8a24e3e713ca44765adb4",
            "protobuf_runtime": google.protobuf.__version__,
            "python": sys.version.split()[0],
        },
        "vectors": build(),
    }
    json.dump(document, sys.stdout, indent=2)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
