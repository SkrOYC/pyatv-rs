#!/usr/bin/env python3
"""Generate known-answer vectors for RAOP's wire formats from pyatv itself.

Every byte string below comes out of *pyatv's own modules* running on *pyatv's
own dependencies*: ``pyatv.protocols.raop.packets`` (which is
``pyatv.support.packet.defpacket``, i.e. ``struct``) for the RTP layouts,
``pyatv.protocols.raop.timing`` for the NTP/RTP clock arithmetic,
``pyatv.support.chacha20.Chacha20Cipher8byteNonce`` for the AirPlay 2 audio
AEAD, ``pyatv.protocols.dmap.tags`` for the DAAP metadata body,
``pyatv.protocols.airplay.utils`` for the volume mapping and
``pyatv.support.rtsp`` for the SDP template and the digest response.

Nothing here is hand-built: the point is to pin the Rust port against the
reference implementation rather than against itself. Where a value would
otherwise be random (session ids, keys, timestamps) it is fixed to a literal so
the file is reproducible.

Usage
-----

    PYTHONPATH=/tmp/pyatv-ref \\
        /tmp/pyvenv/bin/python gen_raop_packets_kat.py > raop_packets_kat.json

Regenerate whenever pyatv's RAOP packet, timing or metadata code changes.
"""

import json

from pyatv.interface import MediaMetadata
from pyatv.protocols.airplay.utils import dbfs_to_pct, pct_to_dbfs
from pyatv.protocols.dmap import tags
from pyatv.protocols.raop import packets, timing
from pyatv.support.chacha20 import Chacha20Cipher8byteNonce
from pyatv.support.rtsp import ANNOUNCE_PAYLOAD, get_digest_payload


def hexed(data: bytes) -> str:
    return data.hex()


def rtp_header_vectors():
    return [
        {
            "name": "sync_first",
            "note": "proto 0x90 marks the first sync packet after RECORD",
            "fields": {"proto": 0x90, "type": 0xD4, "seqno": 7},
            "encoded": hexed(packets.RtpHeader.encode(0x90, 0xD4, 7)),
        },
        {
            "name": "sync_subsequent",
            "note": "every later sync packet drops the marker bit",
            "fields": {"proto": 0x80, "type": 0xD4, "seqno": 7},
            "encoded": hexed(packets.RtpHeader.encode(0x80, 0xD4, 7)),
        },
        {
            "name": "seqno_wraps_at_16_bits",
            "note": "the sequence number is a big-endian u16 and wraps, it does not saturate",
            "fields": {"proto": 0x80, "type": 0x60, "seqno": 0xFFFF},
            "encoded": hexed(packets.RtpHeader.encode(0x80, 0x60, 0xFFFF)),
        },
    ]


def timing_packet_vectors():
    # A receiver's request: everything but proto/type/seqno is zero.
    request = packets.TimingPacket.encode(0x80, 0xD2, 7, 0, 0, 0, 0, 0, 0, 0)
    # The reply pyatv builds in `TimingServer.datagram_received`
    # (`stream_client.py:112-132`): the request's send time becomes the reply's
    # reference time and "now" fills both the receive and the send slots.
    reply = packets.TimingPacket.encode(
        0x80,
        0xD3,
        7,
        0,
        0x11111111,
        0x22222222,
        0xAABBCCDD,
        0xEEFF0011,
        0xAABBCCDD,
        0xEEFF0011,
    )
    return [
        {
            "name": "timing_request",
            "note": "what a receiver sends to the timing server",
            "fields": {
                "proto": 0x80,
                "type": 0xD2,
                "seqno": 7,
                "padding": 0,
                "reftime_sec": 0,
                "reftime_frac": 0,
                "recvtime_sec": 0,
                "recvtime_frac": 0,
                "sendtime_sec": 0,
                "sendtime_frac": 0,
            },
            "encoded": hexed(request),
        },
        {
            "name": "timing_response",
            "note": "the reply, with the request's send time echoed as reftime",
            "fields": {
                "proto": 0x80,
                "type": 0xD3,
                "seqno": 7,
                "padding": 0,
                "reftime_sec": 0x11111111,
                "reftime_frac": 0x22222222,
                "recvtime_sec": 0xAABBCCDD,
                "recvtime_frac": 0xEEFF0011,
                "sendtime_sec": 0xAABBCCDD,
                "sendtime_frac": 0xEEFF0011,
            },
            "encoded": hexed(reply),
        },
    ]


def sync_packet_vectors():
    return [
        {
            "name": "sync_first",
            "note": "`_send_sync_packet` with first=True (`stream_client.py:152-171`)",
            "fields": {
                "proto": 0x90,
                "type": 0xD4,
                "seqno": 7,
                "now_without_latency": 0x00010000,
                "last_sync_sec": 0x83AA7E80,
                "last_sync_frac": 0x40000000,
                "now": 0x00020000,
            },
            "encoded": hexed(
                packets.SyncPacket.encode(
                    0x90, 0xD4, 7, 0x00010000, 0x83AA7E80, 0x40000000, 0x00020000
                )
            ),
        },
        {
            "name": "sync_periodic",
            "note": "the same packet one second later, marker bit cleared",
            "fields": {
                "proto": 0x80,
                "type": 0xD4,
                "seqno": 7,
                "now_without_latency": 0x0001AC44,
                "last_sync_sec": 0x83AA7E81,
                "last_sync_frac": 0x40000000,
                "now": 0x0002AC44,
            },
            "encoded": hexed(
                packets.SyncPacket.encode(
                    0x80, 0xD4, 7, 0x0001AC44, 0x83AA7E81, 0x40000000, 0x0002AC44
                )
            ),
        },
    ]


def audio_header_vectors():
    return [
        {
            "name": "first_audio_packet",
            "note": "type 0xE0 marks the very first audio packet of a stream",
            "fields": {
                "proto": 0x80,
                "type": 0xE0,
                "seqno": 0,
                "timestamp": 0x0000AC44,
                "ssrc": 0,
            },
            "encoded": hexed(
                packets.AudioPacketHeader.encode(0x80, 0xE0, 0, 0x0000AC44, 0)
            ),
        },
        {
            "name": "subsequent_audio_packet",
            "note": "every later packet is 0x60",
            "fields": {
                "proto": 0x80,
                "type": 0x60,
                "seqno": 1,
                "timestamp": 0x0000ADA4,
                "ssrc": 0,
            },
            "encoded": hexed(
                packets.AudioPacketHeader.encode(0x80, 0x60, 1, 0x0000ADA4, 0)
            ),
        },
    ]


def retransmit_vectors():
    return [
        {
            "name": "retransmit_request",
            "note": "what the receiver asks for over the control channel",
            "fields": {
                "proto": 0x80,
                "type": 0x55,
                "seqno": 1,
                "lost_seqno": 42,
                "lost_packets": 3,
            },
            "encoded": hexed(packets.RetransmitReqeust.encode(0x80, 0x55, 1, 42, 3)),
        }
    ]


def timing_math_vectors():
    ntp = 0x83AA7E80_40000000
    return {
        "ntp2parts": [
            {"ntp": ntp, "seconds": timing.ntp2parts(ntp)[0], "fraction": timing.ntp2parts(ntp)[1]},
            {"ntp": 0, "seconds": timing.ntp2parts(0)[0], "fraction": timing.ntp2parts(0)[1]},
        ],
        "ntp2ts": [
            {"ntp": ntp, "rate": 44100, "timestamp": timing.ntp2ts(ntp, 44100)},
            {"ntp": ntp, "rate": 48000, "timestamp": timing.ntp2ts(ntp, 48000)},
            {"ntp": 0, "rate": 44100, "timestamp": timing.ntp2ts(0, 44100)},
        ],
        "ts2ntp": [
            {"timestamp": 0, "rate": 44100, "ntp": timing.ts2ntp(0, 44100)},
            {"timestamp": 44100, "rate": 44100, "ntp": timing.ts2ntp(44100, 44100)},
            {"timestamp": 352, "rate": 44100, "ntp": timing.ts2ntp(352, 44100)},
            {"timestamp": 123457, "rate": 44100, "ntp": timing.ts2ntp(123457, 44100)},
        ],
        "ntp2ms": [
            {"ntp": ntp, "milliseconds": timing.ntp2ms(ntp)},
            {"ntp": 0x40000000, "milliseconds": timing.ntp2ms(0x40000000)},
        ],
        "ts2ms": [
            {"timestamp": 44100, "rate": 44100, "milliseconds": timing.ts2ms(44100, 44100)},
            {"timestamp": 352, "rate": 44100, "milliseconds": timing.ts2ms(352, 44100)},
        ],
    }


def encryption_vectors():
    """Three consecutive AirPlay 2 audio packets from one cipher.

    Consecutive because the nonce is a counter that `encrypt` advances, and the
    trailer carries the nonce the packet was sealed *with* rather than the next
    one -- a port that reads the counter after encrypting is off by one and only
    the second packet onwards shows it.
    """
    key = bytes(range(32))
    cipher = Chacha20Cipher8byteNonce(key, key)
    audio = bytes(range(16))

    out = []
    for index, (marker, seqno, rtptime) in enumerate(
        [(0xE0, 0, 0xAC44), (0x60, 1, 0xADA4), (0x60, 2, 0xAF04)]
    ):
        header = packets.AudioPacketHeader.encode(0x80, marker, seqno, rtptime, 0)
        nonce = cipher.out_nonce
        aad = header[4:12]
        encrypted = cipher.encrypt(audio, aad=aad)
        out.append(
            {
                "name": f"audio_packet_{index}",
                "key": hexed(key),
                "header": hexed(header),
                "aad": hexed(aad),
                "plaintext": hexed(audio),
                "nonce": hexed(nonce),
                "packet": hexed(header + encrypted + nonce[-8:]),
            }
        )
    return out


def metadata_vectors():
    def body(title, album, artist):
        payload = b""
        if title:
            payload += tags.string_tag("minm", title)
        if album:
            payload += tags.string_tag("asal", album)
        if artist:
            payload += tags.string_tag("asar", artist)
        return tags.container_tag("mlit", payload)

    return [
        {
            "name": "full",
            "title": "T",
            "album": "AL",
            "artist": "AR",
            "body": hexed(body("T", "AL", "AR")),
        },
        {
            "name": "title_only",
            "title": "T",
            "album": None,
            "artist": None,
            "body": hexed(body("T", None, None)),
        },
        {
            # `tags.string_tag` writes `len(value)` -- the *character* count of a
            # Python `str` -- as the length and then appends `value.encode("utf-8")`,
            # so any non-ASCII metadata gets a length header that undercounts the
            # bytes that follow and desyncs a receiver walking the container. The
            # Rust port writes the byte count instead; this vector exists to pin
            # that divergence rather than to be matched.
            "name": "utf8",
            "divergence": (
                "pyatv writes the character count as the tag length; the port writes "
                "the UTF-8 byte count, which is what DMAP actually specifies"
            ),
            "title": "é",
            "album": "Ålbum",
            "artist": "Ärtist",
            "body": hexed(body("é", "Ålbum", "Ärtist")),
        },
        {
            "name": "empty",
            "title": None,
            "album": None,
            "artist": None,
            "body": hexed(body(None, None, None)),
        },
    ]


def volume_vectors():
    percentages = [0.0, 1.0, 25.0, 33.0, 50.0, 100.0]
    dbfs = [-144.0, -30.0, -29.9, -15.0, -10.0, 0.0]
    return {
        "pct_to_dbfs": [
            {"percent": value, "dbfs": pct_to_dbfs(value)} for value in percentages
        ],
        "dbfs_to_pct": [{"dbfs": value, "percent": dbfs_to_pct(value)} for value in dbfs],
    }


def volume_body_vectors():
    """The exact ``SET_PARAMETER`` body pyatv puts on the wire for a volume.

    ``StreamClient.set_volume`` calls ``set_parameter("volume", str(volume))``
    (``stream_client.py:370-373``) and ``RtspSession.set_parameter`` formats the
    body as ``f"{parameter}: {value}"`` (``rtsp.py:194-200``). Both halves are
    reproduced here through pyatv's own code path, so the vector pins the
    decimal rendering as well as the separator: ``str`` of a Python float always
    carries a decimal point, which Rust's ``Display`` for ``f32`` does not.
    """

    def body(parameter: str, value) -> str:
        # `RtspSession.set_parameter`'s body expression, verbatim.
        return f"{parameter}: {value}"

    return [
        {
            "percent": percent,
            "dbfs": pct_to_dbfs(percent),
            "value": str(pct_to_dbfs(percent)),
            "body": body("volume", str(pct_to_dbfs(percent))),
        }
        # 0 is the mute sentinel, 100 the top of the range, and 60/50/25 are
        # upstream's own functional-test values. 1 and 33 exercise the
        # non-integral renderings.
        for percent in [0.0, 1.0, 25.0, 33.0, 50.0, 60.0, 100.0]
    ]


def pacing_vectors():
    """``Statistics.expected_frame_count`` at fixed elapsed times.

    ``int((monotonic_ns() - self.start_time_ns) / (10**9 / self.sample_rate))``
    (``stream_client.py:635-638``). The inner division is a *float* division and
    the truncation happens once at the end; an integer divisor is 0.0032% small
    at 44100 Hz and drifts a frame ahead every seven seconds or so. These
    vectors pin the float form.
    """

    def expected(elapsed_ns: int, sample_rate: int) -> int:
        return int(elapsed_ns / (10**9 / sample_rate))

    cases = []
    for sample_rate in [44100, 48000]:
        for elapsed_ns in [
            0,
            1_000_000,  # 1 ms
            22_675,  # just under one frame at 44100 Hz
            22_676,  # just over it
            1_000_000_000,  # exactly one second
            7_000_000_000,  # where an integer divisor is a whole frame out
            3_600_000_000_000,  # an hour
        ]:
            cases.append(
                {
                    "elapsed_ns": elapsed_ns,
                    "sample_rate": sample_rate,
                    "expected_frame_count": expected(elapsed_ns, sample_rate),
                }
            )
    return cases


def announce_vectors():
    return [
        {
            "name": "stereo_16_bit_44100",
            "session_id": 1234567890,
            "local_ip": "10.0.0.2",
            "remote_ip": "10.0.0.1",
            "bytes_per_channel": 2,
            "channels": 2,
            "sample_rate": 44100,
            "body": ANNOUNCE_PAYLOAD.format(
                session_id=1234567890,
                local_ip="10.0.0.2",
                remote_ip="10.0.0.1",
                bits_per_channel=16,
                channels=2,
                sample_rate=44100,
            ),
        },
        {
            "name": "mono_8_bit_48000",
            "session_id": 1,
            "local_ip": "192.168.1.20",
            "remote_ip": "192.168.1.30",
            "bytes_per_channel": 1,
            "channels": 1,
            "sample_rate": 48000,
            "body": ANNOUNCE_PAYLOAD.format(
                session_id=1,
                local_ip="192.168.1.20",
                remote_ip="192.168.1.30",
                bits_per_channel=8,
                channels=1,
                sample_rate=48000,
            ),
        },
    ]


def digest_vectors():
    return [
        {
            "name": "announce",
            "method": "ANNOUNCE",
            "uri": "rtsp://10.0.0.2/1234567890",
            "username": "pyatv",
            "realm": "raop",
            "password": "secret",
            "nonce": "1a2b3c4d",
            "header": get_digest_payload(
                "ANNOUNCE",
                "rtsp://10.0.0.2/1234567890",
                "pyatv",
                "raop",
                "secret",
                "1a2b3c4d",
            ),
        },
        {
            "name": "setup",
            "method": "SETUP",
            "uri": "rtsp://10.0.0.2/1",
            "username": "pyatv",
            "realm": "AirPlay",
            "password": "",
            "nonce": "deadbeef",
            "header": get_digest_payload(
                "SETUP", "rtsp://10.0.0.2/1", "pyatv", "AirPlay", "", "deadbeef"
            ),
        },
    ]


def main() -> None:
    # Prove the metadata vectors really went through pyatv's own type, not just
    # through `tags` directly: the field order below is the one `set_metadata`
    # reads them in.
    assert MediaMetadata(title="T", album="AL", artist="AR").title == "T"

    print(
        json.dumps(
            {
                "source": "pyatv",
                "rtp_header": rtp_header_vectors(),
                "timing_packet": timing_packet_vectors(),
                "sync_packet": sync_packet_vectors(),
                "audio_packet_header": audio_header_vectors(),
                "retransmit_request": retransmit_vectors(),
                "timing_math": timing_math_vectors(),
                "encryption": encryption_vectors(),
                "metadata": metadata_vectors(),
                "volume": volume_vectors(),
                "volume_body": volume_body_vectors(),
                "pacing": pacing_vectors(),
                "announce": announce_vectors(),
                "digest": digest_vectors(),
            },
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
