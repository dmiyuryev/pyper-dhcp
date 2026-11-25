"""Tests for the PyperDHCP packet format, lease store, configuration, server and command line.

Most tests drive the server through fake sockets. Some open real UDP sockets on
127.0.0.1 and send the test process SIGTERM, so the suite assumes Linux. Tests
inspect private state of the lease store and configuration parser on purpose,
and loguru output is switched off because many tests exercise error paths.
"""

# pyright: reportPrivateUsage=false

from __future__ import annotations

import asyncio
from collections.abc import Callable
import contextlib
import errno
import io
import ipaddress
import json
from pathlib import Path
import shutil
import signal
import socket
import stat
import struct
import sys
import tempfile
import time
import tomllib
from typing import ClassVar, cast
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from loguru import logger

logger.remove()

from lease import RENEWAL_SAVE_INTERVAL, Lease, LeaseStore
from protocol import (
    DHCPACK,
    DHCPDECLINE,
    DHCPDISCOVER,
    DHCPINFORM,
    DHCPNAK,
    DHCPOFFER,
    DHCPPacket,
    DHCPPacketError,
    DHCPRELEASE,
    DHCPREQUEST,
    OPTION_DNS,
    OPTION_END,
    OPTION_LEASE_TIME,
    OPTION_MESSAGE_TYPE,
    OPTION_PARAMETER_REQUEST_LIST,
    OPTION_REQUESTED_IP,
    OPTION_ROUTER,
    OPTION_SERVER_IDENTIFIER,
    OPTION_SUBNET_MASK,
    parse_mac,
)
import main
from main import (
    DROP_REPORT_INTERVAL,
    DHCPServer,
    RateLimiter,
    ServerConfig,
    cleanup_leases,
    configure_logging,
    create_socket,
    parse_arguments,
    read_version as main_read_version,
    serve,
)

CLIENT_MAC = "02:00:00:00:00:01"
SERVER_ID = "192.168.1.1"
PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONFIG = PROJECT_ROOT / "config/config.default.toml"
PACKET_INFO_FORMAT = "=I4s4s"
HAS_PACKET_INFO = hasattr(socket, "IP_PKTINFO")


def client_packet(
    message_type: int,
    extra_options: bytes = b"",
    *,
    mac: bytes = b"\x02\0\0\0\0\x01",
    ciaddr: str = "0.0.0.0",
    giaddr: str = "0.0.0.0",
    flags: int = 0x8000,
    hops: int = 0,
    op: int = 1,
) -> bytes:
    """Build a raw client DHCP packet of `message_type` with optional extra options and header fields."""
    fixed = struct.pack(
        "!BBBBIHH4s4s4s4s16s64s128s",
        op, 1, 6, hops, 0x12345678, 0, flags,
        ipaddress.IPv4Address(ciaddr).packed, b"\0" * 4, b"\0" * 4, ipaddress.IPv4Address(giaddr).packed,
        mac + b"\0" * 10, b"\0" * 64, b"\0" * 128,
    )
    return fixed + b"\x63\x82\x53\x63" + bytes((OPTION_MESSAGE_TYPE, 1, message_type)) + extra_options + b"\xff"


def ip_option_bytes(code: int, address: str) -> bytes:
    """Encode a DHCP option carrying a single IPv4 address."""
    return bytes((code, 4)) + ipaddress.IPv4Address(address).packed


class FakeSocket:
    """Socket stand-in without `recvmsg`, so the server sends replies with `sendto`."""

    def __init__(self) -> None:
        """Start with no sent datagrams."""
        self.sent: list[tuple[bytes, tuple[str, int]]] = []

    def sendto(self, data: bytes, destination: tuple[str, int]) -> int:
        """Record a sent datagram and its destination."""
        self.sent.append((data, destination))
        return len(data)


class QueueSocket(FakeSocket):
    """Non-blocking socket stand-in that returns queued datagrams or raises queued exceptions."""

    def __init__(self, incoming: list[bytes | BaseException]) -> None:
        """Queue `incoming` datagrams and exceptions for the server to read."""
        super().__init__()
        self.incoming = incoming

    def _next(self) -> bytes:
        """Return the next queued datagram, raise the next queued exception, or raise `BlockingIOError` when empty."""
        if not self.incoming:
            raise BlockingIOError
        item = self.incoming.pop(0)
        if isinstance(item, BaseException):
            raise item
        return item

    def recvfrom(self, size: int) -> tuple[bytes, tuple[str, int]]:
        """Return the next queued datagram as if it came from a client on port 68."""
        return self._next(), ("0.0.0.0", 68)


class PacketInfoSocket(QueueSocket):
    """Socket stand-in with `recvmsg` and `sendmsg`, so the server takes the `IP_PKTINFO` path."""

    def __init__(
        self,
        incoming: list[bytes | BaseException] | None = None,
        *,
        interface_index: int = 7,
        send_error: OSError | None = None,
    ) -> None:
        """Report `interface_index` for every received datagram, and raise `send_error` from `sendmsg` if given."""
        super().__init__(incoming or [])
        self.interface_index = interface_index
        self.send_error = send_error
        self.sent_with_info: list[tuple[bytes, int, str, tuple[str, int]]] = []

    def recvmsg(
        self, size: int, ancillary_size: int
    ) -> tuple[bytes, list[tuple[int, int, bytes]], int, tuple[str, int]]:
        """Return the next queued datagram with an unrelated and an `IP_PKTINFO` ancillary item."""
        info = struct.pack(PACKET_INFO_FORMAT, self.interface_index, b"\0" * 4, b"\0" * 4)
        ancillary = [(socket.SOL_SOCKET, 0, b"ignored"), (socket.IPPROTO_IP, socket.IP_PKTINFO, info)]
        return self._next(), ancillary, 0, ("0.0.0.0", 68)

    def sendmsg(
        self,
        buffers: list[bytes],
        ancillary: list[tuple[int, int, bytes]],
        flags: int,
        destination: tuple[str, int],
    ) -> int:
        """Record a datagram sent with `IP_PKTINFO`, decoding the interface index and source address."""
        if self.send_error is not None:
            raise self.send_error
        ((level, kind, value),) = ancillary
        if (level, kind) != (socket.IPPROTO_IP, socket.IP_PKTINFO):
            raise OSError(errno.EPERM, "unexpected ancillary data")
        interface_index, spec_dst, _ = struct.unpack(PACKET_INFO_FORMAT, value)
        self.sent_with_info.append((buffers[0], interface_index, socket.inet_ntoa(spec_dst), destination))
        return len(buffers[0])


def build_config(directory: str, **overrides: object) -> ServerConfig:
    """Return a test configuration with a three-address pool, overriding any field with `overrides`."""
    settings: dict[str, object] = {
        "listen_address": "0.0.0.0",
        "listen_port": 6767,
        "server_id": SERVER_ID,
        "subnet_mask": "255.255.255.0",
        "pool_start": "192.168.1.10",
        "pool_end": "192.168.1.12",
        "lease_time": 600,
        "router": "192.168.1.254",
        "dns_servers": ("1.1.1.1", "8.8.8.8"),
        "lease_file": Path(directory) / "leases.json",
        "reservations": {},
    }
    settings.update(overrides)
    return ServerConfig(**settings)  # pyright: ignore[reportArgumentType]


class ServerTestCase(unittest.TestCase):
    """Common fixture: a server backed by a temporary directory and a fake socket."""

    def setUp(self) -> None:
        """Create a temporary lease directory and a server on a `FakeSocket`."""
        self._directory = tempfile.TemporaryDirectory()
        self.addCleanup(self._directory.cleanup)
        self.socket = FakeSocket()
        self.server = DHCPServer(build_config(self._directory.name), self.as_socket())

    def as_socket(self) -> socket.socket:
        """Return the fake socket typed as a real socket for the server constructor."""
        return cast("socket.socket", self.socket)

    def rebuild(self, **overrides: object) -> None:
        """Replace the server with one built from the test configuration plus `overrides`."""
        self.socket = FakeSocket()
        self.server = DHCPServer(build_config(self._directory.name, **overrides), self.as_socket())

    def feed(self, data: bytes, peer: tuple[str, int] = ("0.0.0.0", 68)) -> None:
        """Hand one datagram from `peer` to the server."""
        self.server.handle_datagram(data, peer)

    def use_socket(self, sock: FakeSocket, **overrides: object) -> None:
        """Replace the server with one that uses `sock` and the test configuration plus `overrides`."""
        self.socket = sock
        self.server = DHCPServer(build_config(self._directory.name, **overrides), self.as_socket())

    def last_reply(self) -> tuple[DHCPPacket, tuple[str, int]]:
        """Return the last reply the server sent, parsed, together with its destination."""
        self.assertTrue(self.socket.sent, "server sent no reply")
        data, destination = self.socket.sent[-1]
        return DHCPPacket.from_bytes(data), destination


class DHCPPacketTests(unittest.TestCase):
    """Parsing and building DHCP packets."""
    def test_parse_and_create_reply(self) -> None:
        """A parsed request yields a reply that parses back with the same address and type."""
        request = DHCPPacket.from_bytes(client_packet(DHCPDISCOVER))
        self.assertEqual(request.client_mac, CLIENT_MAC)
        self.assertEqual(request.message_type, DHCPDISCOVER)
        reply = request.reply(message_type=DHCPACK, yiaddr="192.168.1.10", server_ip=SERVER_ID, options={})
        self.assertGreaterEqual(len(reply), 300)
        parsed = DHCPPacket.from_bytes(reply)
        self.assertEqual(parsed.yiaddr, "192.168.1.10")
        self.assertEqual(parsed.message_type, DHCPACK)

    def test_requested_ip(self) -> None:
        """Option 50 is exposed as the requested address."""
        packet = DHCPPacket.from_bytes(client_packet(DHCPREQUEST, ip_option_bytes(OPTION_REQUESTED_IP, "192.168.1.10")))
        self.assertEqual(packet.requested_ip(), "192.168.1.10")

    def test_nak_clears_yiaddr_and_forces_broadcast_flag(self) -> None:
        """A DHCPNAK has `yiaddr` and `siaddr` cleared and the BROADCAST flag set."""
        request = DHCPPacket.from_bytes(client_packet(DHCPREQUEST, flags=0))
        reply = DHCPPacket.from_bytes(
            request.reply(message_type=DHCPNAK, yiaddr="192.168.1.10", server_ip=SERVER_ID, options={})
        )
        self.assertEqual(reply.yiaddr, "0.0.0.0")
        self.assertEqual(reply.siaddr, "0.0.0.0")
        self.assertTrue(reply.broadcast_requested)

    def test_parse_mac_normalises_common_spellings(self) -> None:
        """Common MAC address spellings are normalised to colon-separated lowercase."""
        for value in ("AA-BB-CC-DD-EE-FF", "aabb.ccdd.eeff", "AA:BB:CC:DD:EE:FF", " aabbccddeeff "):
            self.assertEqual(parse_mac(value), "aa:bb:cc:dd:ee:ff")

    def test_parse_mac_rejects_garbage(self) -> None:
        """Values that are not six hexadecimal octets are rejected."""
        for value in ("", "aa:bb:cc", "zz:bb:cc:dd:ee:ff", "aa:bb:cc:dd:ee:ff:00"):
            with self.assertRaises(ValueError):
                parse_mac(value)

    def test_rejects_truncated_options(self) -> None:
        """An option cut off before its length or inside its value is rejected."""
        without_end = client_packet(DHCPDISCOVER)[:-1]
        for tail in (bytes((OPTION_ROUTER,)), bytes((OPTION_ROUTER, 4, 192, 168))):
            with self.subTest(tail=tail), self.assertRaises(DHCPPacketError):
                DHCPPacket.from_bytes(without_end + tail)

    def test_options_may_end_without_end_marker(self) -> None:
        """Options that run to the end of the packet without an END marker are accepted."""
        packet = DHCPPacket.from_bytes(client_packet(DHCPDISCOVER)[:-1])
        self.assertEqual(packet.message_type, DHCPDISCOVER)

    def test_pad_options_are_skipped(self) -> None:
        """PAD bytes between options are ignored."""
        padded = b"\0\0" + ip_option_bytes(OPTION_REQUESTED_IP, "10.0.0.1")
        packet = DHCPPacket.from_bytes(client_packet(DHCPDISCOVER, padded))
        self.assertEqual(packet.requested_ip(), "10.0.0.1")

    def test_rejects_oversized_hardware_address(self) -> None:
        """A hardware address length above 16 is rejected."""
        data = bytearray(client_packet(DHCPDISCOVER))
        data[2] = 17
        with self.assertRaises(DHCPPacketError):
            DHCPPacket.from_bytes(bytes(data))

    def test_rejects_missing_magic_cookie(self) -> None:
        """A packet without the DHCP magic cookie is rejected."""
        data = bytearray(client_packet(DHCPDISCOVER))
        data[236:240] = b"\0\0\0\0"
        with self.assertRaises(DHCPPacketError):
            DHCPPacket.from_bytes(bytes(data))

    def test_reply_rejects_oversized_option(self) -> None:
        """A reply option longer than 255 bytes cannot be encoded."""
        packet = DHCPPacket.from_bytes(client_packet(DHCPDISCOVER))
        with self.assertRaises(ValueError):
            packet.reply(
                message_type=DHCPOFFER, yiaddr="10.0.0.1", server_ip=SERVER_ID, options={OPTION_ROUTER: b"x" * 256}
            )

    def test_reply_keeps_its_own_type_and_server_identifier(self) -> None:
        """Message type and server identifier passed in `options` do not override the reply's own."""
        packet = DHCPPacket.from_bytes(client_packet(DHCPDISCOVER))
        options = {
            OPTION_MESSAGE_TYPE: bytes((DHCPNAK,)),
            OPTION_SERVER_IDENTIFIER: ipaddress.IPv4Address("10.9.9.9").packed,
        }
        reply = DHCPPacket.from_bytes(
            packet.reply(message_type=DHCPOFFER, yiaddr="10.0.0.1", server_ip=SERVER_ID, options=options)
        )
        self.assertEqual(reply.message_type, DHCPOFFER)
        self.assertEqual(reply.server_identifier(), SERVER_ID)
        self.assertNotIn(OPTION_END, reply.options)


class DHCPServerFlowTests(ServerTestCase):
    """End-to-end handling of DISCOVER, REQUEST and INFORM by the server."""
    def test_discover_is_offered_by_broadcast(self) -> None:
        """DISCOVER gets an OFFER of the first pool address, broadcast to port 68."""
        self.feed(client_packet(DHCPDISCOVER))
        reply, destination = self.last_reply()
        self.assertEqual(reply.message_type, DHCPOFFER)
        self.assertEqual(reply.yiaddr, "192.168.1.10")
        self.assertEqual(destination, ("255.255.255.255", 68))

    def test_request_is_acknowledged(self) -> None:
        """REQUEST for the offered address gets an ACK with the lease time."""
        self.feed(client_packet(DHCPDISCOVER))
        self.feed(client_packet(DHCPREQUEST, ip_option_bytes(OPTION_REQUESTED_IP, "192.168.1.10")))
        reply, _ = self.last_reply()
        self.assertEqual(reply.message_type, DHCPACK)
        self.assertEqual(reply.yiaddr, "192.168.1.10")
        self.assertIn(OPTION_LEASE_TIME, reply.options)

    def test_nak_carries_only_the_mandatory_options(self) -> None:
        """A NAK is broadcast and carries no mask, gateway or DNS (RFC 2131, section 4.3.2)."""
        self.feed(client_packet(DHCPREQUEST, ip_option_bytes(OPTION_REQUESTED_IP, "10.0.0.5")))
        reply, destination = self.last_reply()
        self.assertEqual(reply.message_type, DHCPNAK)
        self.assertEqual(set(reply.options), {OPTION_MESSAGE_TYPE, OPTION_SERVER_IDENTIFIER})
        self.assertEqual(destination, ("255.255.255.255", 68))

    def test_renewing_client_is_answered_by_unicast(self) -> None:
        """A renewing client with `ciaddr` set is answered by unicast."""
        self.feed(client_packet(DHCPDISCOVER))
        self.feed(client_packet(DHCPREQUEST, ip_option_bytes(OPTION_REQUESTED_IP, "192.168.1.10")))
        self.feed(client_packet(DHCPREQUEST, ciaddr="192.168.1.10"), peer=("192.168.1.10", 68))
        reply, destination = self.last_reply()
        self.assertEqual(reply.message_type, DHCPACK)
        self.assertEqual(destination, ("192.168.1.10", 68))

    def test_relayed_request_is_answered_to_giaddr(self) -> None:
        """A relayed request is answered to the relay agent on port 67."""
        self.feed(client_packet(DHCPDISCOVER, giaddr="192.168.9.1"), peer=("192.168.9.1", 67))
        _, destination = self.last_reply()
        self.assertEqual(destination, ("192.168.9.1", 67))

    def test_inform_is_answered_without_lease_options(self) -> None:
        """INFORM gets an ACK without an address or lease time, sent to `ciaddr`."""
        self.feed(client_packet(DHCPINFORM, ciaddr="192.168.1.50"), peer=("192.168.1.50", 68))
        reply, destination = self.last_reply()
        self.assertEqual(reply.message_type, DHCPACK)
        self.assertEqual(reply.yiaddr, "0.0.0.0")
        self.assertNotIn(OPTION_LEASE_TIME, reply.options)
        self.assertEqual(destination, ("192.168.1.50", 68))

    def test_parameter_request_list_is_honoured(self) -> None:
        """Only the options the client requested in option 55 are included."""
        requested = bytes((OPTION_PARAMETER_REQUEST_LIST, 2, OPTION_SUBNET_MASK, OPTION_ROUTER))
        self.feed(client_packet(DHCPDISCOVER, requested))
        reply, _ = self.last_reply()
        self.assertIn(OPTION_ROUTER, reply.options)
        self.assertNotIn(OPTION_DNS, reply.options)

    def test_request_addressed_to_another_server_is_ignored(self) -> None:
        """A REQUEST that selects another server gets no reply."""
        options = ip_option_bytes(OPTION_SERVER_IDENTIFIER, "192.168.1.2")
        options += ip_option_bytes(OPTION_REQUESTED_IP, "192.168.1.10")
        self.feed(client_packet(DHCPREQUEST, options))
        self.assertEqual(self.socket.sent, [])

    def test_request_without_any_address_is_ignored(self) -> None:
        """A REQUEST with neither option 50 nor `ciaddr` gets no reply."""
        self.feed(client_packet(DHCPREQUEST))
        self.assertEqual(self.socket.sent, [])

    def test_replies_are_not_sent_to_bootreply_or_relay_loops(self) -> None:
        """BOOTREPLY packets and packets relayed through too many hops are ignored."""
        self.feed(client_packet(DHCPDISCOVER, op=2))
        self.feed(client_packet(DHCPDISCOVER, hops=17))
        self.assertEqual(self.socket.sent, [])

    def test_malformed_packet_is_ignored(self) -> None:
        """Truncated or cookie-less packets get no reply."""
        self.feed(b"\x01\x01\x06\x00")
        self.feed(b"\0" * 300)
        self.assertEqual(self.socket.sent, [])

    def test_reply_without_router_or_dns(self) -> None:
        """Without a router or DNS servers configured, the reply carries only the subnet mask."""
        self.rebuild(router=None, dns_servers=())
        self.feed(client_packet(DHCPDISCOVER))
        reply, _ = self.last_reply()
        self.assertIn(OPTION_SUBNET_MASK, reply.options)
        self.assertNotIn(OPTION_ROUTER, reply.options)
        self.assertNotIn(OPTION_DNS, reply.options)

    def test_non_ethernet_hardware_is_ignored(self) -> None:
        """Packets with a non-Ethernet hardware type are ignored."""
        data = bytearray(client_packet(DHCPDISCOVER))
        data[1] = 6
        self.feed(bytes(data))
        self.assertEqual(self.socket.sent, [])

    def test_exhausted_pool_gets_no_offer(self) -> None:
        """Once every pool address is offered, further clients get no reply."""
        for last_octet in range(1, 5):
            self.feed(client_packet(DHCPDISCOVER, mac=bytes((2, 0, 0, 0, 0, last_octet))))
        offered = [DHCPPacket.from_bytes(data).yiaddr for data, _ in self.socket.sent]
        self.assertEqual(offered, ["192.168.1.10", "192.168.1.11", "192.168.1.12"])

    def test_repeated_discover_gets_the_same_offer(self) -> None:
        """A client that repeats DISCOVER is offered the same address."""
        self.feed(client_packet(DHCPDISCOVER))
        self.feed(client_packet(DHCPDISCOVER))
        offered = [DHCPPacket.from_bytes(data).yiaddr for data, _ in self.socket.sent]
        self.assertEqual(offered, ["192.168.1.10", "192.168.1.10"])

    def test_unknown_message_type_is_ignored(self) -> None:
        """A message type the server does not handle gets no reply."""
        self.feed(client_packet(DHCPOFFER))
        self.assertEqual(self.socket.sent, [])

    def test_unexpected_error_does_not_escape(self) -> None:
        """An unexpected exception while handling a packet is logged, not raised."""
        with mock.patch.object(self.server.leases, "offer", side_effect=RuntimeError("boom")):
            self.feed(client_packet(DHCPDISCOVER))
        self.assertEqual(self.socket.sent, [])

    def test_send_error_is_logged_and_swallowed(self) -> None:
        """A failed send is logged and the offer is still recorded."""
        with mock.patch.object(self.socket, "sendto", side_effect=OSError(errno.ENETUNREACH, "unreachable")):
            self.feed(client_packet(DHCPDISCOVER))
        self.assertIsNotNone(self.server.leases._offers_by_mac.get(CLIENT_MAC))


class DHCPServerReleaseTests(ServerTestCase):
    """Handling of RELEASE and DECLINE by the server."""
    def _lease_first_address(self) -> None:
        """Lease the first pool address to the default client."""
        self.feed(client_packet(DHCPDISCOVER))
        self.feed(client_packet(DHCPREQUEST, ip_option_bytes(OPTION_REQUESTED_IP, "192.168.1.10")))

    def test_release_from_the_lease_owner_frees_the_address(self) -> None:
        """RELEASE sent from the leased address ends the lease."""
        self._lease_first_address()
        self.feed(client_packet(DHCPRELEASE, ciaddr="192.168.1.10"), peer=("192.168.1.10", 68))
        self.assertIsNone(self.server.leases._leases_by_mac.get(CLIENT_MAC))

    def test_release_from_a_foreign_source_is_ignored(self) -> None:
        """RELEASE sent from another address is treated as spoofed and ignored."""
        self._lease_first_address()
        self.feed(client_packet(DHCPRELEASE, ciaddr="192.168.1.10"), peer=("192.168.1.99", 68))
        self.assertIsNotNone(self.server.leases._leases_by_mac.get(CLIENT_MAC))

    def test_release_without_ciaddr_is_ignored(self) -> None:
        """RELEASE without `ciaddr` is ignored."""
        self._lease_first_address()
        self.feed(client_packet(DHCPRELEASE), peer=("192.168.1.10", 68))
        self.assertIsNotNone(self.server.leases._leases_by_mac.get(CLIENT_MAC))

    def test_decline_quarantines_the_address(self) -> None:
        """DECLINE ends the lease and takes the address out of the pool."""
        self._lease_first_address()
        declined = ip_option_bytes(OPTION_REQUESTED_IP, "192.168.1.10")
        declined += ip_option_bytes(OPTION_SERVER_IDENTIFIER, SERVER_ID)
        self.feed(client_packet(DHCPDECLINE, declined))
        self.assertEqual(self.server.leases.offer("02:00:00:00:00:02"), "192.168.1.11")
        self.assertIsNone(self.server.leases._leases_by_mac.get(CLIENT_MAC))

    def test_decline_for_a_foreign_address_is_ignored(self) -> None:
        """DECLINE from a client that does not hold the address is ignored."""
        self._lease_first_address()
        declined = ip_option_bytes(OPTION_REQUESTED_IP, "192.168.1.10")
        self.feed(client_packet(DHCPDECLINE, declined, mac=b"\x02\0\0\0\0\x09"))
        self.assertIsNotNone(self.server.leases._leases_by_mac.get(CLIENT_MAC))

    def test_release_for_another_address_keeps_the_lease(self) -> None:
        """RELEASE for an address the client does not hold keeps its lease."""
        self._lease_first_address()
        self.feed(client_packet(DHCPRELEASE, ciaddr="192.168.1.11"), peer=("192.168.1.11", 68))
        self.assertIsNotNone(self.server.leases._leases_by_mac.get(CLIENT_MAC))

    def test_release_addressed_to_another_server_is_ignored(self) -> None:
        """RELEASE that names another server is ignored."""
        self._lease_first_address()
        options = ip_option_bytes(OPTION_SERVER_IDENTIFIER, "192.168.1.2")
        self.feed(client_packet(DHCPRELEASE, options, ciaddr="192.168.1.10"), peer=("192.168.1.10", 68))
        self.assertIsNotNone(self.server.leases._leases_by_mac.get(CLIENT_MAC))

    def test_relayed_release_is_accepted(self) -> None:
        """A relayed RELEASE is accepted even though it comes from the relay agent."""
        self._lease_first_address()
        self.feed(
            client_packet(DHCPRELEASE, ciaddr="192.168.1.10", giaddr="192.168.9.1"), peer=("192.168.9.1", 67)
        )
        self.assertIsNone(self.server.leases._leases_by_mac.get(CLIENT_MAC))

    def test_decline_addressed_to_another_server_is_ignored(self) -> None:
        """DECLINE that names another server is ignored."""
        self._lease_first_address()
        options = ip_option_bytes(OPTION_SERVER_IDENTIFIER, "192.168.1.2")
        options += ip_option_bytes(OPTION_REQUESTED_IP, "192.168.1.10")
        self.feed(client_packet(DHCPDECLINE, options))
        self.assertIsNotNone(self.server.leases._leases_by_mac.get(CLIENT_MAC))

    def test_decline_without_address_is_ignored(self) -> None:
        """DECLINE with neither option 50 nor `ciaddr` is ignored."""
        self._lease_first_address()
        self.feed(client_packet(DHCPDECLINE))
        self.assertIsNotNone(self.server.leases._leases_by_mac.get(CLIENT_MAC))


class RateLimiterTests(unittest.TestCase):
    """The token bucket rate limiter."""
    def test_disabled_limiter_allows_everything(self) -> None:
        """A rate of 0 disables the limit."""
        limiter = RateLimiter(0)
        self.assertTrue(all(limiter.allow() for _ in range(1000)))

    def test_burst_is_bounded(self) -> None:
        """No more than `burst` datagrams pass at once."""
        limiter = RateLimiter(1.0, burst=3)
        self.assertEqual(sum(limiter.allow() for _ in range(100)), 3)

    def test_tokens_are_replenished_over_time(self) -> None:
        """Tokens come back at `rate` per second, up to the burst size."""
        clock = [100.0]
        with mock.patch("main.time.monotonic", side_effect=lambda: clock[0]):
            limiter = RateLimiter(2.0, burst=1)
            self.assertTrue(limiter.allow())
            self.assertFalse(limiter.allow())
            clock[0] += 0.25
            self.assertFalse(limiter.allow())
            clock[0] += 0.25
            self.assertTrue(limiter.allow())
            clock[0] += 60
            self.assertTrue(limiter.allow())
            self.assertFalse(limiter.allow())

    def test_default_burst_is_twice_the_rate(self) -> None:
        """The default burst is twice the rate, but at least one."""
        self.assertEqual(RateLimiter(5).capacity, 10)
        self.assertEqual(RateLimiter(0.1).capacity, 1)


class LeaseStoreTests(unittest.TestCase):
    """Address allocation and persistence in `LeaseStore`."""
    def setUp(self) -> None:
        """Create a temporary directory for the lease file."""
        self._directory = tempfile.TemporaryDirectory()
        self.addCleanup(self._directory.cleanup)
        self.directory = Path(self._directory.name)

    def store(
        self,
        *,
        start: str = "192.168.1.10",
        end: str = "192.168.1.13",
        reservations: dict[str, str] | None = None,
    ) -> LeaseStore:
        """Return a store for the given pool and reservations, saving to the temporary directory."""
        return LeaseStore(self.directory / "leases.json", start, end, reservations or {})

    def test_offers_addresses_sequentially_without_duplicates(self) -> None:
        """Each new client is offered the next free address."""
        store = self.store()
        clients = ["02:00:00:00:00:01", "02:00:00:00:00:02", "02:00:00:00:00:03"]
        offers = [store.offer(mac) for mac in clients]
        self.assertEqual(offers, ["192.168.1.10", "192.168.1.11", "192.168.1.12"])
        self.assertTrue(store.assign(clients[1], "192.168.1.11", 60))
        self.assertEqual(store.offer("02:00:00:00:00:04"), "192.168.1.13")

    def test_freed_address_is_reused_before_higher_ones(self) -> None:
        """A released address is offered again before higher free addresses."""
        store = self.store()
        for index in range(1, 4):
            mac = f"02:00:00:00:00:0{index}"
            store.offer(mac)
            store.assign(mac, f"192.168.1.{9 + index}", 600)
        store.release("02:00:00:00:00:02", "192.168.1.11")
        self.assertEqual(store.offer("02:00:00:00:00:07"), "192.168.1.11")

    def test_allocation_and_persistence(self) -> None:
        """An assigned lease is exclusive and survives a reload."""
        store = self.store(end="192.168.1.11")
        self.assertEqual(store.offer("02:00:00:00:00:01"), "192.168.1.10")
        self.assertTrue(store.assign("02:00:00:00:00:01", "192.168.1.10", 60))
        self.assertFalse(store.assign("02:00:00:00:00:02", "192.168.1.10", 60))
        reloaded = self.store(end="192.168.1.11")
        reloaded.load()
        self.assertEqual(reloaded.offer("02:00:00:00:00:01"), "192.168.1.10")

    def test_lease_file_is_private(self) -> None:
        """The lease file is created with mode 0600."""
        store = self.store()
        store.assign("02:00:00:00:00:01", "192.168.1.10", 60)
        mode = stat.S_IMODE((self.directory / "leases.json").stat().st_mode)
        self.assertEqual(mode, 0o600)

    def test_reservation_is_excluded_from_dynamic_pool(self) -> None:
        """A reserved address is neither offered nor assigned to other clients."""
        store = self.store(end="192.168.1.11", reservations={"02:00:00:00:00:01": "192.168.1.10"})
        self.assertEqual(store.offer("02:00:00:00:00:02"), "192.168.1.11")
        self.assertFalse(store.assign("02:00:00:00:00:02", "192.168.1.10", 60))

    def test_reserved_address_held_by_another_client_is_not_offered(self) -> None:
        """A reserved address still leased to someone else is not offered, which would only end in a NAK."""
        store = self.store(reservations={"02:00:00:00:00:01": "192.168.1.10"})
        store._put(Lease("192.168.1.10", "02:00:00:00:00:09", time.time() + 600))
        self.assertIsNone(store.offer("02:00:00:00:00:01"))

    def test_load_drops_leases_that_contradict_reservations(self) -> None:
        """A saved lease on an address that is now reserved for another client is dropped."""
        store = self.store()
        store.assign("02:00:00:00:00:09", "192.168.1.10", 600)
        reloaded = self.store(reservations={"02:00:00:00:00:01": "192.168.1.10"})
        reloaded.load()
        self.assertEqual(reloaded.offer("02:00:00:00:00:01"), "192.168.1.10")

    def test_corrupt_lease_file_is_moved_aside(self) -> None:
        """An unparsable lease file is renamed to `.corrupt` and the store starts empty."""
        path = self.directory / "leases.json"
        path.write_text("{ this is not json", encoding="utf-8")
        store = self.store()
        store.load()
        self.assertFalse(path.exists())
        self.assertTrue((self.directory / "leases.json.corrupt").exists())
        self.assertEqual(store.offer("02:00:00:00:00:01"), "192.168.1.10")

    def test_lease_file_with_unexpected_shape_is_moved_aside(self) -> None:
        """A lease file that is not a JSON array is moved aside."""
        path = self.directory / "leases.json"
        path.write_text(json.dumps({"ip": "192.168.1.10"}), encoding="utf-8")
        store = self.store()
        store.load()
        self.assertTrue((self.directory / "leases.json.corrupt").exists())

    def test_lease_file_with_invalid_entries_is_moved_aside(self) -> None:
        """A lease file with a malformed entry is moved aside."""
        valid = {"ip": "192.168.1.10", "mac": "02:00:00:00:00:01", "expires_at": time.time() + 60}
        invalid_entries: list[object] = [
            "not an object",
            {"ip": "192.168.1.10", "mac": "02:00:00:00:00:01"},
            {**valid, "extra": 1},
            {**valid, "ip": 1},
            {**valid, "mac": None},
            {**valid, "expires_at": "soon"},
            {**valid, "expires_at": True},
        ]
        path = self.directory / "leases.json"
        corrupt = self.directory / "leases.json.corrupt"
        for entry in invalid_entries:
            with self.subTest(entry=entry):
                corrupt.unlink(missing_ok=True)
                path.write_text(json.dumps([entry]), encoding="utf-8")
                store = self.store()
                store.load()
                self.assertFalse(path.exists())
                self.assertTrue(corrupt.exists())
                self.assertEqual(store.offer("02:00:00:00:00:01"), "192.168.1.10")

    def test_lease_file_mac_is_normalised_on_load(self) -> None:
        """MAC addresses read from the lease file are lowercased."""
        path = self.directory / "leases.json"
        entry = {"ip": "192.168.1.11", "mac": "02:00:00:00:00:AB", "expires_at": time.time() + 60}
        path.write_text(json.dumps([entry]), encoding="utf-8")
        store = self.store()
        store.load()
        self.assertEqual(store.offer("02:00:00:00:00:ab"), "192.168.1.11")

    def test_expired_and_out_of_pool_entries_are_skipped(self) -> None:
        """Expired leases and leases outside the pool are not loaded."""
        path = self.directory / "leases.json"
        entries = [
            {"ip": "192.168.1.10", "mac": "02:00:00:00:00:01", "expires_at": time.time() - 1},
            {"ip": "10.0.0.5", "mac": "02:00:00:00:00:02", "expires_at": time.time() + 600},
        ]
        path.write_text(json.dumps(entries), encoding="utf-8")
        store = self.store()
        store.load()
        self.assertEqual(store.offer("02:00:00:00:00:03"), "192.168.1.10")

    def test_cleanup_removes_expired_leases(self) -> None:
        """`cleanup()` removes expired leases and frees their addresses."""
        store = self.store(end="192.168.1.11")
        store._put(Lease("192.168.1.10", "02:00:00:00:00:01", time.time() - 1))
        self.assertEqual(store.cleanup(), 1)
        self.assertEqual(store.offer("02:00:00:00:00:02"), "192.168.1.10")

    def test_declined_address_is_not_reused(self) -> None:
        """A declined address is neither offered nor assigned while quarantined."""
        store = self.store(end="192.168.1.11")
        store.offer("02:00:00:00:00:01")
        store.assign("02:00:00:00:00:01", "192.168.1.10", 600)
        self.assertTrue(store.decline("02:00:00:00:00:01", "192.168.1.10"))
        self.assertEqual(store.offer("02:00:00:00:00:02"), "192.168.1.11")
        self.assertFalse(store.assign("02:00:00:00:00:03", "192.168.1.10", 600))

    def test_decline_from_a_stranger_is_rejected(self) -> None:
        """Only the client that was offered an address may decline it."""
        store = self.store()
        store.offer("02:00:00:00:00:01")
        self.assertFalse(store.decline("02:00:00:00:00:09", "192.168.1.10"))

    def test_renewal_is_flushed_on_demand(self) -> None:
        """`flush()` writes a deferred renewal to disk."""
        store = self.store()
        store.assign("02:00:00:00:00:01", "192.168.1.10", 60)
        store.assign("02:00:00:00:00:01", "192.168.1.10", 600)
        store.flush()
        stored = json.loads((self.directory / "leases.json").read_text(encoding="utf-8"))
        self.assertEqual(len(stored), 1)
        self.assertGreater(stored[0]["expires_at"], time.time() + 500)

    def test_release_requires_a_matching_address(self) -> None:
        """A release naming a different address keeps the lease."""
        store = self.store()
        store.assign("02:00:00:00:00:01", "192.168.1.10", 600)
        self.assertFalse(store.release("02:00:00:00:00:01", "192.168.1.11"))
        self.assertTrue(store.release("02:00:00:00:00:01", "192.168.1.10"))

    def write_leases(self, *entries: tuple[str, str]) -> Path:
        """Write active leases for the given `(ip, mac)` pairs to the lease file."""
        path = self.directory / "leases.json"
        expires_at = time.time() + 600
        path.write_text(json.dumps([{"ip": ip, "mac": mac, "expires_at": expires_at} for ip, mac in entries]))
        return path

    def stored_leases(self) -> list[dict[str, object]]:
        """Return the entries currently saved in the lease file."""
        return json.loads((self.directory / "leases.json").read_text(encoding="utf-8"))

    def test_missing_lease_file_starts_empty(self) -> None:
        """Loading without a lease file leaves the store empty and creates no file."""
        store = self.store()
        store.load()
        self.assertFalse((self.directory / "leases.json").exists())
        self.assertEqual(store.offer("02:00:00:00:00:01"), "192.168.1.10")

    def test_load_drops_duplicate_leases(self) -> None:
        """Duplicate leases for one address or MAC address keep only the first entry."""
        self.write_leases(
            ("192.168.1.10", "02:00:00:00:00:01"),
            ("192.168.1.10", "02:00:00:00:00:02"),
            ("192.168.1.11", "02:00:00:00:00:01"),
        )
        store = self.store()
        store.load()
        self.assertEqual(set(store._leases_by_mac), {"02:00:00:00:00:01"})
        self.assertEqual(store._leases_by_mac["02:00:00:00:00:01"].ip, "192.168.1.10")

    def test_load_drops_lease_when_reservation_moved(self) -> None:
        """A saved lease is dropped when the client's reservation now points elsewhere."""
        self.write_leases(("192.168.1.10", "02:00:00:00:00:01"))
        store = self.store(reservations={"02:00:00:00:00:01": "192.168.1.12"})
        store.load()
        self.assertEqual(store._leases_by_mac, {})
        self.assertEqual(store.offer("02:00:00:00:00:01"), "192.168.1.12")

    def test_unmovable_corrupt_file_does_not_stop_loading(self) -> None:
        """If the corrupt file cannot be renamed, the store still starts empty."""
        path = self.directory / "leases.json"
        path.write_text("not json", encoding="utf-8")
        store = self.store()
        with mock.patch.object(Path, "replace", side_effect=OSError(errno.EACCES, "denied")):
            store.load()
        self.assertTrue(path.exists())
        self.assertEqual(store.offer("02:00:00:00:00:01"), "192.168.1.10")

    def test_flush_without_changes_writes_nothing(self) -> None:
        """`flush()` on an unchanged store does not create the lease file."""
        self.store().flush()
        self.assertFalse((self.directory / "leases.json").exists())

    def test_renewal_is_deferred_until_flush(self) -> None:
        """A renewal right after a save is not written immediately."""
        store = self.store()
        store.assign("02:00:00:00:00:01", "192.168.1.10", 60)
        store.assign("02:00:00:00:00:01", "192.168.1.10", 600)
        self.assertLess(cast(float, self.stored_leases()[0]["expires_at"]), time.time() + 500)

    def test_late_renewal_is_saved_immediately(self) -> None:
        """A renewal after `RENEWAL_SAVE_INTERVAL` is written immediately."""
        store = self.store()
        store.assign("02:00:00:00:00:01", "192.168.1.10", 60)
        store._last_save -= RENEWAL_SAVE_INTERVAL
        store.assign("02:00:00:00:00:01", "192.168.1.10", 600)
        self.assertGreater(cast(float, self.stored_leases()[0]["expires_at"]), time.time() + 500)

    def test_moving_to_another_address_frees_the_old_one(self) -> None:
        """A client moving to another address frees its previous one."""
        store = self.store()
        store.assign("02:00:00:00:00:01", "192.168.1.10", 600)
        self.assertTrue(store.assign("02:00:00:00:00:01", "192.168.1.11", 600))
        self.assertEqual(self.stored_leases()[0]["ip"], "192.168.1.11")
        self.assertEqual(store.offer("02:00:00:00:00:02"), "192.168.1.10")

    def test_in_pool_rejects_malformed_addresses(self) -> None:
        """Malformed addresses are outside the pool and cannot be assigned."""
        store = self.store()
        self.assertFalse(store.in_pool("not-an-ip"))
        self.assertFalse(store.assign("02:00:00:00:00:01", "not-an-ip", 600))

    def test_exhausted_pool_offers_nothing(self) -> None:
        """With every address taken, `offer()` returns `None`."""
        store = self.store(end="192.168.1.10")
        self.assertEqual(store.offer("02:00:00:00:00:01"), "192.168.1.10")
        self.assertIsNone(store.offer("02:00:00:00:00:02"))

    def test_existing_lease_is_offered_again(self) -> None:
        """A client with a lease is offered its leased address."""
        store = self.store()
        store.assign("02:00:00:00:00:01", "192.168.1.12", 600)
        self.assertEqual(store.offer("02:00:00:00:00:01"), "192.168.1.12")

    def test_reserved_client_cannot_take_another_address(self) -> None:
        """A client with a reservation may only be assigned its reserved address."""
        store = self.store(reservations={"02:00:00:00:00:01": "192.168.1.12"})
        self.assertFalse(store.assign("02:00:00:00:00:01", "192.168.1.10", 600))
        self.assertTrue(store.assign("02:00:00:00:00:01", "192.168.1.12", 600))

    def test_address_out_of_pool_is_not_assigned(self) -> None:
        """An address outside the pool cannot be assigned."""
        self.assertFalse(self.store().assign("02:00:00:00:00:01", "192.168.1.200", 600))

    def test_address_offered_to_another_client_is_not_assigned(self) -> None:
        """An address offered to one client cannot be assigned to another."""
        store = self.store()
        self.assertEqual(store.offer("02:00:00:00:00:01"), "192.168.1.10")
        self.assertFalse(store.assign("02:00:00:00:00:02", "192.168.1.10", 600))

    def test_reserved_address_in_quarantine_is_not_offered(self) -> None:
        """A quarantined reserved address is not offered, even to its owner."""
        store = self.store(reservations={"02:00:00:00:00:01": "192.168.1.12"})
        self.assertEqual(store.offer("02:00:00:00:00:01"), "192.168.1.12")
        self.assertTrue(store.decline("02:00:00:00:00:01", "192.168.1.12"))
        self.assertIsNone(store.offer("02:00:00:00:00:01"))

    def test_declining_an_offer_withdraws_it(self) -> None:
        """Declining an offered address withdraws the offer and quarantines the address."""
        store = self.store()
        self.assertEqual(store.offer("02:00:00:00:00:01"), "192.168.1.10")
        self.assertTrue(store.decline("02:00:00:00:00:01", "192.168.1.10"))
        self.assertEqual(store._offers_by_mac, {})
        self.assertEqual(store.offer("02:00:00:00:00:01"), "192.168.1.11")

    def test_expired_offer_frees_the_address(self) -> None:
        """An expired offer is removed and its address can be offered again."""
        store = self.store()
        store.offer("02:00:00:00:00:01")
        store._offers_by_mac["02:00:00:00:00:01"].expires_at = time.time() - 1
        self.assertEqual(store.cleanup(), 1)
        self.assertEqual(store.offer("02:00:00:00:00:02"), "192.168.1.10")

    def test_quarantine_expires(self) -> None:
        """An address returns to the pool once its quarantine ends."""
        store = self.store()
        store.offer("02:00:00:00:00:01")
        self.assertTrue(store.decline("02:00:00:00:00:01", "192.168.1.10", quarantine=-1))
        self.assertEqual(store.cleanup(), 1)
        self.assertEqual(store.offer("02:00:00:00:00:02"), "192.168.1.10")


class ConfigTests(unittest.TestCase):
    """Loading, merging and validating `ServerConfig`."""
    def config(self, **overrides: object) -> ServerConfig:
        """Return the test configuration with `overrides`, without validating it."""
        return build_config(tempfile.gettempdir(), **overrides)

    def test_reads_global_settings(self) -> None:
        """The shipped default file sets the logging and cleanup options."""
        config = ServerConfig.from_toml(Path(__file__).resolve().parents[1] / "config/config.default.toml")
        self.assertEqual(config.log_level, "INFO")
        self.assertEqual(config.log_format, "%m/%d/%Y %H:%M:%S")
        self.assertEqual(config.cache_clean_interval, 60)

    def test_merges_local_override(self) -> None:
        """A local file overrides single keys inside tables and adds reservations."""
        base: dict[str, object] = {
            "log_level": "INFO",
            "server": {"server_id": "192.168.1.1", "pool_start": "192.168.1.10"},
            "reservations": {"02:00:00:00:00:01": "192.168.1.10"},
        }
        override: dict[str, object] = {
            "log_level": "DEBUG",
            "server": {"pool_start": "192.168.1.20"},
            "reservations": {"02:00:00:00:00:02": "192.168.1.11"},
        }
        merged = ServerConfig._merge_toml(base, override)
        self.assertEqual(merged["log_level"], "DEBUG")
        self.assertEqual(merged["server"], {"server_id": "192.168.1.1", "pool_start": "192.168.1.20"})
        self.assertEqual(
            merged["reservations"],
            {"02:00:00:00:00:01": "192.168.1.10", "02:00:00:00:00:02": "192.168.1.11"},
        )

    def test_reservation_macs_are_normalised(self) -> None:
        """Reservation MAC addresses are normalised."""
        raw: dict[str, object] = {
            "server": {
                "server_id": "192.168.1.1", "subnet_mask": "255.255.255.0",
                "pool_start": "192.168.1.10", "pool_end": "192.168.1.20",
            },
            "reservations": {"AA-BB-CC-DD-EE-FF": "192.168.1.15"},
        }
        config = ServerConfig._from_raw(raw, Path(tempfile.gettempdir()) / "config.toml")
        self.assertEqual(config.reservations, {"aa:bb:cc:dd:ee:ff": "192.168.1.15"})

    def test_rejects_invalid_reservation_mac(self) -> None:
        """A reservation with an invalid MAC address is rejected."""
        raw: dict[str, object] = {
            "server": {
                "server_id": "192.168.1.1", "subnet_mask": "255.255.255.0",
                "pool_start": "192.168.1.10", "pool_end": "192.168.1.20",
            },
            "reservations": {"not-a-mac": "192.168.1.15"},
        }
        with self.assertRaises(ValueError):
            ServerConfig._from_raw(raw, Path(tempfile.gettempdir()) / "config.toml")

    def test_rejects_pool_outside_subnet(self) -> None:
        """A pool outside the subnet is rejected."""
        with self.assertRaises(ValueError):
            self.config(pool_start="192.168.2.2", pool_end="192.168.2.3").validate()

    def test_rejects_pool_covering_network_or_broadcast(self) -> None:
        """A pool that includes the network or broadcast address is rejected."""
        with self.assertRaises(ValueError):
            self.config(pool_start="192.168.1.0", pool_end="192.168.1.20", router=None).validate()
        with self.assertRaises(ValueError):
            self.config(pool_start="192.168.1.200", pool_end="192.168.1.255", router=None).validate()

    def test_rejects_pool_covering_server_or_router(self) -> None:
        """A pool that includes the server or router address is rejected."""
        with self.assertRaises(ValueError):
            self.config(pool_start="192.168.1.1", pool_end="192.168.1.20", router=None).validate()
        with self.assertRaises(ValueError):
            self.config(pool_start="192.168.1.10", pool_end="192.168.1.20", router="192.168.1.15").validate()

    def test_rejects_duplicate_reservation_addresses(self) -> None:
        """Two reservations for the same address are rejected."""
        reservations = {"02:00:00:00:00:01": "192.168.1.10", "02:00:00:00:00:02": "192.168.1.10"}
        with self.assertRaises(ValueError):
            self.config(reservations=reservations).validate()

    def test_rejects_unusable_lease_time(self) -> None:
        """Lease times outside 1 to 2**32 - 1 are rejected."""
        for lease_time in (0, -1, 2**32):
            with self.assertRaises(ValueError):
                self.config(lease_time=lease_time).validate()

    def test_rejects_option_overflowing_dns_list(self) -> None:
        """More DNS servers than fit into one option are rejected."""
        with self.assertRaises(ValueError):
            self.config(dns_servers=tuple(f"10.0.0.{index}" for index in range(1, 66))).validate()

    def test_rejects_log_format_with_markup(self) -> None:
        """A log time format containing loguru markup characters is rejected."""
        for log_format in ("%Y {message}", "</green>%Y"):
            with self.assertRaises(ValueError):
                self.config(log_format=log_format).validate()

    def test_rejects_invalid_scalar_settings(self) -> None:
        """Out-of-range ports, intervals, rate limits and logging settings are rejected."""
        invalid: list[dict[str, object]] = [
            {"listen_port": 0},
            {"listen_port": 65536},
            {"log_level": "VERBOSE"},
            {"log_format": ""},
            {"cache_clean_interval": 0},
            {"max_packets_per_second": -1},
        ]
        for overrides in invalid:
            with self.subTest(**overrides), self.assertRaises(ValueError):
                self.config(**overrides).validate()

    def test_rejects_malformed_addresses(self) -> None:
        """Invalid IPv4 addresses and subnet masks are rejected."""
        invalid: list[dict[str, object]] = [
            {"listen_address": "0.0.0.300"},
            {"dns_servers": ("1.1.1.1", "dns.example")},
            {"subnet_mask": "255.0.255.0"},
            {"server_id": "server"},
        ]
        for overrides in invalid:
            with self.subTest(**overrides), self.assertRaises(ValueError):
                self.config(**overrides).validate()

    def test_rejects_reservation_outside_pool(self) -> None:
        """A reservation outside the pool is rejected."""
        with self.assertRaises(ValueError):
            self.config(reservations={"02:00:00:00:00:01": "192.168.1.100"}).validate()

    def test_rejects_unordered_pool(self) -> None:
        """A pool whose start is above its end is rejected."""
        with self.assertRaises(ValueError):
            self.config(pool_start="192.168.1.20", pool_end="192.168.1.10").validate()

    def test_allows_point_to_point_subnet(self) -> None:
        """A /31 subnet may use both of its addresses."""
        self.config(
            server_id="10.0.0.0", subnet_mask="255.255.255.254", pool_start="10.0.0.1", pool_end="10.0.0.1", router=None
        ).validate()


class RawConfigTests(unittest.TestCase):
    """Parsing the TOML structure: value types and required keys."""

    SERVER: ClassVar[dict[str, object]] = {
        "server_id": "192.168.1.1",
        "subnet_mask": "255.255.255.0",
        "pool_start": "192.168.1.10",
        "pool_end": "192.168.1.20",
    }

    def from_raw(self, raw: dict[str, object]) -> ServerConfig:
        """Build a configuration from parsed TOML as if it came from a file in the temporary directory."""
        return ServerConfig._from_raw(raw, Path(tempfile.gettempdir()) / "config.toml")

    def test_minimal_config_gets_defaults(self) -> None:
        """Optional settings get their defaults, and the log level is uppercased."""
        config = self.from_raw({"server": dict(self.SERVER), "log_level": "debug"})
        self.assertEqual(config.listen_port, 67)
        self.assertEqual(config.lease_time, 86400)
        self.assertIsNone(config.router)
        self.assertEqual(config.dns_servers, ())
        self.assertEqual(config.log_level, "DEBUG")
        self.assertEqual(config.lease_file, Path(tempfile.gettempdir()).resolve() / "leases.json")

    def test_rejects_missing_required_options(self) -> None:
        """A missing required `[server]` option is reported by name."""
        server = dict(self.SERVER)
        del server["pool_end"]
        with self.assertRaisesRegex(ValueError, "pool_end"):
            self.from_raw({"server": server})

    def test_rejects_non_table_sections(self) -> None:
        """`[server]` and `[reservations]` must be tables."""
        invalid: list[dict[str, object]] = [
            {"server": "oops"},
            {"server": dict(self.SERVER), "reservations": ["02:00:00:00:00:01"]},
        ]
        for raw in invalid:
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                self.from_raw(raw)

    def test_rejects_non_integer_options(self) -> None:
        """Strings, booleans and floats are rejected where an integer is expected."""
        for value in ("600", True, 1.5):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.from_raw({"server": {**self.SERVER, "lease_time": value}})

    def test_rejects_non_array_dns_servers(self) -> None:
        """`dns_servers` must be an array."""
        with self.assertRaises(ValueError):
            self.from_raw({"server": {**self.SERVER, "dns_servers": "1.1.1.1"}})

    def test_rejects_reservation_defined_twice(self) -> None:
        """Two spellings of the same MAC address are reported as a duplicate reservation."""
        reservations = {"AA-BB-CC-DD-EE-FF": "192.168.1.15", "aa:bb:cc:dd:ee:ff": "192.168.1.16"}
        with self.assertRaisesRegex(ValueError, "more than once"):
            self.from_raw({"server": dict(self.SERVER), "reservations": reservations})

    def test_local_file_overrides_defaults(self) -> None:
        """`from_files()` merges a local file over the shipped defaults."""
        with tempfile.TemporaryDirectory() as directory:
            local = Path(directory) / "config.toml"
            local.write_text('log_level = "DEBUG"\n[server]\nlease_time = 3600\n', encoding="utf-8")
            config = ServerConfig.from_files(DEFAULT_CONFIG, local)
        self.assertEqual(config.log_level, "DEBUG")
        self.assertEqual(config.lease_time, 3600)
        self.assertEqual(config.server_id, "192.168.50.1")

    def test_accepts_the_shipped_defaults(self) -> None:
        """The shipped configuration, with the local file if present, is valid."""
        ServerConfig.from_files(
            Path(__file__).resolve().parents[1] / "config/config.default.toml",
            Path(__file__).resolve().parents[1] / "config/config.toml",
        )


@unittest.skipUnless(HAS_PACKET_INFO, "IP_PKTINFO is Linux-specific")
class PacketInfoTests(ServerTestCase):
    """Replies leave through the interface the request arrived on."""

    def test_reply_is_pinned_to_the_incoming_interface(self) -> None:
        """The reply is sent with `IP_PKTINFO` naming the incoming interface and `server_id`."""
        sock = PacketInfoSocket()
        self.use_socket(sock)
        self.server.handle_datagram(client_packet(DHCPDISCOVER), ("0.0.0.0", 68), interface_index=3)
        self.assertEqual(sock.sent, [])
        ((data, interface_index, spec_dst, destination),) = sock.sent_with_info
        self.assertEqual(DHCPPacket.from_bytes(data).message_type, DHCPOFFER)
        self.assertEqual((interface_index, spec_dst, destination), (3, SERVER_ID, ("255.255.255.255", 68)))

    def test_falls_back_to_sendto_when_interface_rejects_server_id(self) -> None:
        """If the interface rejects `server_id`, the reply is sent with `sendto`."""
        for code in (errno.EINVAL, errno.ENODEV, errno.ENETUNREACH):
            with self.subTest(errno=errno.errorcode[code]):
                sock = PacketInfoSocket(send_error=OSError(code, "rejected"))
                self.use_socket(sock)
                self.server.handle_datagram(client_packet(DHCPDISCOVER), ("0.0.0.0", 68), interface_index=3)
                self.assertEqual(len(sock.sent), 1)

    def test_other_send_errors_are_not_retried(self) -> None:
        """Other `sendmsg` errors are logged without a retry."""
        sock = PacketInfoSocket(send_error=OSError(errno.EPERM, "denied"))
        self.use_socket(sock)
        self.server.handle_datagram(client_packet(DHCPDISCOVER), ("0.0.0.0", 68), interface_index=3)
        self.assertEqual(sock.sent, [])

    def test_unknown_interface_uses_sendto(self) -> None:
        """Without an interface index the reply is sent with `sendto`."""
        sock = PacketInfoSocket()
        self.use_socket(sock)
        self.server.handle_datagram(client_packet(DHCPDISCOVER), ("0.0.0.0", 68))
        self.assertEqual(len(sock.sent), 1)
        self.assertEqual(sock.sent_with_info, [])

    def test_receive_extracts_the_interface_index(self) -> None:
        """The interface index from received ancillary data is used for the reply."""
        sock = PacketInfoSocket([client_packet(DHCPDISCOVER)], interface_index=9)
        self.use_socket(sock)
        self.server.receive_datagrams()
        self.assertEqual([entry[1] for entry in sock.sent_with_info], [9])

    def test_interface_index_ignores_unrelated_ancillary_data(self) -> None:
        """Short or unrelated ancillary items yield no interface index."""
        short = (socket.IPPROTO_IP, socket.IP_PKTINFO, b"\0" * 4)
        unrelated = (socket.SOL_SOCKET, socket.IP_PKTINFO, struct.pack(PACKET_INFO_FORMAT, 5, b"\0" * 4, b"\0" * 4))
        self.assertIsNone(self.server._interface_index([short, unrelated]))


class ReceiveDatagramsTests(ServerTestCase):
    """Reading datagrams from the socket."""
    def test_reads_until_the_socket_is_drained(self) -> None:
        """All waiting datagrams are read and answered."""
        sock = QueueSocket([client_packet(DHCPDISCOVER), client_packet(DHCPDISCOVER, mac=b"\x02\0\0\0\0\x02")])
        self.use_socket(sock)
        self.server.receive_datagrams()
        self.assertEqual(len(sock.sent), 2)
        self.assertEqual(sock.incoming, [])

    def test_interrupted_read_is_retried(self) -> None:
        """A read interrupted by a signal is retried."""
        sock = QueueSocket([InterruptedError(), client_packet(DHCPDISCOVER)])
        self.use_socket(sock)
        self.server.receive_datagrams()
        self.assertEqual(len(sock.sent), 1)

    def test_socket_error_stops_the_read(self) -> None:
        """A socket error ends the call and leaves later datagrams queued."""
        packet = client_packet(DHCPDISCOVER)
        sock = QueueSocket([OSError(errno.ECONNREFUSED, "refused"), packet])
        self.use_socket(sock)
        self.server.receive_datagrams()
        self.assertEqual(sock.sent, [])
        self.assertEqual(sock.incoming, [packet])

    def test_one_call_reads_a_bounded_batch(self) -> None:
        """One call reads at most `MAX_DATAGRAMS_PER_READ` datagrams."""
        packet = client_packet(DHCPINFORM, ciaddr="192.168.1.50")
        sock = QueueSocket([packet] * (main.MAX_DATAGRAMS_PER_READ + 5))
        self.use_socket(sock, max_packets_per_second=0)
        self.server.receive_datagrams()
        self.assertEqual(len(sock.sent), main.MAX_DATAGRAMS_PER_READ)
        self.assertEqual(len(sock.incoming), 5)

    def test_rate_limit_drops_excess_packets(self) -> None:
        """Datagrams over the rate limit are dropped and counted."""
        packet = client_packet(DHCPINFORM, ciaddr="192.168.1.50")
        sock = QueueSocket([packet] * 10)
        self.use_socket(sock, max_packets_per_second=1)
        self.server.receive_datagrams()
        self.assertEqual(len(sock.sent), 2)
        self.assertEqual(self.server._dropped, 8)

    def test_drop_counter_is_reset_after_report(self) -> None:
        """The drop counter restarts after the dropped packets are reported."""
        sock = QueueSocket([client_packet(DHCPINFORM, ciaddr="192.168.1.50")] * 4)
        self.use_socket(sock, max_packets_per_second=1)
        self.server._dropped_reported -= DROP_REPORT_INTERVAL
        self.server.receive_datagrams()
        self.assertEqual(self.server._dropped, 1)


class FakeLeases:
    """Lease store stand-in that returns or raises preset cleanup results and stops the loop after the last one."""
    def __init__(self, stop_event: asyncio.Event, results: list[int | OSError]) -> None:
        """Return or raise `results` in order and set `stop_event` after the last one."""
        self.stop_event = stop_event
        self.results = results
        self.calls = 0

    def cleanup(self) -> int:
        """Count the call and return or raise the next preset result."""
        self.calls += 1
        result = self.results.pop(0)
        if not self.results:
            self.stop_event.set()
        if isinstance(result, OSError):
            raise result
        return result


class CleanupLeasesTests(unittest.IsolatedAsyncioTestCase):
    """The periodic lease cleanup task."""
    async def test_runs_cleanup_until_stopped(self) -> None:
        """Cleanup keeps running after a save error until the stop event is set."""
        stop_event = asyncio.Event()
        leases = FakeLeases(stop_event, [0, 2, OSError(errno.ENOSPC, "disk full"), 1])
        await asyncio.wait_for(cleanup_leases(cast(LeaseStore, leases), 0, stop_event), timeout=5)
        self.assertEqual(leases.calls, 4)

    async def test_stops_immediately_when_already_stopped(self) -> None:
        """No cleanup runs if the server is already stopping."""
        stop_event = asyncio.Event()
        stop_event.set()
        leases = FakeLeases(stop_event, [0])
        await cleanup_leases(cast(LeaseStore, leases), 0, stop_event)
        self.assertEqual(leases.calls, 0)


def free_udp_port() -> int:
    """Return a UDP port on 127.0.0.1 that is free at the moment of the call."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


class CreateSocketTests(unittest.TestCase):
    """Creating the listening socket."""
    def test_socket_is_bound_and_non_blocking(self) -> None:
        """The socket is bound, non-blocking and has broadcast, address reuse and packet info enabled."""
        port = free_udp_port()
        with tempfile.TemporaryDirectory() as directory:
            sock = create_socket(build_config(directory, listen_address="127.0.0.1", listen_port=port))
        with sock:
            self.assertEqual(sock.getsockname(), ("127.0.0.1", port))
            self.assertFalse(sock.getblocking())
            self.assertTrue(sock.getsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST))
            self.assertTrue(sock.getsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR))
            if HAS_PACKET_INFO:
                self.assertTrue(sock.getsockopt(socket.IPPROTO_IP, socket.IP_PKTINFO))

    def test_socket_is_closed_when_bind_fails(self) -> None:
        """The socket is closed when binding fails; 192.0.2.1 (TEST-NET-1) is not a local address."""
        created: list[socket.socket] = []
        original = socket.socket

        def tracking_socket(*args: int) -> socket.socket:
            """Create a real socket and remember it."""
            sock = original(*args)
            created.append(sock)
            return sock

        with tempfile.TemporaryDirectory() as directory:
            config = build_config(directory, listen_address="192.0.2.1", listen_port=free_udp_port())
            with mock.patch("main.socket.socket", side_effect=tracking_socket), self.assertRaises(OSError):
                create_socket(config)
        self.assertEqual(len(created), 1)
        self.assertEqual(created[0].fileno(), -1)


class RecordingServer(DHCPServer):
    """`DHCPServer` that remembers its instances so that tests can inspect the server `serve()` created."""
    instances: ClassVar[list[DHCPServer]] = []

    def __init__(self, config: ServerConfig, sock: socket.socket) -> None:
        """Create the server and record it in `instances`."""
        super().__init__(config, sock)
        RecordingServer.instances.append(self)


class ServeTests(unittest.IsolatedAsyncioTestCase):
    """The full `serve()` lifecycle on a loopback socket."""

    def setUp(self) -> None:
        """Prepare a loopback configuration on a free port and record the server `serve()` creates."""
        self._directory = tempfile.TemporaryDirectory()
        self.addCleanup(self._directory.cleanup)
        self.directory = Path(self._directory.name)
        self.port = free_udp_port()
        self.config = build_config(
            self._directory.name,
            listen_address="127.0.0.1",
            listen_port=self.port,
            lease_file=self.directory / "db" / "leases.json",
            cache_clean_interval=3600,
        )
        RecordingServer.instances = []
        patcher = mock.patch("main.DHCPServer", RecordingServer)
        patcher.start()
        self.addCleanup(patcher.stop)

    async def started_server(self) -> tuple[asyncio.Task[None], DHCPServer]:
        """Start `serve()` and wait until it has created the server and installed its signal handlers."""
        task = asyncio.create_task(serve(self.config, version="test"))
        for _ in range(200):
            if RecordingServer.instances and signal.getsignal(signal.SIGTERM) is not signal.SIG_DFL:
                return task, RecordingServer.instances[0]
            await asyncio.sleep(0.01)
        task.cancel()
        self.fail("serve() did not start")

    async def wait_for(self, condition: Callable[[], bool], message: str) -> None:
        """Wait up to two seconds for `condition` to become true, failing with `message` otherwise."""
        for _ in range(200):
            if condition():
                return
            await asyncio.sleep(0.01)
        self.fail(message)

    async def test_handles_datagrams_and_stops_on_sigterm(self) -> None:
        """The server loads leases, answers a real datagram, and stops cleanly on SIGTERM."""
        stale = {"ip": "192.168.1.11", "mac": "02:00:00:00:00:07", "expires_at": time.time() + 600}
        self.config.lease_file.parent.mkdir()
        self.config.lease_file.write_text(json.dumps([stale]), encoding="utf-8")
        task, server = await self.started_server()
        self.assertIn("02:00:00:00:00:07", server.leases._leases_by_mac)

        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.sendto(client_packet(DHCPDISCOVER), ("127.0.0.1", self.port))
        await self.wait_for(lambda: CLIENT_MAC in server.leases._offers_by_mac, "DISCOVER was not processed")
        self.assertEqual(server.leases._offers_by_mac[CLIENT_MAC].ip, "192.168.1.10")

        signal.raise_signal(signal.SIGTERM)
        await asyncio.wait_for(task, timeout=5)
        self.assertIs(signal.getsignal(signal.SIGTERM), signal.SIG_DFL)
        self.assertEqual(server.socket.fileno(), -1)

    async def test_cancellation_flushes_deferred_renewals(self) -> None:
        """Cancelling `serve()` writes deferred renewals and closes the socket."""
        task, server = await self.started_server()
        server.leases.assign(CLIENT_MAC, "192.168.1.10", 60)
        server.leases.assign(CLIENT_MAC, "192.168.1.10", 6000)
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        stored = json.loads(self.config.lease_file.read_text(encoding="utf-8"))
        self.assertGreater(stored[0]["expires_at"], time.time() + 5000)
        self.assertEqual(server.socket.fileno(), -1)

    async def test_flush_error_on_shutdown_is_logged(self) -> None:
        """A save error during shutdown is logged and does not stop the shutdown."""
        task, server = await self.started_server()
        with mock.patch.object(server.leases, "flush", side_effect=OSError(errno.ENOSPC, "disk full")) as flush:
            signal.raise_signal(signal.SIGTERM)
            await asyncio.wait_for(task, timeout=5)
        flush.assert_called_once_with()

    async def test_bind_error_is_raised(self) -> None:
        """A busy port makes `serve()` fail before any server is created."""
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as busy:
            busy.bind(("127.0.0.1", 0))
            config = build_config(
                self._directory.name, listen_address="127.0.0.1", listen_port=busy.getsockname()[1]
            )
            with self.assertRaises(OSError):
                await serve(config, version="test")
        self.assertEqual(RecordingServer.instances, [])


class LoggingTests(unittest.TestCase):
    """Log output configuration."""
    def setUp(self) -> None:
        """Capture standard error and remove the log handler afterwards."""
        self.addCleanup(logger.remove)
        self.stderr = io.StringIO()
        patcher = mock.patch("main.sys.stderr", self.stderr)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_respects_level_and_time_format(self) -> None:
        """Messages below the level are hidden, and lines use the configured time format."""
        configure_logging(level="WARNING", time_format="%Y")
        main.LOG.info("hidden")
        main.LOG.warning("visible")
        lines = self.stderr.getvalue().splitlines()
        self.assertEqual(len(lines), 1)
        self.assertRegex(lines[0], r"^\d{4} \| WARNING  \| dhcp    \| visible$")

    def test_component_defaults_to_dhcp(self) -> None:
        """Messages logged without a component are labelled `dhcp`."""
        configure_logging(level="INFO", time_format="%Y")
        logger.info("plain")
        self.assertIn("| dhcp    | plain", self.stderr.getvalue())


class VersionTests(unittest.TestCase):
    """The `VERSION` file as the only source of the application version."""
    def test_version_file_is_the_single_source(self) -> None:
        """The version exists only in `VERSION`, not in `pyproject.toml` or the default configuration."""
        version = main_read_version()
        self.assertRegex(version, r"^\d+\.\d+\.\d+$")
        self.assertEqual(main.VERSION_PATH, PROJECT_ROOT / "VERSION")
        pyproject = tomllib.loads((PROJECT_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        self.assertNotIn("version", pyproject["project"])
        self.assertIn("version", pyproject["project"]["dynamic"])
        self.assertNotIn("version", tomllib.loads(DEFAULT_CONFIG.read_text(encoding="utf-8")))

    def test_surrounding_whitespace_is_stripped(self) -> None:
        """Whitespace around the version is ignored."""
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "VERSION"
            path.write_text("  2.0.1  \n", encoding="utf-8")
            self.assertEqual(main_read_version(path), "2.0.1")


class CommandLineTests(unittest.TestCase):
    """The `main()` command-line entry point."""
    def setUp(self) -> None:
        """Copy the shipped configuration to a temporary directory and capture standard error."""
        self._directory = tempfile.TemporaryDirectory()
        self.addCleanup(self._directory.cleanup)
        self.directory = Path(self._directory.name)
        self.default_config = self.directory / "config.default.toml"
        shutil.copy(DEFAULT_CONFIG, self.default_config)
        self.local_config = self.directory / "config.toml"
        self.addCleanup(logger.remove)
        self.stderr = io.StringIO()
        patcher = mock.patch("main.sys.stderr", self.stderr)
        patcher.start()
        self.addCleanup(patcher.stop)

    @staticmethod
    def patched_runtime(run_error: BaseException | None = None) -> contextlib.ExitStack:
        """Replace `serve()` and `asyncio.run()` so that `main()` does not start a real server."""
        stack = contextlib.ExitStack()
        stack.enter_context(mock.patch("main.serve", new_callable=mock.MagicMock))
        stack.enter_context(mock.patch("main.asyncio.run", side_effect=run_error))
        return stack

    def run_main(self, *arguments: str) -> str:
        """Run `main()` with the temporary configuration files and `arguments`, returning standard output."""
        stdout = io.StringIO()
        argv = ["--default-config", str(self.default_config), "--config", str(self.local_config), *arguments]
        with contextlib.redirect_stdout(stdout):
            main.main(argv)
        return stdout.getvalue()

    def test_parse_arguments_defaults(self) -> None:
        """Without arguments, the default configuration paths are used and no flag is set."""
        arguments = parse_arguments([])
        self.assertEqual(arguments.default_config, main.DEFAULT_CONFIG_PATH)
        self.assertEqual(arguments.config, main.LOCAL_CONFIG_PATH)
        self.assertFalse(arguments.check_config)
        self.assertFalse(arguments.version)

    def test_parse_arguments_flags(self) -> None:
        """All options and flags are parsed."""
        arguments = parse_arguments(["--config", "/etc/dhcp.toml", "--check-config", "--version"])
        self.assertEqual(arguments.config, Path("/etc/dhcp.toml"))
        self.assertTrue(arguments.check_config)
        self.assertTrue(arguments.version)

    def use_version_file(self, content: str | None) -> Path:
        """Make `main()` read the version from a temporary `VERSION` file.

        The file gets `content`, or is left missing if `content` is `None`.
        """
        path = self.directory / "VERSION"
        if content is not None:
            path.write_text(content, encoding="utf-8")
        patcher = mock.patch("main.read_version", side_effect=lambda: main_read_version(path))
        patcher.start()
        self.addCleanup(patcher.stop)
        return path

    def test_version_is_printed_from_version_file(self) -> None:
        """`--version` prints the content of `VERSION` without starting the server."""
        self.use_version_file("9.9.9\n")
        with mock.patch("main.serve", new_callable=mock.MagicMock) as serve_mock:
            self.assertEqual(self.run_main("--version"), "9.9.9\n")
        serve_mock.assert_not_called()

    def test_version_does_not_need_a_valid_config(self) -> None:
        """`--version` works even if the configuration is invalid."""
        self.use_version_file("9.9.9\n")
        self.local_config.write_text("[server]\nlease_time = 0\n", encoding="utf-8")
        self.assertEqual(self.run_main("--version"), "9.9.9\n")

    def test_version_key_in_config_is_ignored(self) -> None:
        """A `version` key in the configuration does not change the printed version."""
        self.use_version_file("9.9.9\n")
        self.local_config.write_text('version = "0.0.1"\n', encoding="utf-8")
        self.assertEqual(self.run_main("--version"), "9.9.9\n")

    def test_unreadable_version_file_exits_with_code_2(self) -> None:
        """A missing, empty or multi-line `VERSION` file exits with code 2."""
        for content in (None, "", "  \n", "1.0\n2.0\n"):
            with self.subTest(content=content):
                path = self.use_version_file(content)
                with self.assertRaises(SystemExit) as raised:
                    self.run_main("--version")
                self.assertEqual(raised.exception.code, 2)
                self.assertIn("Could not determine the application version", self.stderr.getvalue())
                path.unlink(missing_ok=True)

    def test_check_config_reports_success(self) -> None:
        """`--check-config` reports a valid configuration without starting the server."""
        with mock.patch("main.serve", new_callable=mock.MagicMock) as serve_mock:
            self.run_main("--check-config")
        serve_mock.assert_not_called()
        self.assertIn("Configuration is valid", self.stderr.getvalue())

    def test_invalid_config_exits_with_code_2(self) -> None:
        """An invalid configuration exits with code 2."""
        self.local_config.write_text("[server]\nlease_time = 0\n", encoding="utf-8")
        with self.assertRaises(SystemExit) as raised:
            self.run_main("--check-config")
        self.assertEqual(raised.exception.code, 2)
        self.assertIn("Could not load configuration", self.stderr.getvalue())

    def test_missing_default_config_exits_with_code_2(self) -> None:
        """A missing base configuration file exits with code 2."""
        self.default_config.unlink()
        with self.assertRaises(SystemExit) as raised:
            self.run_main()
        self.assertEqual(raised.exception.code, 2)

    def test_runs_the_server_with_loaded_config(self) -> None:
        """Without flags, `main()` runs `serve()` with the loaded configuration and version."""
        with self.patched_runtime():
            self.run_main()
            serve_mock = cast(mock.MagicMock, main.serve)
            run_mock = cast(mock.MagicMock, main.asyncio.run)
            (config,), _ = serve_mock.call_args
            run_mock.assert_called_once_with(serve_mock.return_value)
            self.assertEqual(serve_mock.call_args.kwargs, {"version": main_read_version()})
        self.assertEqual(config.server_id, "192.168.50.1")

    def test_startup_error_exits_with_code_2(self) -> None:
        """An error while starting the server exits with code 2."""
        error = OSError(errno.EACCES, "permission denied")
        with self.patched_runtime(error), self.assertRaises(SystemExit) as raised:
            self.run_main()
        self.assertEqual(raised.exception.code, 2)
        self.assertIn("Could not start DHCP server", self.stderr.getvalue())

    def test_keyboard_interrupt_stops_quietly(self) -> None:
        """Ctrl+C is logged and ends `main()` normally."""
        with self.patched_runtime(KeyboardInterrupt()):
            self.run_main()
        self.assertIn("Received Ctrl+C", self.stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
