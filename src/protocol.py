"""Minimal implementation of the DHCPv4 wire format (RFC 2131 and RFC 2132).

Parses incoming BOOTP/DHCP packets, builds server replies and encodes option
values. This module does no network I/O.
"""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import struct


BOOTREQUEST = 1
BOOTREPLY = 2
DHCP_MAGIC_COOKIE = b"\x63\x82\x53\x63"
DHCP_CLIENT_PORT = 68
DHCP_SERVER_PORT = 67
BROADCAST_ADDRESS = "255.255.255.255"
UNSPECIFIED_ADDRESS = "0.0.0.0"
BROADCAST_FLAG = 0x8000
MAX_RELAY_HOPS = 16
"""RFC 1542: a packet that has passed more than 16 relay agents is treated as looping."""
MAX_OPTION_LENGTH = 255
"""An option value length is encoded in a single byte."""

OPTION_PAD = 0
OPTION_SUBNET_MASK = 1
OPTION_ROUTER = 3
OPTION_DNS = 6
OPTION_REQUESTED_IP = 50
OPTION_LEASE_TIME = 51
OPTION_MESSAGE_TYPE = 53
OPTION_SERVER_IDENTIFIER = 54
OPTION_PARAMETER_REQUEST_LIST = 55
OPTION_RENEWAL_TIME = 58
OPTION_REBINDING_TIME = 59
OPTION_END = 255

DHCPDISCOVER = 1
DHCPOFFER = 2
DHCPREQUEST = 3
DHCPDECLINE = 4
DHCPACK = 5
DHCPNAK = 6
DHCPRELEASE = 7
DHCPINFORM = 8

_HEADER_FORMAT = "!BBBBIHH4s4s4s4s16s64s128s"
"""The fixed BOOTP header, without the magic cookie."""
_HEADER_SIZE = struct.calcsize(_HEADER_FORMAT)
_COOKIE_END = _HEADER_SIZE + len(DHCP_MAGIC_COOKIE)
_MINIMUM_REPLY_SIZE = 300
"""BOOTP clients expect a vendor area of at least 64 bytes, so replies are zero-padded to 300 bytes."""

_MAC_SEPARATORS = str.maketrans("", "", ":-. ")


class DHCPPacketError(ValueError):
    """The packet does not match the minimal DHCPv4 format."""


def _as_ipv4(value: bytes) -> str:
    """Convert 4 bytes in network byte order to a dotted-quad IPv4 address."""
    return str(ipaddress.IPv4Address(value))


def _ipv4_bytes(value: str) -> bytes:
    """Convert a dotted-quad IPv4 address to 4 bytes in network byte order."""
    return ipaddress.IPv4Address(value).packed


def normalise_mac(value: bytes) -> str:
    """Format a hardware address as `aa:bb:cc:dd:ee:ff`."""
    return ":".join(f"{part:02x}" for part in value)


def parse_mac(value: str) -> str:
    """Normalise a MAC address from the configuration to `aa:bb:cc:dd:ee:ff`.

    The separators `:`, `-`, `.` and spaces are ignored. Raises `ValueError`
    unless the value holds exactly six hexadecimal octets.
    """
    digits = value.strip().translate(_MAC_SEPARATORS)
    if len(digits) != 12:
        raise ValueError(f"invalid MAC address {value!r}: expected 6 octets")
    try:
        octets = bytes.fromhex(digits)
    except ValueError as error:
        raise ValueError(f"invalid MAC address {value!r}: {error}") from error
    return normalise_mac(octets)


@dataclass(frozen=True, slots=True)
class DHCPPacket:
    """A parsed BOOTP/DHCP packet: header fields and options keyed by code."""

    op: int
    htype: int
    hlen: int
    hops: int
    xid: int
    secs: int
    flags: int
    ciaddr: str
    yiaddr: str
    siaddr: str
    giaddr: str
    chaddr: bytes
    options: dict[int, bytes]

    @property
    def client_mac(self) -> str:
        """The client MAC address, taken from the first `hlen` bytes of `chaddr`."""
        return normalise_mac(self.chaddr[: self.hlen])

    @property
    def message_type(self) -> int | None:
        """The DHCP message type (option 53), or `None` if the option is missing or malformed."""
        value = self.options.get(OPTION_MESSAGE_TYPE)
        return value[0] if value and len(value) == 1 else None

    @property
    def broadcast_requested(self) -> bool:
        """Whether the client set the BROADCAST flag to ask for a broadcast reply."""
        return bool(self.flags & BROADCAST_FLAG)

    @property
    def relayed(self) -> bool:
        """Whether the packet came through a relay agent, that is, `giaddr` is set."""
        return self.giaddr != UNSPECIFIED_ADDRESS

    def requested_ip(self) -> str | None:
        """Return the address the client asked for (option 50), or `None`."""
        value = self.options.get(OPTION_REQUESTED_IP)
        return _as_ipv4(value) if value and len(value) == 4 else None

    def server_identifier(self) -> str | None:
        """Return the address of the server the client selected (option 54), or `None`."""
        value = self.options.get(OPTION_SERVER_IDENTIFIER)
        return _as_ipv4(value) if value and len(value) == 4 else None

    def parameter_request_list(self) -> frozenset[int]:
        """Return the option codes the client requested in option 55; empty if it sent no list."""
        return frozenset(self.options.get(OPTION_PARAMETER_REQUEST_LIST, b""))

    @classmethod
    def from_bytes(cls, data: bytes) -> DHCPPacket:
        """Parse a datagram into a packet.

        Repeated options are concatenated as RFC 3396 describes. Raises
        `DHCPPacketError` for a short packet, a missing magic cookie, an invalid
        hardware address length or a truncated option.
        """
        if len(data) < _COOKIE_END:
            raise DHCPPacketError(f"DHCP packet is shorter than {_COOKIE_END} bytes")

        fixed = struct.unpack(_HEADER_FORMAT, data[:_HEADER_SIZE])
        op, htype, hlen, hops, xid, secs, flags, ciaddr, yiaddr, siaddr, giaddr, chaddr, _, _ = fixed
        if data[_HEADER_SIZE:_COOKIE_END] != DHCP_MAGIC_COOKIE:
            raise DHCPPacketError("DHCP magic cookie is missing")
        if hlen > 16:
            raise DHCPPacketError("invalid hardware address length")

        options: dict[int, bytes] = {}
        index = _COOKIE_END
        while index < len(data):
            code = data[index]
            index += 1
            if code == OPTION_END:
                break
            if code == OPTION_PAD:
                continue
            if index >= len(data):
                raise DHCPPacketError("truncated DHCP option length")
            length = data[index]
            index += 1
            if index + length > len(data):
                raise DHCPPacketError("truncated DHCP option value")
            value = data[index : index + length]
            index += length
            options[code] = options.get(code, b"") + value

        return cls(
            op=op,
            htype=htype,
            hlen=hlen,
            hops=hops,
            xid=xid,
            secs=secs,
            flags=flags,
            ciaddr=_as_ipv4(ciaddr),
            yiaddr=_as_ipv4(yiaddr),
            siaddr=_as_ipv4(siaddr),
            giaddr=_as_ipv4(giaddr),
            chaddr=chaddr,
            options=options,
        )

    def reply(self, *, message_type: int, yiaddr: str, server_ip: str, options: dict[int, bytes]) -> bytes:
        """Build the server's reply to this packet.

        The message type and server identifier always come first, and the same
        codes in `options` are skipped. Following RFC 2131 (table 3), a DHCPNAK
        has `yiaddr` and `siaddr` cleared and the BROADCAST flag set, because it
        is always broadcast. Raises `ValueError` for an option longer than 255
        bytes.
        """
        is_nak = message_type == DHCPNAK
        flags = self.flags | BROADCAST_FLAG if is_nak else self.flags
        fixed = struct.pack(
            _HEADER_FORMAT,
            BOOTREPLY,
            self.htype,
            self.hlen,
            0,
            self.xid,
            0,
            flags,
            _ipv4_bytes(UNSPECIFIED_ADDRESS),
            _ipv4_bytes(UNSPECIFIED_ADDRESS if is_nak else yiaddr),
            _ipv4_bytes(UNSPECIFIED_ADDRESS if is_nak else server_ip),
            _ipv4_bytes(self.giaddr),
            self.chaddr,
            b"\0" * 64,
            b"\0" * 128,
        )
        encoded_options = bytearray(DHCP_MAGIC_COOKIE)
        encoded_options.extend((OPTION_MESSAGE_TYPE, 1, message_type))
        encoded_options.extend((OPTION_SERVER_IDENTIFIER, 4))
        encoded_options.extend(_ipv4_bytes(server_ip))
        for code, value in options.items():
            if code in {OPTION_MESSAGE_TYPE, OPTION_SERVER_IDENTIFIER}:
                continue
            if len(value) > MAX_OPTION_LENGTH:
                raise ValueError(f"DHCP option {code} is too long")
            encoded_options.extend((code, len(value)))
            encoded_options.extend(value)
        encoded_options.append(OPTION_END)
        return (fixed + bytes(encoded_options)).ljust(_MINIMUM_REPLY_SIZE, b"\0")


def ip_option(value: str) -> bytes:
    """Encode an option value holding one IPv4 address, such as the subnet mask."""
    return _ipv4_bytes(value)


def ips_option(values: tuple[str, ...]) -> bytes:
    """Encode an option value holding a list of IPv4 addresses, such as routers or DNS servers."""
    return b"".join(_ipv4_bytes(value) for value in values)


def uint32_option(value: int) -> bytes:
    """Encode a 32-bit unsigned option value, such as the lease time, T1 or T2."""
    return struct.pack("!I", value)
