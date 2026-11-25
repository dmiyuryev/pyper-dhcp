"""Asynchronous DHCPv4 server: configuration, packet handling and the command-line entry point.

Run it with `python src/main.py`; see `docs/running.md` for the options.
"""

from __future__ import annotations

import argparse
import asyncio
from collections.abc import Mapping
from contextlib import suppress
from dataclasses import dataclass
import errno
import ipaddress
from pathlib import Path
import signal
import socket
import struct
import sys
import time
import tomllib
from typing import cast

from loguru import logger

from lease import LeaseStore
from protocol import (
    BOOTREQUEST,
    BROADCAST_ADDRESS,
    DHCPACK,
    DHCP_CLIENT_PORT,
    DHCP_SERVER_PORT,
    DHCPDECLINE,
    DHCPDISCOVER,
    DHCPINFORM,
    DHCPNAK,
    DHCPOFFER,
    DHCPPacket,
    DHCPPacketError,
    DHCPRELEASE,
    DHCPREQUEST,
    MAX_OPTION_LENGTH,
    MAX_RELAY_HOPS,
    OPTION_DNS,
    OPTION_LEASE_TIME,
    OPTION_REBINDING_TIME,
    OPTION_RENEWAL_TIME,
    OPTION_ROUTER,
    OPTION_SUBNET_MASK,
    UNSPECIFIED_ADDRESS,
    ip_option,
    ips_option,
    parse_mac,
    uint32_option,
)

LOG = logger.bind(component="dhcp")
PROJECT_DIRECTORY = Path(__file__).resolve().parent.parent
CONFIG_DIRECTORY = PROJECT_DIRECTORY / "config"
VERSION_PATH = PROJECT_DIRECTORY / "VERSION"
"""The only source of the application version."""
DEFAULT_CONFIG_PATH = CONFIG_DIRECTORY / "config.default.toml"
LOCAL_CONFIG_PATH = CONFIG_DIRECTORY / "config.toml"

LOG_LEVELS = frozenset({"TRACE", "DEBUG", "INFO", "SUCCESS", "WARNING", "ERROR", "CRITICAL"})
FORBIDDEN_LOG_FORMAT_CHARACTERS = "{}<>"
"""The time format is inserted into a loguru markup string, so braces and angle brackets are not allowed."""
MAX_IP_LIST_LENGTH = MAX_OPTION_LENGTH // 4
"""Options 3 and 6 hold a list of IPv4 addresses, limited by the option length."""
MAX_DATAGRAMS_PER_READ = 64
"""Datagrams read per reader callback, so that a packet storm cannot block the event loop."""
DROP_REPORT_INTERVAL = 10.0
"""How often, in seconds, packets dropped by the rate limiter are reported."""
UINT32_LIMIT = 2**32


@dataclass(frozen=True, slots=True)
class ServerConfig:
    """Validated server settings loaded from the TOML configuration."""
    listen_address: str
    listen_port: int
    server_id: str
    subnet_mask: str
    pool_start: str
    pool_end: str
    lease_time: int
    router: str | None
    dns_servers: tuple[str, ...]
    lease_file: Path
    reservations: dict[str, str]
    log_level: str = "INFO"
    log_format: str = "%Y-%m-%d %H:%M:%S"
    cache_clean_interval: int = 60
    max_packets_per_second: int = 200

    @classmethod
    def from_toml(cls, path: Path) -> ServerConfig:
        """Load and validate the configuration from a single TOML file."""
        return cls._from_raw(cls._read_toml(path), path)

    @classmethod
    def from_files(cls, default_path: Path, local_path: Path) -> ServerConfig:
        """Load the base TOML file, merge the optional local file over it, and validate the result.

        Relative paths, such as `lease_file`, are resolved from the directory of the base file.
        """
        raw = cls._read_toml(default_path)
        if local_path.exists():
            raw = cls._merge_toml(raw, cls._read_toml(local_path))
        return cls._from_raw(raw, default_path)

    @staticmethod
    def _read_toml(path: Path) -> dict[str, object]:
        """Parse a TOML file into a dictionary."""
        with path.open("rb") as file:
            return tomllib.load(file)

    @classmethod
    def _merge_toml(cls, base: Mapping[str, object], override: Mapping[str, object]) -> dict[str, object]:
        """Merge TOML tables recursively, with values from `override` taking precedence."""
        merged = dict(base)
        for key, value in override.items():
            current = merged.get(key)
            if isinstance(current, dict) and isinstance(value, dict):
                merged[key] = cls._merge_toml(cast(dict[str, object], current), cast(dict[str, object], value))
            else:
                merged[key] = value
        return merged

    @classmethod
    def _from_raw(cls, raw: Mapping[str, object], path: Path) -> ServerConfig:
        """Build a configuration from parsed TOML, fill in defaults and validate it.

        `path` is the file the values came from; relative paths are resolved from its directory.
        Raises `ValueError` if a required option is missing or a value is invalid.
        """
        server = cls._table(raw, "server")
        required = ("server_id", "subnet_mask", "pool_start", "pool_end")
        missing = [key for key in required if key not in server]
        if missing:
            raise ValueError(f"missing [server] option(s): {', '.join(missing)}")
        config = cls(
            listen_address=str(server.get("listen_address", "0.0.0.0")),
            listen_port=cls._integer(server, "listen_port", DHCP_SERVER_PORT),
            server_id=str(server["server_id"]),
            subnet_mask=str(server["subnet_mask"]),
            pool_start=str(server["pool_start"]),
            pool_end=str(server["pool_end"]),
            lease_time=cls._integer(server, "lease_time", 86400),
            router=str(server["router"]) if server.get("router") else None,
            dns_servers=cls._string_list(server, "dns_servers"),
            lease_file=(path.parent / str(server.get("lease_file", "leases.json"))).resolve(),
            reservations=cls._reservations(raw),
            log_level=str(raw.get("log_level", "INFO")).upper(),
            log_format=str(raw.get("log_format", "%Y-%m-%d %H:%M:%S")),
            cache_clean_interval=cls._integer(raw, "cache_clean_interval", 60),
            max_packets_per_second=cls._integer(server, "max_packets_per_second", 200),
        )
        config.validate()
        return config

    @staticmethod
    def _table(raw: Mapping[str, object], key: str) -> Mapping[str, object]:
        """Return the TOML table under `key`, or an empty mapping; raise `ValueError` if it is not a table."""
        value = raw.get(key, {})
        if not isinstance(value, dict):
            raise ValueError(f"[{key}] must be a TOML table")
        return cast(dict[str, object], value)

    @staticmethod
    def _integer(table: Mapping[str, object], key: str, default: int) -> int:
        """Return the integer under `key`, or `default`; raise `ValueError` for any other type, including booleans."""
        value = table.get(key, default)
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError(f"{key} must be an integer")
        return value

    @staticmethod
    def _string_list(server: Mapping[str, object], key: str) -> tuple[str, ...]:
        """Return the array under `key` as a tuple of strings; raise `ValueError` if it is not an array."""
        value = server.get(key, [])
        if not isinstance(value, (list, tuple)):
            raise ValueError(f"[server].{key} must be an array")
        return tuple(str(item) for item in cast(list[object] | tuple[object, ...], value))

    @classmethod
    def _reservations(cls, raw: Mapping[str, object]) -> dict[str, str]:
        """Read `[reservations]`, normalising MAC addresses so that spellings like `AA-BB-..` are not silently lost.

        Raises `ValueError` for an invalid MAC address or one that is listed twice.
        """
        reservations: dict[str, str] = {}
        for mac, address in cls._table(raw, "reservations").items():
            normalised = parse_mac(str(mac))
            if normalised in reservations:
                raise ValueError(f"reservation {normalised} is defined more than once")
            reservations[normalised] = str(address)
        return reservations

    def validate(self) -> None:
        """Check that the settings are consistent and raise `ValueError` if they are not.

        The pool must lie inside the subnet defined by `server_id` and `subnet_mask`
        and must not contain the network or broadcast address (except on a /31),
        `server_id` or `router`. Reservations must be unique and inside the pool, and
        numeric and logging settings must be in range.
        """
        server_ip = ipaddress.IPv4Address(self.server_id)
        network = ipaddress.IPv4Network(f"{server_ip}/{self.subnet_mask}", strict=False)
        start, end = ipaddress.IPv4Address(self.pool_start), ipaddress.IPv4Address(self.pool_end)
        if start > end or start not in network or end not in network:
            raise ValueError("pool range must be ordered and belong to the configured subnet")
        if network.prefixlen < 31 and (start == network.network_address or end == network.broadcast_address):
            raise ValueError("pool must not include the network or the broadcast address")
        if start <= server_ip <= end:
            raise ValueError("pool must not include server_id")
        if self.router and start <= ipaddress.IPv4Address(self.router) <= end:
            raise ValueError("pool must not include router")
        if not 0 < self.lease_time < UINT32_LIMIT:
            raise ValueError(f"lease_time must be between 1 and {UINT32_LIMIT - 1}")
        if not 1 <= self.listen_port <= 65535:
            raise ValueError("listen_port must be between 1 and 65535")
        if len(self.dns_servers) > MAX_IP_LIST_LENGTH:
            raise ValueError(f"dns_servers must contain at most {MAX_IP_LIST_LENGTH} addresses")
        if self.log_level not in LOG_LEVELS:
            raise ValueError("log_level must be a valid loguru level")
        if not self.log_format:
            raise ValueError("log_format must not be empty")
        if any(character in self.log_format for character in FORBIDDEN_LOG_FORMAT_CHARACTERS):
            raise ValueError(f"log_format must not contain any of {FORBIDDEN_LOG_FORMAT_CHARACTERS!r}")
        if self.cache_clean_interval <= 0:
            raise ValueError("cache_clean_interval must be positive")
        if self.max_packets_per_second < 0:
            raise ValueError("max_packets_per_second must not be negative")
        for value in (self.listen_address, self.router, *self.dns_servers, *self.reservations.values()):
            if value:
                ipaddress.IPv4Address(value)
        if len(set(self.reservations.values())) != len(self.reservations):
            raise ValueError("every reservation must use a distinct address")
        for mac, address in self.reservations.items():
            if not start <= ipaddress.IPv4Address(address) <= end:
                raise ValueError(f"reservation {mac} is outside the pool")


class RateLimiter:
    """Token bucket that limits how many incoming datagrams are processed per second."""

    def __init__(self, rate: float, burst: float | None = None) -> None:
        """Allow `rate` datagrams per second with bursts of up to `burst`.

        The burst defaults to twice the rate, but at least one. A rate of 0 disables the limit.
        """
        self.rate = rate
        self.capacity = burst if burst is not None else max(rate * 2.0, 1.0)
        self._tokens = self.capacity
        self._updated = time.monotonic()

    def allow(self) -> bool:
        """Take one token and return whether the datagram may be processed."""
        if self.rate <= 0:
            return True
        now = time.monotonic()
        self._tokens = min(self.capacity, self._tokens + (now - self._updated) * self.rate)
        self._updated = now
        if self._tokens < 1.0:
            return False
        self._tokens -= 1.0
        return True


class DHCPServer:
    """Handles DHCP messages and sends each reply through the interface the request came in on."""

    _PACKET_INFO_SIZE = struct.calcsize("=I4s4s")

    def __init__(self, config: ServerConfig, sock: socket.socket) -> None:
        """Create a server that answers on `sock` using the lease store described by `config`."""
        self.config = config
        self.leases = LeaseStore(config.lease_file, config.pool_start, config.pool_end, config.reservations)
        self.socket = sock
        self.packet_info_enabled = hasattr(socket, "IP_PKTINFO") and hasattr(sock, "recvmsg")
        self.limiter = RateLimiter(config.max_packets_per_second)
        self._dropped = 0
        self._dropped_reported = time.monotonic()

    def start(self) -> None:
        """Log the address and port the server listens on."""
        LOG.info("DHCP server listens on {}:{}", self.config.listen_address, self.config.listen_port)

    def receive_datagrams(self) -> None:
        """Read the waiting UDP datagrams and handle them, keeping the index of the incoming interface.

        Reads at most `MAX_DATAGRAMS_PER_READ` datagrams per call and drops those over
        the rate limit. Socket errors are logged and end the call, otherwise the
        exception would be raised again from the `add_reader` callback forever.
        """
        for _ in range(MAX_DATAGRAMS_PER_READ):
            try:
                if self.packet_info_enabled:
                    data, ancillary, _, address = self.socket.recvmsg(65535, socket.CMSG_SPACE(self._PACKET_INFO_SIZE))
                    interface_index = self._interface_index(ancillary)
                else:
                    data, address = self.socket.recvfrom(65535)
                    interface_index = None
            except BlockingIOError:
                return
            except InterruptedError:
                continue
            except OSError as error:
                LOG.warning("Could not read from the DHCP socket: {}", error)
                return
            if not self.limiter.allow():
                self._count_dropped()
                continue
            self.handle_datagram(data, address, interface_index)

    def _count_dropped(self) -> None:
        """Count a datagram dropped by the rate limiter.

        The total is logged at most once every `DROP_REPORT_INTERVAL` seconds.
        """
        self._dropped += 1
        now = time.monotonic()
        if now - self._dropped_reported >= DROP_REPORT_INTERVAL:
            LOG.warning("Rate limit exceeded: dropped {} DHCP packet(s)", self._dropped)
            self._dropped = 0
            self._dropped_reported = now

    def handle_datagram(self, data: bytes, address: tuple[str, int], interface_index: int | None = None) -> None:
        """Parse one datagram and answer it.

        BOOTREPLY packets, non-Ethernet hardware and packets relayed through more than
        `MAX_RELAY_HOPS` agents are ignored. Malformed packets and unexpected errors
        are logged and never propagate.
        """
        try:
            packet = DHCPPacket.from_bytes(data)
            if packet.op != BOOTREQUEST or packet.htype != 1 or packet.hlen != 6:
                return
            if packet.hops > MAX_RELAY_HOPS:
                LOG.warning("Dropping packet from {} after {} relay hops", packet.client_mac, packet.hops)
                return
            self._handle(packet, address, interface_index)
        except DHCPPacketError as error:
            LOG.debug("Invalid DHCP packet from {}: {}", address, error)
        except Exception:
            LOG.exception("Failed to process DHCP packet from {}", address)

    def _interface_index(self, ancillary: list[tuple[int, int, bytes]]) -> int | None:
        """Return the incoming interface index from `IP_PKTINFO` ancillary data, or `None` if it is absent."""
        for level, kind, value in ancillary:
            if level == socket.IPPROTO_IP and kind == socket.IP_PKTINFO and len(value) >= self._PACKET_INFO_SIZE:
                interface_index, _, _ = struct.unpack("=I4s4s", value[: self._PACKET_INFO_SIZE])
                return int(interface_index)
        return None

    def _addressed_to_us(self, packet: DHCPPacket) -> bool:
        """Tell whether the message is meant for this server.

        Option 54, if present, must name this server (RFC 2131, section 4.3).
        """
        selected = packet.server_identifier()
        return selected is None or selected == self.config.server_id

    def _handle(self, packet: DHCPPacket, peer: tuple[str, int], interface_index: int | None) -> None:
        """Dispatch a packet to the handler for its DHCP message type; other types are ignored."""
        message_type = packet.message_type
        if message_type == DHCPDISCOVER:
            self._discover(packet, peer, interface_index)
        elif message_type == DHCPREQUEST:
            self._request(packet, peer, interface_index)
        elif message_type == DHCPRELEASE:
            self._release(packet, peer)
        elif message_type == DHCPDECLINE:
            self._decline(packet)
        elif message_type == DHCPINFORM:
            self._send(packet, DHCPACK, UNSPECIFIED_ADDRESS, peer, interface_index, include_lease=False)

    def _discover(self, packet: DHCPPacket, peer: tuple[str, int], interface_index: int | None) -> None:
        """Answer DHCPDISCOVER with an offer, or log a warning if the pool is exhausted."""
        offered_ip = self.leases.offer(packet.client_mac)
        if offered_ip is None:
            LOG.warning("No address available for {}", packet.client_mac)
            return
        self._send(packet, DHCPOFFER, offered_ip, peer, interface_index)
        LOG.info("Offered {} to {}", offered_ip, packet.client_mac)

    def _request(self, packet: DHCPPacket, peer: tuple[str, int], interface_index: int | None) -> None:
        """Answer DHCPREQUEST with DHCPACK if the address can be leased, otherwise with DHCPNAK.

        A request that names neither a requested address nor `ciaddr` does not say what
        to confirm, so it is ignored (RFC 2131, section 4.3.2).
        """
        if not self._addressed_to_us(packet):
            return
        requested_ip = packet.requested_ip() or self._client_address(packet)
        if requested_ip is None:
            LOG.debug("Ignoring DHCPREQUEST without an address from {}", packet.client_mac)
            return
        if not self.leases.assign(packet.client_mac, requested_ip, self.config.lease_time):
            self._send(packet, DHCPNAK, UNSPECIFIED_ADDRESS, peer, interface_index, include_lease=False)
            LOG.warning("Rejected request from {} for {}", packet.client_mac, requested_ip)
            return
        self._send(packet, DHCPACK, requested_ip, peer, interface_index)
        LOG.info("Assigned {} to {}", requested_ip, packet.client_mac)

    def _release(self, packet: DHCPPacket, peer: tuple[str, int]) -> None:
        """Free the client's lease on DHCPRELEASE.

        DHCPRELEASE is sent by unicast, so a direct (not relayed) release must come
        from the address being released; otherwise any client could end another
        client's lease.
        """
        address = self._client_address(packet)
        if address is None:
            LOG.warning("Ignoring DHCPRELEASE without ciaddr from {}", packet.client_mac)
            return
        if not self._addressed_to_us(packet):
            return
        if not packet.relayed and peer[0] not in {UNSPECIFIED_ADDRESS, address}:
            LOG.warning("Ignoring spoofed DHCPRELEASE for {} sent from {}", address, peer[0])
            return
        if self.leases.release(packet.client_mac, address):
            LOG.info("Released {} for {}", address, packet.client_mac)
        else:
            LOG.debug("DHCPRELEASE from {} for {} matched no lease", packet.client_mac, address)

    def _decline(self, packet: DHCPPacket) -> None:
        """Quarantine the address a client reported as already in use (DHCPDECLINE)."""
        address = packet.requested_ip() or self._client_address(packet)
        if address is None or not self._addressed_to_us(packet):
            return
        if self.leases.decline(packet.client_mac, address):
            LOG.warning("Client {} declined {}; address is quarantined", packet.client_mac, address)
        else:
            LOG.warning("Ignoring DHCPDECLINE for {} from {}: address is not theirs", address, packet.client_mac)

    @staticmethod
    def _client_address(packet: DHCPPacket) -> str | None:
        """Return the client's `ciaddr`, or `None` if it is unset."""
        return packet.ciaddr if packet.ciaddr != UNSPECIFIED_ADDRESS else None

    def _reply_options(self, packet: DHCPPacket, *, include_lease: bool) -> dict[int, bytes]:
        """Build the options for an OFFER or ACK.

        The gateway and DNS servers are included only if the client asked for them in
        option 55 or sent no list. With `include_lease`, the lease time, T1 and T2 are added.
        """
        requested = packet.parameter_request_list()

        def wanted(code: int) -> bool:
            """Tell whether the client wants option `code`; an empty list means it asked for everything."""
            return not requested or code in requested

        options: dict[int, bytes] = {OPTION_SUBNET_MASK: ip_option(self.config.subnet_mask)}
        if self.config.router and wanted(OPTION_ROUTER):
            options[OPTION_ROUTER] = ip_option(self.config.router)
        if self.config.dns_servers and wanted(OPTION_DNS):
            options[OPTION_DNS] = ips_option(self.config.dns_servers)
        if include_lease:
            options[OPTION_LEASE_TIME] = uint32_option(self.config.lease_time)
            options[OPTION_RENEWAL_TIME] = uint32_option(self.config.lease_time // 2)
            options[OPTION_REBINDING_TIME] = uint32_option(self.config.lease_time * 7 // 8)
        return options

    @staticmethod
    def _destination(packet: DHCPPacket, message_type: int) -> tuple[str, int]:
        """Choose where to send the reply, following RFC 2131, section 4.1.

        Relayed requests go back to the relay agent. A DHCPNAK is broadcast, because
        the client has no usable address yet. Clients that already have an address in
        `ciaddr` (renewing, DHCPINFORM) get a unicast reply. Everyone else gets a
        broadcast, because unicast to an unconfigured `yiaddr` would need a manual ARP
        entry.
        """
        if packet.relayed:
            return (packet.giaddr, DHCP_SERVER_PORT)
        if message_type == DHCPNAK:
            return (BROADCAST_ADDRESS, DHCP_CLIENT_PORT)
        if packet.ciaddr != UNSPECIFIED_ADDRESS:
            return (packet.ciaddr, DHCP_CLIENT_PORT)
        return (BROADCAST_ADDRESS, DHCP_CLIENT_PORT)

    def _send(
        self,
        packet: DHCPPacket,
        message_type: int,
        yiaddr: str,
        peer: tuple[str, int],
        interface_index: int | None,
        *,
        include_lease: bool = True,
    ) -> None:
        """Build and send a reply of type `message_type` offering `yiaddr`.

        A DHCPNAK carries only the message type and server identifier (RFC 2131,
        section 4.3.2). On Linux the reply is pinned to the incoming interface with
        `IP_PKTINFO`; if `server_id` is not available on that interface, or the
        platform has no `IP_PKTINFO`, it falls back to `sendto`. Send errors are logged.
        """
        options = {} if message_type == DHCPNAK else self._reply_options(packet, include_lease=include_lease)
        reply = packet.reply(message_type=message_type, yiaddr=yiaddr, server_ip=self.config.server_id, options=options)
        destination = self._destination(packet, message_type)
        try:
            if interface_index is not None and self.packet_info_enabled:
                packet_info = struct.pack("=I4s4s", interface_index, socket.inet_aton(self.config.server_id), b"\0" * 4)
                try:
                    self.socket.sendmsg([reply], [(socket.IPPROTO_IP, socket.IP_PKTINFO, packet_info)], 0, destination)
                    return
                except OSError as error:
                    if error.errno not in {errno.EINVAL, errno.ENODEV, errno.ENETUNREACH}:
                        raise
                    LOG.debug("Could not pin the reply to interface {}: {}", interface_index, error)
            self.socket.sendto(reply, destination)
        except OSError:
            LOG.exception("Could not send DHCP reply to {} via interface {}", destination, interface_index)


async def cleanup_leases(leases: LeaseStore, interval: int, stop_event: asyncio.Event) -> None:
    """Remove expired leases every `interval` seconds until `stop_event` is set."""
    while not stop_event.is_set():
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=interval)
        except TimeoutError:
            try:
                removed = leases.cleanup()
            except OSError:
                LOG.exception("Could not persist the lease database")
                continue
            if removed:
                LOG.info("Removed {} expired record(s) from cache", removed)


def create_socket(config: ServerConfig) -> socket.socket:
    """Create the non-blocking, broadcast-capable UDP socket the server listens on."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        if hasattr(socket, "IP_PKTINFO") and hasattr(sock, "recvmsg"):
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_PKTINFO, 1)
        sock.bind((config.listen_address, config.listen_port))
        sock.setblocking(False)
    except OSError:
        sock.close()
        raise
    return sock


async def serve(config: ServerConfig, *, version: str) -> None:
    """Run the server until SIGINT, SIGTERM or cancellation, then shut down cleanly.

    On shutdown the socket is closed, the cleanup task is stopped and pending lease
    renewals are written to disk. Signal handlers are skipped where the event loop
    does not support them, for example on Windows.
    """
    config.lease_file.parent.mkdir(parents=True, exist_ok=True)
    sock = create_socket(config)
    loop = asyncio.get_running_loop()
    cleanup_task: asyncio.Task[None] | None = None
    stop_event = asyncio.Event()
    registered_signals: list[signal.Signals] = []
    protocol: DHCPServer | None = None

    def request_shutdown(signum: signal.Signals) -> None:
        """Handle SIGINT or SIGTERM by asking the server to stop."""
        if not stop_event.is_set():
            LOG.info("Received {}; stopping DHCP server", signum.name)
            stop_event.set()

    try:
        protocol = DHCPServer(config, sock)
        protocol.leases.load()
        loop.add_reader(sock.fileno(), protocol.receive_datagrams)
        protocol.start()
        LOG.info("Starting PyperDHCP version {}", version)
        for signum in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(signum, request_shutdown, signum)
                registered_signals.append(signum)
            except (NotImplementedError, RuntimeError):
                LOG.debug("Signal handler for {} is unavailable", signum.name)
        cleanup_task = asyncio.create_task(
            cleanup_leases(protocol.leases, config.cache_clean_interval, stop_event),
            name="dhcp-lease-cache-cleanup",
        )
        await stop_event.wait()
    except asyncio.CancelledError:
        LOG.info("DHCP server task was cancelled; stopping")
        raise
    finally:
        if cleanup_task is not None:
            cleanup_task.cancel()
            with suppress(asyncio.CancelledError):
                await cleanup_task
        for signum in registered_signals:
            loop.remove_signal_handler(signum)
        loop.remove_reader(sock.fileno())
        sock.close()
        if protocol is not None:
            try:
                protocol.leases.flush()
            except OSError:
                LOG.exception("Could not persist the lease database on shutdown")
        LOG.info("DHCP server stopped")


def read_version(path: Path = VERSION_PATH) -> str:
    """Read the application version from the `VERSION` file in the project root.

    Raises `ValueError` if the file cannot be read or does not contain exactly one non-empty line.
    """
    try:
        version = path.read_text(encoding="utf-8").strip()
    except OSError as error:
        raise ValueError(f"cannot read version file {path}: {error.strerror or error}") from error
    if not version or len(version.splitlines()) != 1:
        raise ValueError(f"version file {path} must contain exactly one non-empty line")
    return version


def configure_logging(*, level: str, time_format: str) -> None:
    """Send logs to standard error with the given level and timestamp format."""
    logger.remove()
    logger.configure(extra={"component": "dhcp"})
    logger.add(
        sys.stderr,
        level=level,
        format=(
            f"<green>{{time:{time_format}}}</green> | <level>{{level: <8}}</level> "
            "| <cyan>{extra[component]: <7}</cyan> | {message}"
        ),
        colorize=sys.stderr.isatty(),
    )


def parse_arguments(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse the command-line arguments."""
    parser = argparse.ArgumentParser(prog="pyper-dhcp", description="A small asynchronous DHCPv4 server")
    parser.add_argument(
        "--default-config",
        type=Path,
        default=DEFAULT_CONFIG_PATH,
        metavar="PATH",
        help="base configuration file (default: config/config.default.toml)",
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=LOCAL_CONFIG_PATH,
        metavar="PATH",
        help="local configuration file that overrides the base file (default: config/config.toml)",
    )
    parser.add_argument("--check-config", action="store_true", help="validate the configuration and exit")
    parser.add_argument("--version", action="store_true", help="print the version and exit")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    """Command-line entry point: load the configuration and run the server.

    Exits with code 2 if the version file or the configuration cannot be loaded,
    or if the server cannot start. Ctrl+C is also handled here for environments
    without asyncio signal handlers.
    """
    arguments = parse_arguments(argv)
    try:
        version = read_version()
    except ValueError as error:
        configure_logging(level="INFO", time_format="%Y-%m-%d %H:%M:%S")
        LOG.error("Could not determine the application version: {}", error)
        raise SystemExit(2) from error
    if arguments.version:
        print(version)
        return

    try:
        config = ServerConfig.from_files(arguments.default_config, arguments.config)
    except (OSError, ValueError) as error:
        configure_logging(level="INFO", time_format="%Y-%m-%d %H:%M:%S")
        LOG.error("Could not load configuration: {}", error)
        raise SystemExit(2) from error

    configure_logging(level=config.log_level, time_format=config.log_format)

    if arguments.check_config:
        LOG.success("Configuration is valid: {} (+ {})", arguments.default_config, arguments.config)
        return

    try:
        asyncio.run(serve(config, version=version))
    except KeyboardInterrupt:
        LOG.info("Received Ctrl+C; DHCP server stopped")
    except (OSError, ValueError) as error:
        LOG.error("Could not start DHCP server: {}", error)
        raise SystemExit(2) from error


if __name__ == "__main__":
    main()
