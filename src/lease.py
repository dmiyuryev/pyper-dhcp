"""DHCP lease bookkeeping with a simple JSON file for persistence.

`LeaseStore` decides which address a client is offered, records leases,
offers and quarantined addresses, and keeps the active leases on disk.
"""

from __future__ import annotations

from contextlib import suppress
from dataclasses import asdict, dataclass, fields
import ipaddress
import json
import os
from pathlib import Path
import time
from typing import cast

from loguru import logger


LOG = logger.bind(component="lease")

OFFER_LIFETIME = 60
"""How long, in seconds, an address stays reserved between DHCPOFFER and DHCPREQUEST."""
DECLINE_QUARANTINE = 3600
"""How long, in seconds, an address is taken out of use after DHCPDECLINE reports a conflict."""
RENEWAL_SAVE_INTERVAL = 10.0
"""Minimum delay, in seconds, between saves caused by lease renewals.

Saving a renewal late is safe: after a crash the server sees the earlier
expiry and still will not give the address to another client.
"""
LEASE_FILE_MODE = 0o600
"""Permissions of the lease file, which maps every client's MAC address to its IP address."""


@dataclass(slots=True)
class Lease:
    """An address held by a client until `expires_at`, a Unix timestamp."""

    ip: str
    mac: str
    expires_at: float

    @property
    def active(self) -> bool:
        """Whether the lease has not expired yet."""
        return self.expires_at > time.time()


LEASE_FIELDS = frozenset(field.name for field in fields(Lease))
"""The exact set of keys every entry of the lease file must have."""


class LeaseStore:
    """Leases, offers and quarantined addresses for one address pool."""

    def __init__(self, path: Path, pool_start: str, pool_end: str, reservations: dict[str, str]) -> None:
        """Create an empty store for the pool from `pool_start` to `pool_end`, saved to `path`.

        `reservations` maps MAC addresses to the address reserved for them.
        Call `load()` to read leases saved earlier.
        """
        self.path = path
        self.pool_start = ipaddress.IPv4Address(pool_start)
        self.pool_end = ipaddress.IPv4Address(pool_end)
        self.reservations = {mac.lower(): ip for mac, ip in reservations.items()}
        self._reserved_addresses = frozenset(self.reservations.values())
        self._reserved_numbers = frozenset(int(ipaddress.IPv4Address(ip)) for ip in self._reserved_addresses)
        self._leases_by_mac: dict[str, Lease] = {}
        self._leases_by_ip: dict[str, Lease] = {}
        self._offers_by_mac: dict[str, Lease] = {}
        self._offers_by_ip: dict[str, Lease] = {}
        self._declined: dict[str, float] = {}
        self._dirty = False
        self._last_save = 0.0

    def load(self) -> None:
        """Read leases from disk.

        A damaged file must not stop the server from handing out addresses, so
        it is moved aside and the store starts empty. Duplicate leases for the
        same address or MAC address are dropped, keeping the first one.
        """
        if not self.path.exists():
            return
        try:
            leases = self._parse(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError, TypeError) as error:
            self._quarantine_lease_file(error)
            return
        for lease in leases:
            if lease.ip in self._leases_by_ip or lease.mac in self._leases_by_mac:
                LOG.warning("Dropping duplicate lease {} for {}", lease.ip, lease.mac)
                continue
            self._put(lease)

    def _parse(self, content: str) -> list[Lease]:
        """Validate the JSON content of the lease file and return the usable leases.

        Raises `ValueError` if the content is not an array of objects with
        exactly the `Lease` fields of the right types. Expired leases, leases
        outside the pool and leases that conflict with reservations are skipped.
        """
        raw = json.loads(content)
        if not isinstance(raw, list):
            raise ValueError("lease file must contain a JSON array")
        leases: list[Lease] = []
        for item in cast(list[object], raw):
            if not isinstance(item, dict):
                raise ValueError("lease entry must be a JSON object")
            entry = cast(dict[str, object], item)
            if entry.keys() != LEASE_FIELDS:
                raise ValueError(f"lease entry must have exactly the fields {sorted(LEASE_FIELDS)}")
            ip, mac, expires_at = entry["ip"], entry["mac"], entry["expires_at"]
            if not isinstance(ip, str) or not isinstance(mac, str):
                raise ValueError("lease ip and mac must be strings")
            if isinstance(expires_at, bool) or not isinstance(expires_at, (int, float)):
                raise ValueError("lease expires_at must be a number")
            lease = Lease(ip=ip, mac=mac.lower(), expires_at=float(expires_at))
            if not lease.active or not self.in_pool(lease.ip):
                continue
            if self._conflicts_with_reservations(lease):
                continue
            leases.append(lease)
        return leases

    def _conflicts_with_reservations(self, lease: Lease) -> bool:
        """Tell whether a saved lease contradicts reservations changed since it was saved."""
        reserved = self.reservations.get(lease.mac)
        if reserved is not None and reserved != lease.ip:
            LOG.info("Dropping lease {} for {}: reservation now points to {}", lease.ip, lease.mac, reserved)
            return True
        if reserved is None and lease.ip in self._reserved_addresses:
            LOG.info("Dropping lease {} for {}: address is now reserved for another client", lease.ip, lease.mac)
            return True
        return False

    def _quarantine_lease_file(self, error: Exception) -> None:
        """Move an unreadable lease file to `<name>.corrupt` and log why."""
        backup = self.path.with_name(f"{self.path.name}.corrupt")
        LOG.error("Cannot read lease file {}: {}; starting with an empty lease database", self.path, error)
        try:
            self.path.replace(backup)
        except OSError as rename_error:
            LOG.error("Could not move the damaged lease file aside: {}", rename_error)
        else:
            LOG.error("Damaged lease file was moved to {}", backup)

    def save(self) -> None:
        """Write the active leases to disk atomically.

        The data goes to a temporary file with `LEASE_FILE_MODE` permissions,
        is flushed with `fsync` and then renamed over the lease file.
        """
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._purge_expired()
        content = json.dumps([asdict(lease) for lease in self._leases_by_mac.values()], indent=2, sort_keys=True)
        temporary_path = self.path.with_name(f"{self.path.name}.tmp")
        descriptor = os.open(temporary_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, LEASE_FILE_MODE)
        with os.fdopen(descriptor, "w", encoding="utf-8") as file:
            file.write(content + "\n")
            file.flush()
            os.fsync(file.fileno())
        os.replace(temporary_path, self.path)
        self._sync_directory()
        self._dirty = False
        self._last_save = time.monotonic()

    def _sync_directory(self) -> None:
        """Flush the directory entry so that the rename survives a power failure."""
        with suppress(OSError):
            descriptor = os.open(self.path.parent, os.O_RDONLY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)

    def flush(self) -> None:
        """Save pending changes, such as deferred lease renewals."""
        if self._dirty:
            self.save()

    def _save_now_or_defer(self, *, renewal: bool) -> None:
        """Save a lease change, or defer it if it only renews a lease.

        A new lease must reach the disk at once, otherwise the same address
        could be given to a second client after a crash. Renewals are saved at
        most once per `RENEWAL_SAVE_INTERVAL`.
        """
        if not renewal or time.monotonic() - self._last_save >= RENEWAL_SAVE_INTERVAL:
            self.save()

    def in_pool(self, address: str) -> bool:
        """Tell whether `address` is a valid IPv4 address inside the pool."""
        try:
            ip = ipaddress.IPv4Address(address)
        except ipaddress.AddressValueError:
            return False
        return self.pool_start <= ip <= self.pool_end

    def offer(self, mac: str) -> str | None:
        """Choose an address to offer to `mac`, or return `None` if none is available.

        A client with a reservation is offered its reserved address. A client
        with a lease or an open offer gets the same address again. Anyone else
        gets the lowest free address, which stays reserved for `OFFER_LIFETIME`.
        """
        mac = mac.lower()
        self._purge()
        if reserved := self.reservations.get(mac):
            return self._offer_reserved(mac, reserved)
        if existing := self._leases_by_mac.get(mac):
            return existing.ip
        if offered := self._offers_by_mac.get(mac):
            return offered.ip
        address = self._next_free_address()
        if address is None:
            return None
        self._put_offer(Lease(ip=address, mac=mac, expires_at=time.time() + OFFER_LIFETIME))
        return address

    def _offer_reserved(self, mac: str, reserved: str) -> str | None:
        """Offer `mac` its reserved address unless another client holds it or it is quarantined."""
        holder = self._leases_by_ip.get(reserved)
        if holder is not None and holder.mac != mac:
            LOG.warning("Reserved address {} for {} is still leased to {}", reserved, mac, holder.mac)
            return None
        if reserved in self._declined:
            LOG.warning("Reserved address {} for {} is quarantined after DHCPDECLINE", reserved, mac)
            return None
        self._put_offer(Lease(ip=reserved, mac=mac, expires_at=time.time() + OFFER_LIFETIME))
        return reserved

    def _next_free_address(self) -> str | None:
        """Find the lowest free address in the pool.

        Taken addresses are converted to integers once: there are usually far
        fewer of them than addresses in the pool, and each candidate then costs
        a single set lookup.
        """
        taken = self._reserved_numbers | {
            int(ipaddress.IPv4Address(address))
            for address in (*self._leases_by_ip, *self._offers_by_ip, *self._declined)
        }
        for number in range(int(self.pool_start), int(self.pool_end) + 1):
            if number not in taken:
                return str(ipaddress.IPv4Address(number))
        return None

    def assign(self, mac: str, address: str, duration: int) -> bool:
        """Lease `address` to `mac` for `duration` seconds and return whether it was allowed.

        The request is refused if the address belongs to another client's
        reservation, lease or offer, lies outside the pool, or is quarantined.
        A client with a reservation may only take its reserved address. Any
        previous lease of the same client is replaced.
        """
        mac = mac.lower()
        self._purge()
        reserved = self.reservations.get(mac)
        if reserved is not None and address != reserved:
            return False
        if reserved is None and address in self._reserved_addresses:
            return False
        if reserved is None and not self.in_pool(address):
            return False
        if address in self._declined:
            return False
        current = self._leases_by_ip.get(address)
        if current is not None and current.mac != mac:
            return False
        offered = self._offers_by_ip.get(address)
        if offered is not None and offered.mac != mac:
            return False
        previous = self._leases_by_mac.pop(mac, None)
        if previous is not None:
            self._leases_by_ip.pop(previous.ip, None)
        self._remove_offer(mac)
        self._put(Lease(ip=address, mac=mac, expires_at=time.time() + duration))
        self._dirty = True
        self._save_now_or_defer(renewal=previous is not None and previous.ip == address)
        return True

    def release(self, mac: str, address: str | None = None) -> bool:
        """End the lease of `mac` and return whether there was one to end.

        If `address` is given, the lease is ended only when it holds that address.
        """
        lease = self._leases_by_mac.get(mac.lower())
        if lease is None or (address is not None and lease.ip != address):
            return False
        self._leases_by_mac.pop(lease.mac, None)
        self._leases_by_ip.pop(lease.ip, None)
        self._dirty = True
        self.save()
        return True

    def decline(self, mac: str, address: str, quarantine: float = DECLINE_QUARANTINE) -> bool:
        """Take `address` out of use for `quarantine` seconds after a client found a conflict.

        Only the client that holds or was offered the address may decline it,
        otherwise any client could take every address in the pool out of use.
        Returns whether the address was quarantined.
        """
        mac = mac.lower()
        lease = self._leases_by_ip.get(address)
        offered = self._offers_by_ip.get(address)
        owner = lease.mac if lease is not None else offered.mac if offered is not None else None
        if owner != mac:
            return False
        if lease is not None:
            self._leases_by_mac.pop(lease.mac, None)
            self._leases_by_ip.pop(lease.ip, None)
            self._dirty = True
        if offered is not None:
            self._remove_offer(offered.mac)
        self._declined[address] = time.time() + quarantine
        self.flush()
        return True

    def cleanup(self) -> int:
        """Remove expired records, save the store if it changed, and return how many were removed."""
        removed = self._purge()
        self.flush()
        return removed

    def _purge(self) -> int:
        """Remove expired leases, offers and quarantine entries; return how many were removed."""
        return self._purge_expired() + self._purge_expired_offers() + self._purge_expired_declines()

    def _purge_expired(self) -> int:
        """Remove expired leases, mark the store as changed, and return how many were removed."""
        removed = 0
        for lease in list(self._leases_by_mac.values()):
            if not lease.active:
                self._leases_by_mac.pop(lease.mac, None)
                self._leases_by_ip.pop(lease.ip, None)
                self._dirty = True
                removed += 1
        return removed

    def _purge_expired_offers(self) -> int:
        """Remove expired offers and return how many were removed."""
        removed = 0
        for offer in list(self._offers_by_mac.values()):
            if not offer.active:
                self._offers_by_mac.pop(offer.mac, None)
                self._offers_by_ip.pop(offer.ip, None)
                removed += 1
        return removed

    def _purge_expired_declines(self) -> int:
        """Return addresses whose quarantine has ended to the pool; return how many were freed."""
        now = time.time()
        expired = [address for address, until in self._declined.items() if until <= now]
        for address in expired:
            del self._declined[address]
        return len(expired)

    def _put(self, lease: Lease) -> None:
        """Index a lease by MAC address and by IP address."""
        self._leases_by_mac[lease.mac] = lease
        self._leases_by_ip[lease.ip] = lease

    def _put_offer(self, offer: Lease) -> None:
        """Index an offer by MAC address and by IP address."""
        self._offers_by_mac[offer.mac] = offer
        self._offers_by_ip[offer.ip] = offer

    def _remove_offer(self, mac: str) -> None:
        """Drop the open offer for `mac`, if there is one."""
        offer = self._offers_by_mac.pop(mac, None)
        if offer is not None:
            self._offers_by_ip.pop(offer.ip, None)
