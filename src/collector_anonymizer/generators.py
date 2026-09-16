"""Anonymization Generators: produce anonymized replacement values.

Each generator class exposes a ``generate(original: str) -> str`` method that
returns a deterministic or sequentially assigned anonymized value. Sequential
generators use zero-padded counters starting from 0001. The IPAddressGenerator
preserves /24 subnet relationships. MAC and IPv6 generators use per-instance
random salts to prevent offline reversal.
"""

import hashlib
import ipaddress
import os
import re
from dataclasses import dataclass, field
from typing import Dict


# ---------------------------------------------------------------------------
# IP address anonymization data models
# ---------------------------------------------------------------------------


@dataclass
class SubnetMapping:
    """Maps an original /24 prefix to an anonymized /24 prefix."""

    original_prefix: str  # e.g. "192.168.1"
    anonymized_prefix: str  # e.g. "10.1.0"


@dataclass
class IPAnonymizationState:
    """Tracks subnet allocation state for IP anonymization."""

    subnet_mappings: Dict[str, str] = field(default_factory=dict)
    next_subnet_octet2: int = 1
    next_subnet_octet3: int = 0


# ---------------------------------------------------------------------------
# Sequential base class
# ---------------------------------------------------------------------------


class _SequentialGenerator:
    """Base for generators that produce ``<prefix>NNNN`` values."""

    def __init__(self, prefix: str, separator: str = "") -> None:
        self._prefix = prefix
        self._separator = separator
        self._counter = 0

    def generate(self, original: str) -> str:  # noqa: ARG002 – original unused
        """Return the next sequential anonymized value."""
        self._counter += 1
        return f"{self._prefix}{self._separator}{self._counter:04d}"


# ---------------------------------------------------------------------------
# Concrete generator classes
# ---------------------------------------------------------------------------


class HostnameGenerator(_SequentialGenerator):
    """Generates ``server-NNNN`` hostnames (zero-padded, starting at 0001)."""

    def __init__(self) -> None:
        super().__init__(prefix="server", separator="-")


class DatabaseNameGenerator(_SequentialGenerator):
    """Generates ``database-NNNN`` names."""

    def __init__(self) -> None:
        super().__init__(prefix="database", separator="-")


class OwnerNameGenerator(_SequentialGenerator):
    """Generates ``owner-NNNN`` names."""

    def __init__(self) -> None:
        super().__init__(prefix="owner", separator="-")


class OwnerEmailGenerator:
    """Generates ``owner-NNNN@example.com`` email addresses."""

    def __init__(self) -> None:
        self._counter = 0

    def generate(self, original: str) -> str:  # noqa: ARG002
        self._counter += 1
        return f"owner-{self._counter:04d}@example.com"


class OwnerPhoneGenerator:
    """Generates ``555-000-NNNN`` phone numbers."""

    def __init__(self) -> None:
        self._counter = 0

    def generate(self, original: str) -> str:  # noqa: ARG002
        self._counter += 1
        return f"555-000-{self._counter:04d}"


class ProcessNameGenerator(_SequentialGenerator):
    """Generates ``process-NNNN`` names."""

    def __init__(self) -> None:
        super().__init__(prefix="process", separator="-")


class ServiceAccountGenerator(_SequentialGenerator):
    """Generates ``svc-account-NNNN`` names."""

    def __init__(self) -> None:
        super().__init__(prefix="svc-account", separator="-")


# ---------------------------------------------------------------------------
# IP Address Generator (subnet-preserving)
# ---------------------------------------------------------------------------


class IPAddressGenerator:
    """Generates ``10.X.Y.Z`` IPs preserving /24 subnet relationships.

    Algorithm
    ---------
    1. Extract the /24 prefix (first three octets) from the original IP.
    2. If the prefix already has a mapping, reuse the anonymized prefix.
    3. Otherwise, assign the next available ``10.X.Y`` prefix.
    4. Combine the anonymized prefix with the original host octet (4th octet).
    5. Two IPs on the same /24 get the same anonymized /24.
    """

    def __init__(self) -> None:
        self._state = IPAnonymizationState()

    @property
    def state(self) -> IPAnonymizationState:
        """Expose internal state for inspection in tests."""
        return self._state

    def generate(self, original: str) -> str:
        """Return an anonymized IP that preserves /24 subnet membership."""
        parts = original.split(".")
        original_prefix = ".".join(parts[:3])
        host_octet = parts[3]

        if original_prefix in self._state.subnet_mappings:
            anon_prefix = self._state.subnet_mappings[original_prefix]
        else:
            anon_prefix = self._allocate_prefix(original_prefix)

        return f"{anon_prefix}.{host_octet}"

    def _allocate_prefix(self, original_prefix: str) -> str:
        """Assign the next available ``10.X.Y`` prefix and record the mapping."""
        o2 = self._state.next_subnet_octet2
        o3 = self._state.next_subnet_octet3

        anon_prefix = f"10.{o2}.{o3}"
        self._state.subnet_mappings[original_prefix] = anon_prefix

        # Advance to the next available prefix
        self._state.next_subnet_octet3 += 1
        if self._state.next_subnet_octet3 > 255:
            self._state.next_subnet_octet3 = 0
            self._state.next_subnet_octet2 += 1

        return anon_prefix


# ---------------------------------------------------------------------------
# Server ID Generator (deterministic UUID v5)
# ---------------------------------------------------------------------------


class ServerIDGenerator(_SequentialGenerator):
    """Generates ``d-server-NNNN`` sequential Server IDs.

    Uses sequential assignment instead of deterministic hashing to prevent
    brute-force reversal. The mapping store handles consistency across files.
    """

    def __init__(self) -> None:
        super().__init__(prefix="d-server", separator="-")


# ---------------------------------------------------------------------------
# MAC Address Generator
# ---------------------------------------------------------------------------


class MACAddressGenerator:
    """Generates anonymized MAC addresses with locally-administered bit set.

    Uses a per-instance random salt combined with the original MAC value to
    produce a salted SHA-256 hash. The salt prevents offline reversal while
    the original value ensures consistent output within a run when called
    through the mapping store. Prefixed with ``02:`` to indicate a
    locally-administered address.
    """

    def __init__(self) -> None:
        self._salt = os.urandom(16).hex()

    def generate(self, original: str) -> str:
        """Return an anonymized MAC address derived from a salted hash of *original*."""
        h = hashlib.sha256(f"{self._salt}-{original}".encode()).hexdigest()[:10]
        return "02:" + ":".join(h[i : i + 2] for i in range(0, 10, 2))


# ---------------------------------------------------------------------------
# IPv6 Address Generator
# ---------------------------------------------------------------------------


class IPv6AddressGenerator:
    """Generates anonymized IPv6 addresses in the ``fd00::/8`` ULA range.

    Uses a per-instance random salt combined with the original address to
    produce a salted SHA-256 hash. The salt prevents offline reversal while
    the original value ensures consistent output within a run when called
    through the mapping store.
    """

    def __init__(self) -> None:
        self._salt = os.urandom(16).hex()

    def generate(self, original: str) -> str:
        """Return a salted, anonymized IPv6 address for *original*."""
        h = hashlib.sha256(f"{self._salt}-{original}".encode()).hexdigest()[:28]
        return (
            f"fd00:{h[:4]}:{h[4:8]}:{h[8:12]}"
            f":{h[12:16]}:{h[16:20]}:{h[20:24]}:{h[24:28]}"
        )


# ---------------------------------------------------------------------------
# Domain Generator
# ---------------------------------------------------------------------------


class DomainGenerator(_SequentialGenerator):
    """Generates ``domain-NNN.local`` anonymized domain names."""

    def __init__(self) -> None:
        super().__init__(prefix="domain-", separator="")

    def generate(self, original: str) -> str:  # noqa: ARG002
        self._counter += 1
        return f"domain-{self._counter:03d}.local"


# ---------------------------------------------------------------------------
# FQDN Anonymization Helper
# ---------------------------------------------------------------------------


def anonymize_fqdn(
    original: str,
    mapping,
    hostname_generator,
    domain_generator,
) -> str:
    """Anonymize a fully qualified domain name by splitting host and domain parts.

    If *original* contains a dot, it is split into ``hostname.domain``. Each
    part is anonymized independently and recombined. The full FQDN is also
    stored in the hostnames mapping for consistent reverse lookup.

    If *original* has no dot, it is treated as a plain hostname.

    Parameters
    ----------
    original:
        The FQDN or hostname string.
    mapping:
        A :class:`MappingStore` instance.
    hostname_generator:
        Generator for the hostname part.
    domain_generator:
        Generator for the domain part.

    Returns
    -------
    str
        The anonymized FQDN or hostname.
    """
    if not original or not original.strip():
        return original

    key = original.strip().rstrip(".")
    if not key:
        return original

    # Already mapped as a full hostname (from a previous call)
    existing = mapping.forward.get("hostnames", {}).get(key)
    if existing:
        return existing

    parts = key.split(".", 1)
    if len(parts) == 1 or not parts[1] or len(parts[1]) < 2:
        # Plain hostname or degenerate FQDN
        return mapping.get_or_create("hostnames", key, hostname_generator.generate)

    hostname_part, domain_part = parts
    anon_host = mapping.get_or_create("hostnames", hostname_part, hostname_generator.generate)
    anon_domain = mapping.get_or_create("domains", domain_part, domain_generator.generate)
    fqdn = f"{anon_host}.{anon_domain}"

    # Store the full FQDN mapping so reverse lookup works on the complete string
    mapping.get_or_create("hostnames", key, lambda _: fqdn)
    return fqdn


# ---------------------------------------------------------------------------
# Multi-value IP field helpers
# ---------------------------------------------------------------------------

# Splits a field into IP tokens and the separators between them, capturing the
# separators so the original spacing/commas can be reproduced exactly on rejoin.
# Example: "1.1.1.1, 2.2.2.2  3.3.3.3" -> ["1.1.1.1", ", ", "2.2.2.2", "  ", "3.3.3.3"]
_IP_FIELD_SPLIT_RE = re.compile(r"([,\s]+)")


def _looks_like_ipv6(value: str) -> bool:
    """Return True if *value* is a valid IPv6 address."""
    if ":" not in value:
        return False
    try:
        ipaddress.IPv6Address(value)
        return True
    except ValueError:
        return False


def _is_separator(token: str) -> bool:
    """Return True if *token* is a run of commas/whitespace (a separator)."""
    return bool(token) and _IP_FIELD_SPLIT_RE.fullmatch(token) is not None


def anonymize_ip_field(value: str, mapping, generators: Dict[str, object]) -> str:
    """Anonymize an IP field that may hold one or more IPs.

    Handles single IPs as well as whitespace- and/or comma-separated lists of
    IPs in a single field. Each IP token is anonymized independently (IPv4 and
    IPv6 routed to their respective categories) and the original separators are
    preserved on rejoin. Non-IP tokens fall back to the IPv4 category, matching
    the historical single-value behaviour.
    """
    parts = _IP_FIELD_SPLIT_RE.split(value)
    out = []
    for token in parts:
        if not token or _is_separator(token):
            out.append(token)
        elif _looks_like_ipv6(token):
            out.append(
                mapping.get_or_create(
                    "ipv6_addresses", token, generators["ipv6_addresses"].generate
                )
            )
        else:
            out.append(
                mapping.get_or_create(
                    "ip_addresses", token, generators["ip_addresses"].generate
                )
            )
    return "".join(out)


def deanonymize_ip_field(value: str, mapping) -> str:
    """Reverse an IP field that may hold one or more IPs.

    Mirror of :func:`anonymize_ip_field`: tokenizes on whitespace/commas,
    reverse-looks-up each IP token (IPv4 then IPv6), preserves separators, and
    leaves unmapped tokens unchanged.
    """
    parts = _IP_FIELD_SPLIT_RE.split(value)
    out = []
    for token in parts:
        if not token or _is_separator(token):
            out.append(token)
        else:
            original = mapping.reverse_lookup("ip_addresses", token)
            if original is None:
                original = mapping.reverse_lookup("ipv6_addresses", token)
            out.append(original if original is not None else token)
    return "".join(out)
