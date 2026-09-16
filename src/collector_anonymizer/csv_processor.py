"""CSV Processor: anonymize and de-anonymize sensitive columns in CSV files.

Handles column-based replacement for sensitive fields (hostnames, IPs, Server
IDs, database names, owner info, process names, service accounts) and
hostname substitution within file path columns.
"""

import csv
import io
from typing import Dict, List

from collector_anonymizer.generators import (
    DatabaseNameGenerator,
    DomainGenerator,
    HostnameGenerator,
    IPAddressGenerator,
    IPv6AddressGenerator,
    MACAddressGenerator,
    OwnerEmailGenerator,
    OwnerNameGenerator,
    OwnerPhoneGenerator,
    ProcessNameGenerator,
    ServerIDGenerator,
    ServiceAccountGenerator,
    anonymize_fqdn,
    anonymize_ip_field,
    deanonymize_ip_field,
)
from collector_anonymizer.mapping_store import MappingStore

# ---------------------------------------------------------------------------
# Column classification
# ---------------------------------------------------------------------------

SENSITIVE_COLUMNS: Dict[str, str] = {
    # --- Hostnames / FQDNs ---
    "HOSTNAME": "hostnames",
    "Display Name": "hostnames",
    "Virtual Server Name": "hostnames",
    "PS Computer Name": "hostnames",
    "DB Instance Name": "hostnames",
    "Container Name": "hostnames",
    "SSRS Database Server Name": "hostnames",
    "server_name": "hostnames",
    "primary_hostname": "hostnames",
    "cluster_name": "hostnames",
    "hypervisor_hostname": "hostnames",
    "virtual_network_name": "hostnames",
    "interface_name": "hostnames",
    # --- IPv4 addresses ---
    "Source Server IP Address": "ip_addresses",
    "Target Server IP Address": "ip_addresses",
    "Server Connection Address": "ip_addresses",
    "primary_ip_address": "ip_addresses",
    "ipv4_address": "ip_addresses",
    "ipv4_gateway": "ip_addresses",
    "dns_servers": "ip_addresses",
    # --- IPv6 addresses ---
    "ipv6_address": "ipv6_addresses",
    "ipv6_gateway": "ipv6_addresses",
    # --- Server IDs ---
    "Server ID": "server_ids",
    "Serverid": "server_ids",
    "Source Server ID": "server_ids",
    "Target Server ID": "server_ids",
    "SQL Component ID": "server_ids",
    "server_id": "server_ids",
    "hypervisor_host_id": "server_ids",
    "hypervisor_id": "server_ids",
    "hypervisor_object_id": "server_ids",
    # --- MAC addresses ---
    "mac_address": "mac_addresses",
    # --- Database names ---
    "DB Name": "database_names",
    "SSRS Database Name": "database_names",
    # --- Owner info ---
    "Database Owner Name": "owner_names",
    "Database Owner Email": "owner_emails",
    "Database Owner Phone": "owner_phones",
    "process_user": "owner_names",
    # --- Process names ---
    "Source Process Name": "process_names",
    "Target Process Name": "process_names",
    "process_name": "process_names",
    # --- Service accounts ---
    "Service Account Name": "service_accounts",
}

PATH_COLUMNS: List[str] = [
    "Binary Path",
    "Install Path",
    "Data Path",
    "SSRS Config Path",
    "process_command_line",
]

# Map category names to their generator classes
_GENERATORS: Dict[str, type] = {
    "hostnames": HostnameGenerator,
    "ip_addresses": IPAddressGenerator,
    "ipv6_addresses": IPv6AddressGenerator,
    "server_ids": ServerIDGenerator,
    "database_names": DatabaseNameGenerator,
    "owner_names": OwnerNameGenerator,
    "owner_emails": OwnerEmailGenerator,
    "owner_phones": OwnerPhoneGenerator,
    "process_names": ProcessNameGenerator,
    "service_accounts": ServiceAccountGenerator,
    "mac_addresses": MACAddressGenerator,
    "domains": DomainGenerator,
}


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _build_generators() -> Dict[str, object]:
    """Instantiate one generator per category."""
    return {cat: cls() for cat, cls in _GENERATORS.items()}


import re

_MAC_RE = re.compile(r"^([0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}$")


def _is_mac(value: str) -> bool:
    """Return True if *value* looks like a MAC address."""
    return bool(_MAC_RE.match(value))


def _anonymize_path(value: str, mapping: MappingStore) -> str:
    """Replace known hostnames embedded in a file path with their anonymized equivalents.

    Scans the forward hostname mappings and substitutes any occurrence found
    within *value*, preserving drive letters, separators, and all other path
    components.
    """
    hostname_fwd = mapping.forward.get("hostnames", {})
    for original, anonymized in hostname_fwd.items():
        if original in value:
            value = value.replace(original, anonymized)
    return value


def _deanonymize_path(value: str, mapping: MappingStore) -> str:
    """Replace anonymized hostnames embedded in a file path with originals."""
    hostname_rev = mapping.reverse.get("hostnames", {})
    for anonymized, original in hostname_rev.items():
        if anonymized in value:
            value = value.replace(anonymized, original)
    return value


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def anonymize_csv(
    content: str,
    mapping: MappingStore,
    generators: Dict[str, object] | None = None,
) -> str:
    """Parse a CSV string, replace sensitive column values, and return the anonymized CSV.

    For columns listed in ``SENSITIVE_COLUMNS``, each non-empty cell value is
    passed through ``MappingStore.get_or_create`` with the appropriate
    generator. For columns listed in ``PATH_COLUMNS``, known hostnames are
    substituted within the path string. All other columns are passed through
    unchanged. Headers, row count, and non-sensitive values are preserved.

    Parameters
    ----------
    content:
        The raw CSV string.
    mapping:
        The :class:`MappingStore` to use for lookups and storage.
    generators:
        Optional pre-built generator dict. If ``None``, fresh generators are
        created. Pass shared generators from the orchestrator to avoid counter
        resets across files.
    """
    reader = csv.DictReader(io.StringIO(content))
    if reader.fieldnames is None:
        return content

    fieldnames: List[str] = list(reader.fieldnames)
    if generators is None:
        generators = _build_generators()

    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()

    for row in reader:
        new_row: Dict[str, str] = {}
        for col in fieldnames:
            value = row.get(col, "")

            if not value:
                # Empty cells are left unchanged
                new_row[col] = value
            elif col in SENSITIVE_COLUMNS:
                category = SENSITIVE_COLUMNS[col]
                gen = generators[category]

                if category == "hostnames" and "." in value and not value.replace(".", "").isdigit():
                    # FQDN detected: split into hostname and domain parts
                    new_row[col] = anonymize_fqdn(
                        value, mapping, generators["hostnames"], generators["domains"]
                    )
                elif category == "ip_addresses":
                    # A MAC address that landed in an IP column is handled as a
                    # MAC; everything else (single IP, IPv6, or a whitespace-/
                    # comma-separated list of IPs) is tokenized per-IP.
                    if _is_mac(value):
                        new_row[col] = mapping.get_or_create(
                            "mac_addresses", value, generators["mac_addresses"].generate
                        )
                    else:
                        new_row[col] = anonymize_ip_field(value, mapping, generators)
                elif category == "ipv6_addresses":
                    new_row[col] = mapping.get_or_create(
                        "ipv6_addresses", value, generators["ipv6_addresses"].generate
                    )
                elif category == "mac_addresses":
                    new_row[col] = mapping.get_or_create(
                        "mac_addresses", value, generators["mac_addresses"].generate
                    )
                else:
                    new_row[col] = mapping.get_or_create(
                        category, value, gen.generate
                    )
            elif col in PATH_COLUMNS:
                new_row[col] = _anonymize_path(value, mapping)
            else:
                new_row[col] = value

        writer.writerow(new_row)

    return output.getvalue()


def deanonymize_csv(content: str, mapping: MappingStore) -> str:
    """Parse a CSV string, reverse anonymized values, and return the de-anonymized CSV.

    For columns listed in ``SENSITIVE_COLUMNS``, each non-empty cell value is
    looked up via ``MappingStore.reverse_lookup``. If no reverse mapping
    exists the value is left unchanged. Path columns have anonymized hostnames
    reversed. All other columns pass through unchanged.
    """
    reader = csv.DictReader(io.StringIO(content))
    if reader.fieldnames is None:
        return content

    fieldnames: List[str] = list(reader.fieldnames)

    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()

    for row in reader:
        new_row: Dict[str, str] = {}
        for col in fieldnames:
            value = row.get(col, "")

            if not value:
                new_row[col] = value
            elif col in SENSITIVE_COLUMNS:
                category = SENSITIVE_COLUMNS[col]
                if category == "ip_addresses":
                    # Tokenize per-IP (handles single, whitespace-, and
                    # comma-separated values). Fall back to MAC lookup for a
                    # single MAC that was anonymized from an IP column.
                    restored = deanonymize_ip_field(value, mapping)
                    if restored == value:
                        mac_orig = mapping.reverse_lookup("mac_addresses", value)
                        if mac_orig is not None:
                            restored = mac_orig
                    new_row[col] = restored
                else:
                    original = mapping.reverse_lookup(category, value)
                    new_row[col] = original if original is not None else value
            elif col in PATH_COLUMNS:
                new_row[col] = _deanonymize_path(value, mapping)
            else:
                new_row[col] = value

        writer.writerow(new_row)

    return output.getvalue()
