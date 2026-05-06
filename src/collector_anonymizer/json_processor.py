"""JSON Processor: anonymize and de-anonymize vmware_data_full.json files.

Handles the deeply nested VMware vCenter data structure where:
- Top-level keys are Server IDs (must be replaced)
- ``info.hostname`` and ``info.vm_name`` contain hostnames
- ``vm_name`` can appear at any nesting depth
- ``network[].ip_address`` contains IP addresses
"""

import json
from typing import Any, Dict

from collector_anonymizer.generators import (
    DomainGenerator,
    HostnameGenerator,
    IPAddressGenerator,
    IPv6AddressGenerator,
    MACAddressGenerator,
    ServerIDGenerator,
    anonymize_fqdn,
)
from collector_anonymizer.mapping_store import MappingStore

# ---------------------------------------------------------------------------
# Sensitive JSON field classification
# ---------------------------------------------------------------------------

# Fields whose values are hostnames or FQDNs
_HOSTNAME_KEYS = frozenset({"vm_name", "hostname", "dns_name", "host"})

# Fields whose values are IP addresses (IPv4 or IPv6)
_IP_KEYS = frozenset({"ip_address", "ipv4_address", "ipv6_address", "primary_ip_address"})

# Fields whose values are MAC addresses
_MAC_KEYS = frozenset({"mac_address"})

# Fields whose values are generic sensitive names (switch names, vCenter servers)
_GENERIC_HOSTNAME_KEYS = frozenset({"vi_sdk_server", "network", "switch"})

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _build_generators() -> Dict[str, object]:
    """Instantiate one generator per category used in JSON processing."""
    return {
        "server_ids": ServerIDGenerator(),
        "hostnames": HostnameGenerator(),
        "ip_addresses": IPAddressGenerator(),
        "ipv6_addresses": IPv6AddressGenerator(),
        "mac_addresses": MACAddressGenerator(),
        "domains": DomainGenerator(),
    }


def _is_ipv6(value: str) -> bool:
    """Return True if *value* looks like an IPv6 address."""
    import ipaddress as _ipaddress
    if ":" not in value:
        return False
    try:
        _ipaddress.IPv6Address(value)
        return True
    except ValueError:
        return False


def _anonymize_hostname_value(value: str, mapping: MappingStore, generators: Dict[str, object]) -> str:
    """Anonymize a hostname or FQDN value, splitting FQDNs into host + domain."""
    if "." in value and not value.replace(".", "").isdigit():
        return anonymize_fqdn(value, mapping, generators["hostnames"], generators["domains"])
    return mapping.get_or_create("hostnames", value, generators["hostnames"].generate)


def _anonymize_ip_value(value: str, mapping: MappingStore, generators: Dict[str, object]) -> str:
    """Anonymize an IP address, detecting IPv4 vs IPv6."""
    if _is_ipv6(value):
        return mapping.get_or_create("ipv6_addresses", value, generators["ipv6_addresses"].generate)
    return mapping.get_or_create("ip_addresses", value, generators["ip_addresses"].generate)


def _traverse_and_anonymize(obj: Any, mapping: MappingStore, generators: Dict[str, object]) -> Any:
    """Recursively traverse a JSON structure, anonymizing sensitive fields.

    Sensitive fields handled:
    - Hostname/FQDN keys: ``vm_name``, ``hostname``, ``dns_name``, ``host``
    - IP keys: ``ip_address``, ``ipv4_address``, ``ipv6_address``, ``primary_ip_address``
    - MAC keys: ``mac_address``
    - Generic hostname keys: ``vi_sdk_server``, ``network``, ``switch``

    All other keys and values are passed through unchanged.
    """
    if isinstance(obj, dict):
        result = {}
        for key, value in obj.items():
            if key in _HOSTNAME_KEYS and isinstance(value, str) and value.strip():
                result[key] = _anonymize_hostname_value(value.strip(), mapping, generators)
            elif key in _IP_KEYS and isinstance(value, str) and value.strip():
                result[key] = _anonymize_ip_value(value.strip(), mapping, generators)
            elif key in _MAC_KEYS and isinstance(value, str) and value.strip():
                result[key] = mapping.get_or_create(
                    "mac_addresses", value, generators["mac_addresses"].generate
                )
            elif key in _GENERIC_HOSTNAME_KEYS and isinstance(value, str) and value.strip():
                result[key] = _anonymize_hostname_value(value.strip(), mapping, generators)
            else:
                result[key] = _traverse_and_anonymize(value, mapping, generators)
        return result
    elif isinstance(obj, list):
        return [_traverse_and_anonymize(item, mapping, generators) for item in obj]
    else:
        return obj


def _deanonymize_value(value: str, mapping: MappingStore, categories: list[str]) -> str:
    """Try reverse lookup across multiple categories, return original or value as-is."""
    for cat in categories:
        original = mapping.reverse_lookup(cat, value)
        if original is not None:
            return original
    return value


def _traverse_and_deanonymize(obj: Any, mapping: MappingStore) -> Any:
    """Recursively traverse a JSON structure, reversing anonymization.

    Looks up anonymized values in the reverse mapping for the same sensitive
    fields handled during anonymization. Values without a reverse mapping
    are left unchanged.
    """
    if isinstance(obj, dict):
        result = {}
        for key, value in obj.items():
            if key in _HOSTNAME_KEYS and isinstance(value, str) and value.strip():
                result[key] = _deanonymize_value(value, mapping, ["hostnames", "domains"])
            elif key in _IP_KEYS and isinstance(value, str) and value.strip():
                result[key] = _deanonymize_value(value, mapping, ["ip_addresses", "ipv6_addresses"])
            elif key in _MAC_KEYS and isinstance(value, str) and value.strip():
                result[key] = _deanonymize_value(value, mapping, ["mac_addresses"])
            elif key in _GENERIC_HOSTNAME_KEYS and isinstance(value, str) and value.strip():
                result[key] = _deanonymize_value(value, mapping, ["hostnames", "domains"])
            else:
                result[key] = _traverse_and_deanonymize(value, mapping)
        return result
    elif isinstance(obj, list):
        return [_traverse_and_deanonymize(item, mapping) for item in obj]
    else:
        return obj


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def anonymize_json(
    content: str,
    mapping: MappingStore,
    generators: Dict[str, object] | None = None,
) -> str:
    """Anonymize a vmware_data_full.json string.

    Processing steps:
    1. Parse the JSON content.
    2. Replace top-level dictionary keys (Server IDs) with anonymized UUIDs.
    3. Recursively traverse each server entry to replace ``vm_name``,
       ``hostname``, ``ip_address``, and ``mac_address`` values.
    4. Return the anonymized JSON as a formatted string.
    """
    data = json.loads(content)
    if generators is None:
        generators = _build_generators()

    anonymized: Dict[str, Any] = {}
    for server_id, server_data in data.items():
        # Anonymize the top-level Server ID key
        anon_id = mapping.get_or_create(
            "server_ids", server_id, generators["server_ids"].generate
        )
        # Recursively anonymize the nested structure
        anon_data = _traverse_and_anonymize(server_data, mapping, generators)
        anonymized[anon_id] = anon_data

    return json.dumps(anonymized, indent=2)


def deanonymize_json(content: str, mapping: MappingStore) -> str:
    """Reverse anonymization on a vmware_data_full.json string.

    Processing steps:
    1. Parse the JSON content.
    2. Reverse top-level dictionary keys (Server IDs) using reverse lookup.
    3. Recursively traverse each server entry to reverse ``vm_name``,
       ``hostname``, and ``ip_address`` values.
    4. Return the de-anonymized JSON as a formatted string.
    """
    data = json.loads(content)

    deanonymized: Dict[str, Any] = {}
    for anon_id, server_data in data.items():
        # Reverse the top-level Server ID key
        original_id = mapping.reverse_lookup("server_ids", anon_id)
        key = original_id if original_id is not None else anon_id
        # Recursively de-anonymize the nested structure
        restored_data = _traverse_and_deanonymize(server_data, mapping)
        deanonymized[key] = restored_data

    return json.dumps(deanonymized, indent=2)
