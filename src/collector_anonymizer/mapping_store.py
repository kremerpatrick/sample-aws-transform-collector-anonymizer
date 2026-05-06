"""Mapping Store: Bidirectional mapping between original and anonymized values.

Manages persistent, category-keyed forward (original->anonymized) and reverse
(anonymized->original) mappings. Supports loading from and saving to JSON files
with metadata, and validates 1:1 bijection invariants.
"""

import hashlib
import json
import os
import stat
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Dict, List, Optional

from collector_anonymizer import __version__

# All supported mapping categories
CATEGORIES = [
    "hostnames",
    "ip_addresses",
    "ipv6_addresses",
    "server_ids",
    "database_names",
    "owner_names",
    "owner_emails",
    "owner_phones",
    "process_names",
    "service_accounts",
    "mac_addresses",
    "domains",
]


class MappingStore:
    """Bidirectional mapping store for anonymization.

    Maintains forward (original -> anonymized) and reverse (anonymized -> original)
    dictionaries for each category. Ensures consistency: the same original value
    always returns the same anonymized value within a category.
    """

    def __init__(self, path: Optional[Path] = None) -> None:
        """Load existing mapping from *path*, or start with empty maps.

        Parameters
        ----------
        path:
            Path to an existing mapping JSON file. If ``None`` or the file does
            not exist, the store starts empty with all categories initialised.
        """
        self._forward: Dict[str, Dict[str, str]] = {c: {} for c in CATEGORIES}
        self._reverse: Dict[str, Dict[str, str]] = {c: {} for c in CATEGORIES}
        self._created_at: str = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        self._updated_at: str = self._created_at

        if path is not None:
            p = Path(path)
            if p.exists():
                self._load(p)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_or_create(
        self, category: str, original: str, generator: Callable[[str], str]
    ) -> str:
        """Return the anonymized value for *original*, creating one if needed.

        If *original* already exists in the forward map for *category*, the
        previously stored anonymized value is returned. Otherwise *generator*
        is called with *original* to produce a new anonymized value, and both
        the forward and reverse entries are recorded.

        Parameters
        ----------
        category:
            One of the supported category names (e.g. ``"hostnames"``).
        original:
            The real, sensitive value.
        generator:
            A callable ``(original) -> anonymized`` used when no mapping exists.

        Returns
        -------
        str
            The anonymized replacement value.
        """
        if category not in self._forward:
            self._forward[category] = {}
            self._reverse[category] = {}

        fwd = self._forward[category]
        if original in fwd:
            return fwd[original]

        anonymized = generator(original)
        fwd[original] = anonymized
        self._reverse[category][anonymized] = original
        self._updated_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        return anonymized

    def reverse_lookup(self, category: str, anonymized: str) -> Optional[str]:
        """Return the original value for *anonymized*, or ``None``.

        Parameters
        ----------
        category:
            The mapping category to search.
        anonymized:
            The anonymized value to look up.

        Returns
        -------
        str or None
            The original value, or ``None`` if no mapping exists.
        """
        return self._reverse.get(category, {}).get(anonymized)

    def save(self, path: Path) -> None:
        """Persist the mapping store to a JSON file at *path*.

        The JSON structure contains three top-level keys:
        ``metadata``, ``forward``, and ``reverse``.

        The metadata includes a SHA-256 integrity hash computed over the
        forward and reverse mapping content. The file is written with
        restrictive permissions (owner read/write only, 0o600).
        """
        # Build the payload without the hash first
        forward_json = json.dumps(self._forward, sort_keys=True, ensure_ascii=False)
        reverse_json = json.dumps(self._reverse, sort_keys=True, ensure_ascii=False)
        integrity_hash = hashlib.sha256(
            (forward_json + reverse_json).encode("utf-8")
        ).hexdigest()

        data = {
            "metadata": {
                "created_at": self._created_at,
                "updated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "tool_version": __version__,
                "integrity_sha256": integrity_hash,
            },
            "forward": self._forward,
            "reverse": self._reverse,
        }
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")

        # Set restrictive file permissions (owner read/write only)
        try:
            os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)  # 0o600
        except OSError:
            pass  # Best-effort; may fail on some file systems

    def validate_consistency(self) -> List[str]:
        """Check 1:1 bijection invariants across all categories.

        Returns a list of human-readable error descriptions. An empty list
        means the mapping is consistent.

        Checks performed per category:
        1. Every forward entry ``original -> anonymized`` has a matching
           reverse entry ``anonymized -> original``.
        2. Every reverse entry ``anonymized -> original`` has a matching
           forward entry ``original -> anonymized``.
        3. No two distinct originals map to the same anonymized value
           (forward injectivity).
        4. No two distinct anonymized values map to the same original
           (reverse injectivity).
        """
        errors: List[str] = []

        for category in set(list(self._forward.keys()) + list(self._reverse.keys())):
            fwd = self._forward.get(category, {})
            rev = self._reverse.get(category, {})

            # Check forward -> reverse consistency
            for original, anonymized in fwd.items():
                if anonymized not in rev:
                    errors.append(
                        f"[{category}] Forward entry '{original}' -> '{anonymized}' "
                        f"has no corresponding reverse entry."
                    )
                elif rev[anonymized] != original:
                    errors.append(
                        f"[{category}] Forward entry '{original}' -> '{anonymized}' "
                        f"but reverse maps '{anonymized}' -> '{rev[anonymized]}'."
                    )

            # Check reverse -> forward consistency
            for anonymized, original in rev.items():
                if original not in fwd:
                    errors.append(
                        f"[{category}] Reverse entry '{anonymized}' -> '{original}' "
                        f"has no corresponding forward entry."
                    )
                elif fwd[original] != anonymized:
                    errors.append(
                        f"[{category}] Reverse entry '{anonymized}' -> '{original}' "
                        f"but forward maps '{original}' -> '{fwd[original]}'."
                    )

            # Check forward injectivity (no two originals share an anonymized value)
            seen_anon: Dict[str, str] = {}
            for original, anonymized in fwd.items():
                if anonymized in seen_anon and seen_anon[anonymized] != original:
                    errors.append(
                        f"[{category}] Collision: both '{seen_anon[anonymized]}' and "
                        f"'{original}' map to anonymized value '{anonymized}'."
                    )
                seen_anon[anonymized] = original

            # Check reverse injectivity (no two anonymized values share an original)
            seen_orig: Dict[str, str] = {}
            for anonymized, original in rev.items():
                if original in seen_orig and seen_orig[original] != anonymized:
                    errors.append(
                        f"[{category}] Collision: both '{seen_orig[original]}' and "
                        f"'{anonymized}' reverse-map to original value '{original}'."
                    )
                seen_orig[original] = anonymized

        return errors

    @property
    def categories(self) -> List[str]:
        """Return the list of category names with at least one mapping."""
        return [c for c in CATEGORIES if self._forward.get(c)]

    @property
    def forward(self) -> Dict[str, Dict[str, str]]:
        """Read-only access to the forward mapping dictionaries."""
        return self._forward

    @property
    def reverse(self) -> Dict[str, Dict[str, str]]:
        """Read-only access to the reverse mapping dictionaries."""
        return self._reverse

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _load(self, path: Path) -> None:
        """Load mapping data from a JSON file and verify integrity if a hash is present."""
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)

        metadata = data.get("metadata", {})
        self._created_at = metadata.get("created_at", self._created_at)
        self._updated_at = metadata.get("updated_at", self._updated_at)

        for category, entries in data.get("forward", {}).items():
            if category not in self._forward:
                self._forward[category] = {}
            self._forward[category].update(entries)

        for category, entries in data.get("reverse", {}).items():
            if category not in self._reverse:
                self._reverse[category] = {}
            self._reverse[category].update(entries)

        # Verify integrity hash if present
        stored_hash = metadata.get("integrity_sha256")
        if stored_hash:
            forward_json = json.dumps(self._forward, sort_keys=True, ensure_ascii=False)
            reverse_json = json.dumps(self._reverse, sort_keys=True, ensure_ascii=False)
            computed_hash = hashlib.sha256(
                (forward_json + reverse_json).encode("utf-8")
            ).hexdigest()
            if computed_hash != stored_hash:
                raise ValueError(
                    f"Mapping file integrity check failed for {path}. "
                    f"The file may have been tampered with or corrupted. "
                    f"Expected SHA-256: {stored_hash}, computed: {computed_hash}."
                )
