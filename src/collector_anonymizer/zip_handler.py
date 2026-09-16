"""ZIP file handling for reading, writing, and validating Discovery Export archives."""

import logging
import os
import zipfile
from pathlib import Path
from typing import Dict, List

logger = logging.getLogger(__name__)

# Safety limits for zip extraction
MAX_TOTAL_UNCOMPRESSED_SIZE = 2 * 1024 * 1024 * 1024  # 2 GB
MAX_COMPRESSION_RATIO = 100  # reject entries with ratio > 100:1
MAX_ENTRY_COUNT = 10_000


def _validate_zip_entry(info: zipfile.ZipInfo) -> List[str]:
    """Validate a single zip entry for path traversal and zip bomb indicators.

    Returns a list of error messages. Empty means the entry is safe.
    """
    errors: List[str] = []
    name = info.filename

    # Path traversal checks
    if name.startswith("/") or name.startswith("\\"):
        errors.append(f"Absolute path rejected: {name}")
    if ".." in name.split("/") or ".." in name.split("\\"):
        errors.append(f"Directory traversal rejected: {name}")
    # Normalise and re-check
    resolved = os.path.normpath(name)
    if resolved.startswith(".."):
        errors.append(f"Normalised path escapes root: {name} -> {resolved}")

    # Compression ratio check (zip bomb indicator)
    if info.compress_size > 0:
        ratio = info.file_size / info.compress_size
        if ratio > MAX_COMPRESSION_RATIO:
            errors.append(
                f"Suspicious compression ratio ({ratio:.0f}:1) for {name}. "
                f"Compressed: {info.compress_size}, uncompressed: {info.file_size}."
            )

    return errors


def read_zip(
    path: Path,
    max_total_uncompressed_size: int = MAX_TOTAL_UNCOMPRESSED_SIZE,
) -> Dict[str, bytes]:
    """Extract all files from a zip archive with safety validation.

    Validates each entry for path traversal sequences, excessive compression
    ratios (zip bomb indicator), and total uncompressed size limits.

    Args:
        path: Path to the zip file.
        max_total_uncompressed_size: Maximum allowed total uncompressed size in
            bytes. Defaults to ``MAX_TOTAL_UNCOMPRESSED_SIZE`` (2 GB). Raise this
            for large exports from trusted sources.

    Returns:
        Dictionary mapping internal file paths to their content as bytes.

    Raises:
        FileNotFoundError: If the file does not exist.
        zipfile.BadZipFile: If the file is not a valid zip archive.
        ValueError: If any entry fails safety validation.
    """
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Input file not found: {path}")

    if not zipfile.is_zipfile(path):
        raise zipfile.BadZipFile(f"Not a valid zip file: {path}")

    files: Dict[str, bytes] = {}
    with zipfile.ZipFile(path, "r") as zf:
        entries = zf.infolist()

        # Entry count check
        if len(entries) > MAX_ENTRY_COUNT:
            raise ValueError(
                f"Zip contains {len(entries)} entries, exceeding the "
                f"safety limit of {MAX_ENTRY_COUNT}."
            )

        # Total uncompressed size check
        total_size = sum(info.file_size for info in entries)
        if total_size > max_total_uncompressed_size:
            raise ValueError(
                f"Total uncompressed size ({total_size:,} bytes) exceeds the "
                f"safety limit of {max_total_uncompressed_size:,} bytes."
            )

        for info in entries:
            # Skip directories
            if info.is_dir():
                continue

            # Per-entry safety validation
            entry_errors = _validate_zip_entry(info)
            if entry_errors:
                raise ValueError(
                    f"Unsafe zip entry '{info.filename}': "
                    + "; ".join(entry_errors)
                )

            files[info.filename] = zf.read(info.filename)
    return files


def write_zip(path: Path, files: Dict[str, bytes]) -> None:
    """Write a dictionary of files to a new zip archive.

    Creates parent directories if they do not exist.

    Args:
        path: Output path for the zip file.
        files: Dictionary mapping internal file paths to content bytes.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        for internal_path, content in files.items():
            zf.writestr(internal_path, content)


def validate_zip_structure(files: Dict[str, bytes]) -> List[str]:
    """Validate that the zip contains expected Discovery Export directories.

    Checks for the presence of files under ``mpa_exports/`` and
    ``full_exports/`` directories.

    Args:
        files: Dictionary of internal file paths to content bytes.

    Returns:
        List of warning messages. Empty if structure is valid.
    """
    warnings: List[str] = []
    has_mpa = any(p.startswith("mpa_exports/") for p in files)
    has_full = any(p.startswith("full_exports/") for p in files)

    if not has_mpa and not has_full:
        warnings.append(
            "ZIP does not contain expected 'mpa_exports/' or 'full_exports/' directories."
        )
    else:
        if not has_mpa:
            warnings.append("ZIP does not contain 'mpa_exports/' directory.")
        if not has_full:
            warnings.append("ZIP does not contain 'full_exports/' directory.")

    return warnings
