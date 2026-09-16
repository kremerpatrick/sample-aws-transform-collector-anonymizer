"""Orchestrator: coordinates anonymization and de-anonymization workflows.

Provides ``run_anonymize`` and ``run_deanonymize`` entry points that wire
together the ZIP handler, CSV/JSON processors, Excel de-anonymizer, and
mapping store into complete pipelines with logging and error handling.
"""

import logging
import os
import stat
import time
import zipfile
from pathlib import Path
from typing import Dict

from collector_anonymizer.csv_processor import anonymize_csv, deanonymize_csv, _build_generators as build_csv_generators
from collector_anonymizer.excel_processor import deanonymize_excel
from collector_anonymizer.json_processor import anonymize_json, deanonymize_json
from collector_anonymizer.mapping_store import MappingStore
from collector_anonymizer.zip_handler import read_zip, validate_zip_structure, write_zip

logger = logging.getLogger(__name__)


def _setup_logging() -> None:
    """Configure dual logging to stderr and ``anonymizer.log`` if not already set up."""
    root = logging.getLogger()
    # Avoid adding duplicate handlers on repeated calls
    if any(
        isinstance(h, logging.FileHandler) and h.baseFilename.endswith("anonymizer.log")
        for h in root.handlers
    ):
        return

    formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")

    file_handler = logging.FileHandler("anonymizer.log")
    file_handler.setFormatter(formatter)
    root.addHandler(file_handler)

    # Restrict log file permissions (owner read/write only)
    try:
        os.chmod("anonymizer.log", stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass  # Best-effort; may fail on some file systems

    # Ensure at least one stderr handler exists
    if not any(
        isinstance(h, logging.StreamHandler) and not isinstance(h, logging.FileHandler)
        for h in root.handlers
    ):
        stream_handler = logging.StreamHandler()
        stream_handler.setFormatter(formatter)
        root.addHandler(stream_handler)


def _default_output_path(input_path: Path, suffix: str) -> Path:
    """Derive a default output path by inserting *suffix* before the extension."""
    return input_path.parent / f"{input_path.stem}{suffix}{input_path.suffix}"


def _default_mapping_path(output_path: Path, input_path: Path) -> Path:
    """Derive the default mapping JSON path alongside the output zip.

    Uses a ``SENSITIVE_`` prefix to clearly mark the file as containing
    sensitive data that must not be shared with the anonymized export.
    """
    return output_path.parent / f"SENSITIVE_{input_path.stem}_mapping.json"



def run_anonymize(
    input_path: Path,
    output_path: Path | None = None,
    mapping_path: Path | None = None,
    max_uncompressed_size: int | None = None,
) -> int:
    """Full anonymization pipeline. Returns 0 on success, 1 on failure.

    Steps:
    1. Validate input file exists and is a valid zip.
    2. Load or create a MappingStore.
    3. Read zip contents.
    4. Route each file to the appropriate processor (CSV / JSON / passthrough).
    5. Write anonymized zip.
    6. Save mapping.
    7. Run consistency validation.
    8. Log summary statistics.
    """
    _setup_logging()
    start_time = time.time()

    input_path = Path(input_path)

    # --- Fail fast: input validation ---
    if not input_path.exists():
        logger.error("Input file not found: %s", input_path)
        return 1

    if not zipfile.is_zipfile(input_path):
        logger.error("Not a valid zip file: %s", input_path)
        return 1

    # --- Resolve output and mapping paths ---
    if output_path is None:
        output_path = _default_output_path(input_path, "_anonymized")
    else:
        output_path = Path(output_path)

    if mapping_path is None:
        mapping_path = _default_mapping_path(output_path, input_path)
    else:
        mapping_path = Path(mapping_path)

    # --- Load or create mapping store ---
    if mapping_path.exists():
        logger.info("Loading existing mapping from %s", mapping_path)
        mapping = MappingStore(path=mapping_path)
    else:
        mapping = MappingStore()

    # --- Read zip ---
    read_kwargs = (
        {} if max_uncompressed_size is None
        else {"max_total_uncompressed_size": max_uncompressed_size}
    )
    try:
        files = read_zip(input_path, **read_kwargs)
    except (FileNotFoundError, zipfile.BadZipFile, ValueError) as exc:
        logger.error("Failed to read zip: %s", exc)
        return 1

    # --- Validate structure (warn only) ---
    warnings = validate_zip_structure(files)
    for w in warnings:
        logger.warning(w)

    # --- Process files ---
    anonymized_files: Dict[str, bytes] = {}
    files_processed = 0
    files_skipped = 0

    # Build generators once so counters persist across all files
    shared_generators = build_csv_generators()

    for filepath, content_bytes in files.items():
        lower = filepath.lower()
        try:
            if lower.endswith(".csv"):
                content_str = content_bytes.decode("utf-8")
                result = anonymize_csv(content_str, mapping, generators=shared_generators)
                anonymized_files[filepath] = result.encode("utf-8")
                files_processed += 1
            elif lower.endswith(".json"):
                content_str = content_bytes.decode("utf-8")
                result = anonymize_json(content_str, mapping, generators=shared_generators)
                anonymized_files[filepath] = result.encode("utf-8")
                files_processed += 1
            else:
                # Pass through unchanged
                anonymized_files[filepath] = content_bytes
                files_processed += 1
        except Exception:
            logger.error("Error processing file '%s', skipping", filepath)
            files_skipped += 1
            # Continue processing remaining files

    # --- Write output zip ---
    write_zip(output_path, anonymized_files)
    logger.info("Anonymized zip written to %s", output_path)

    # --- Save mapping ---
    mapping.save(mapping_path)
    logger.info("Mapping saved to %s", mapping_path)
    logger.warning(
        "SECURITY: The mapping file '%s' contains sensitive data. "
        "Do NOT share it alongside the anonymized export. "
        "Treat it with the same sensitivity as the original data.",
        mapping_path.name,
    )

    # --- Consistency validation ---
    errors = mapping.validate_consistency()
    if errors:
        for err in errors:
            logger.error("Consistency violation: %s", err)
        return 1

    # --- Summary ---
    elapsed = time.time() - start_time
    category_counts = {
        cat: len(mapping.forward.get(cat, {})) for cat in mapping.categories
    }
    logger.info(
        "Anonymization complete: %d files processed, %d skipped, %.2fs elapsed",
        files_processed,
        files_skipped,
        elapsed,
    )
    for cat, count in category_counts.items():
        logger.info("  %s: %d values anonymized", cat, count)

    return 0



def run_deanonymize(
    input_path: Path,
    mapping_path: Path,
    output_path: Path | None = None,
    max_uncompressed_size: int | None = None,
) -> int:
    """Full de-anonymization pipeline (zip or xlsx). Returns 0 on success, 1 on failure.

    Detects input type by extension and routes to the appropriate de-anonymizer.
    """
    _setup_logging()
    start_time = time.time()

    input_path = Path(input_path)
    mapping_path = Path(mapping_path)

    # --- Fail fast: input validation ---
    if not input_path.exists():
        logger.error("Input file not found: %s", input_path)
        return 1

    if not mapping_path.exists():
        logger.error("Mapping file not found: %s", mapping_path)
        return 1

    # --- Load mapping ---
    try:
        mapping = MappingStore(path=mapping_path)
    except ValueError as exc:
        logger.error("Mapping integrity check failed: %s", exc)
        return 1
    except Exception:
        logger.error("Failed to load mapping file: %s", mapping_path)
        return 1

    lower = str(input_path).lower()

    if lower.endswith(".zip"):
        return _deanonymize_zip(
            input_path, mapping, output_path, start_time, max_uncompressed_size
        )
    elif lower.endswith(".xlsx"):
        return _deanonymize_excel(input_path, mapping, output_path, start_time)
    else:
        logger.error(
            "Unsupported input file type: %s (expected .zip or .xlsx)", input_path
        )
        return 1


def _deanonymize_zip(
    input_path: Path,
    mapping: MappingStore,
    output_path: Path | None,
    start_time: float,
    max_uncompressed_size: int | None = None,
) -> int:
    """De-anonymize a zip file."""
    if not zipfile.is_zipfile(input_path):
        logger.error("Not a valid zip file: %s", input_path)
        return 1

    if output_path is None:
        output_path = _default_output_path(input_path, "_deanonymized")
    else:
        output_path = Path(output_path)

    read_kwargs = (
        {} if max_uncompressed_size is None
        else {"max_total_uncompressed_size": max_uncompressed_size}
    )
    try:
        files = read_zip(input_path, **read_kwargs)
    except (FileNotFoundError, zipfile.BadZipFile, ValueError) as exc:
        logger.error("Failed to read zip: %s", exc)
        return 1

    deanonymized_files: Dict[str, bytes] = {}
    files_processed = 0
    files_skipped = 0

    for filepath, content_bytes in files.items():
        lower_fp = filepath.lower()
        try:
            if lower_fp.endswith(".csv"):
                content_str = content_bytes.decode("utf-8")
                result = deanonymize_csv(content_str, mapping)
                deanonymized_files[filepath] = result.encode("utf-8")
                files_processed += 1
            elif lower_fp.endswith(".json"):
                content_str = content_bytes.decode("utf-8")
                result = deanonymize_json(content_str, mapping)
                deanonymized_files[filepath] = result.encode("utf-8")
                files_processed += 1
            else:
                deanonymized_files[filepath] = content_bytes
                files_processed += 1
        except Exception:
            logger.error(
                "Error de-anonymizing file '%s', skipping", filepath
            )
            files_skipped += 1

    write_zip(output_path, deanonymized_files)

    elapsed = time.time() - start_time
    logger.info(
        "De-anonymization complete: %d files processed, %d skipped, %.2fs elapsed",
        files_processed,
        files_skipped,
        elapsed,
    )
    logger.info("Output written to %s", output_path)
    return 0


def _deanonymize_excel(
    input_path: Path,
    mapping: MappingStore,
    output_path: Path | None,
    start_time: float,
) -> int:
    """De-anonymize an Excel file."""
    if output_path is None:
        output_path = _default_output_path(input_path, "_deanonymized")
    else:
        output_path = Path(output_path)

    try:
        replacement_count = deanonymize_excel(input_path, output_path, mapping)
    except Exception:
        logger.error("Failed to de-anonymize Excel file: %s", input_path)
        return 1

    elapsed = time.time() - start_time
    logger.info(
        "Excel de-anonymization complete: %d replacements, %.2fs elapsed",
        replacement_count,
        elapsed,
    )
    logger.info("Output written to %s", output_path)
    return 0
