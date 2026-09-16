"""CLI entry point for the Collector Anonymizer tool.

Provides ``build_parser()`` for argparse configuration and ``main()`` as the
primary entry point that configures logging, parses arguments, and dispatches
to the appropriate orchestrator function.
"""

import argparse
import logging
import os
import stat
import sys
from pathlib import Path

from collector_anonymizer.anonymizer import run_anonymize, run_deanonymize
from collector_anonymizer.zip_handler import MAX_TOTAL_UNCOMPRESSED_SIZE

# Bytes per gigabyte, used to convert the --max-uncompressed-size-gb flag.
_BYTES_PER_GB = 1024 ** 3
_DEFAULT_MAX_UNCOMPRESSED_GB = MAX_TOTAL_UNCOMPRESSED_SIZE / _BYTES_PER_GB


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser with anonymize/deanonymize subcommands."""
    parser = argparse.ArgumentParser(
        prog="collector-anonymizer",
        description="Anonymize or de-anonymize AWS Discovery Collector export files.",
        epilog=(
            "Examples:\n"
            "  collector-anonymizer anonymize --input export.zip\n"
            "  collector-anonymizer anonymize --input export.zip --output anon.zip --log-level DEBUG\n"
            "  collector-anonymizer deanonymize --input anon.zip --mapping mapping.json\n"
            "  collector-anonymizer deanonymize --input report.xlsx --mapping mapping.json --output restored.xlsx\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # --- anonymize subcommand ---
    anon_parser = subparsers.add_parser(
        "anonymize",
        help="Anonymize a Discovery Collector export zip file.",
    )
    anon_parser.add_argument(
        "--input",
        required=True,
        help="Path to the source Discovery Collector export zip file.",
    )
    anon_parser.add_argument(
        "--output",
        required=False,
        default=None,
        help="Path for the anonymized output file. Defaults to {input_name}_anonymized.zip.",
    )
    anon_parser.add_argument(
        "--max-uncompressed-size-gb",
        required=False,
        type=float,
        default=_DEFAULT_MAX_UNCOMPRESSED_GB,
        help=(
            "Maximum total uncompressed size of the input zip, in GB "
            f"(default: {_DEFAULT_MAX_UNCOMPRESSED_GB:g}). Raise this for large "
            "exports from trusted sources."
        ),
    )
    anon_parser.add_argument(
        "--log-level",
        required=False,
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging level (default: INFO).",
    )

    # --- deanonymize subcommand ---
    deanon_parser = subparsers.add_parser(
        "deanonymize",
        help="De-anonymize a previously anonymized file using a mapping.",
    )
    deanon_parser.add_argument(
        "--input",
        required=True,
        help="Path to the anonymized file (.zip or .xlsx).",
    )
    deanon_parser.add_argument(
        "--mapping",
        required=True,
        help="Path to the mapping JSON file produced during anonymization.",
    )
    deanon_parser.add_argument(
        "--output",
        required=False,
        default=None,
        help="Path for the de-anonymized output file. Defaults to {input_name}_deanonymized.{ext}.",
    )
    deanon_parser.add_argument(
        "--max-uncompressed-size-gb",
        required=False,
        type=float,
        default=_DEFAULT_MAX_UNCOMPRESSED_GB,
        help=(
            "Maximum total uncompressed size of the input zip, in GB "
            f"(default: {_DEFAULT_MAX_UNCOMPRESSED_GB:g}). Ignored for .xlsx "
            "input. Raise this for large exports from trusted sources."
        ),
    )
    deanon_parser.add_argument(
        "--log-level",
        required=False,
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging level (default: INFO).",
    )

    return parser


def _configure_logging(level_name: str) -> None:
    """Set up dual logging to stderr and ``anonymizer.log`` at the given level."""
    level = getattr(logging, level_name.upper(), logging.INFO)
    root = logging.getLogger()
    root.setLevel(level)

    formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")

    # File handler
    if not any(
        isinstance(h, logging.FileHandler)
        and h.baseFilename.endswith("anonymizer.log")
        for h in root.handlers
    ):
        file_handler = logging.FileHandler("anonymizer.log")
        file_handler.setLevel(level)
        file_handler.setFormatter(formatter)
        root.addHandler(file_handler)

        # Restrict log file permissions (owner read/write only)
        try:
            os.chmod("anonymizer.log", stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            pass  # Best-effort; may fail on some file systems

    # Stderr handler
    if not any(
        isinstance(h, logging.StreamHandler)
        and not isinstance(h, logging.FileHandler)
        for h in root.handlers
    ):
        stream_handler = logging.StreamHandler(sys.stderr)
        stream_handler.setLevel(level)
        stream_handler.setFormatter(formatter)
        root.addHandler(stream_handler)

    # Update existing handler levels
    for h in root.handlers:
        h.setLevel(level)


def main(argv: list[str] | None = None) -> int:
    """Parse arguments, configure logging, and dispatch to the orchestrator.

    Returns 0 on success, 1 on failure.
    """
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help()
        return 1

    _configure_logging(args.log_level)
    logger = logging.getLogger(__name__)

    try:
        max_uncompressed_size = int(args.max_uncompressed_size_gb * _BYTES_PER_GB)

        if args.command == "anonymize":
            input_path = Path(args.input)
            output_path = Path(args.output) if args.output else None
            logger.info("Starting anonymization of %s", input_path)
            result = run_anonymize(
                input_path,
                output_path,
                max_uncompressed_size=max_uncompressed_size,
            )
            if result == 0:
                print(
                    "\n"
                    "╔══════════════════════════════════════════════════════════════╗\n"
                    "║  SECURITY NOTICE                                           ║\n"
                    "║                                                            ║\n"
                    "║  The mapping file contains the COMPLETE original-to-       ║\n"
                    "║  anonymized value mapping. Treat it with the SAME          ║\n"
                    "║  sensitivity as the original data.                         ║\n"
                    "║                                                            ║\n"
                    "║  Do NOT share it alongside the anonymized export.          ║\n"
                    "╚══════════════════════════════════════════════════════════════╝",
                    file=sys.stderr,
                )
            return result

        elif args.command == "deanonymize":
            input_path = Path(args.input)
            mapping_path = Path(args.mapping)
            output_path = Path(args.output) if args.output else None
            logger.info("Starting de-anonymization of %s", input_path)
            return run_deanonymize(
                input_path,
                mapping_path,
                output_path,
                max_uncompressed_size=max_uncompressed_size,
            )

    except Exception:
        logger.exception("Unexpected error during %s", args.command)
        return 1

    return 0
