# Collector Anonymizer

Anonymize sensitive data in AWS Discovery Collector export zip files so they can be shared with third parties (e.g., AWS migration teams) without exposing customer infrastructure details. De-anonymize the results after AWS Transform processing to restore original values.

## Disclaimer

You are solely responsible for reviewing the outputs of Collector Anonymizer for accuracy. AWS makes no representations or warranties about your use of the AWS Transform Discovery Tool Collector Anonymizer.

## Platform Support

The tool runs on macOS, Linux, and Windows. It is a pure Python CLI with no OS-specific dependencies. File permission hardening (mapping file restricted to owner-only access) is applied automatically on macOS and Linux. On Windows, the permission step is skipped gracefully.

## What It Anonymizes

| Category | Example Original | Example Anonymized |
|---|---|---|
| Hostnames & FQDNs | `PROD-WEB-01.corp.net` | `server-0001.domain-001.local` |
| IPv4 addresses | `192.168.1.10` | `10.1.0.10` (subnet-preserving) |
| IPv6 addresses | `2001:db8::1` | `fd00:a1b2:...` |
| Server IDs | `d-server-01a2b3c4d5e6` | `d-server-0001` (sequential) |
| MAC addresses | `00:50:56:aa:bb:cc` | `02:1f:0e:fc:62:c8` |
| Database names | `CustomerDB_Prod` | `database-0001` |
| Owner names/emails/phones | `John Smith` | `owner-0001` |
| Process names | `sqlservr.exe` | `process-0001` |
| Service accounts | `DOMAIN\svc_sql` | `svc-account-0001` |

Subnet relationships are preserved: two IPs on the same /24 stay on the same anonymized /24.

## Install

```bash
pip install -e ".[dev]"
```

Requires Python 3.9+. The only runtime dependency is `openpyxl`.

## Usage

### Anonymize a Discovery Collector export

```bash
collector-anonymizer anonymize --input export.zip
```

Produces `export_anonymized.zip` and `SENSITIVE_export_mapping.json`.

### De-anonymize a zip

```bash
collector-anonymizer deanonymize --input export_anonymized.zip --mapping SENSITIVE_export_mapping.json
```

### De-anonymize an AWS Transform Excel output

```bash
collector-anonymizer deanonymize --input analysis.xlsx --mapping SENSITIVE_export_mapping.json
```

### Options

```
--output PATH     Custom output file path (default: auto-named)
--log-level LEVEL DEBUG, INFO, WARNING, or ERROR (default: INFO)
```

## How It Works

1. Reads the Discovery Collector zip (CSV + JSON files in `mpa_exports/` and `full_exports/`)
2. Validates zip structure and performs safety checks (path traversal, zip bomb, size limits)
3. Identifies sensitive fields by column name (CSV) and JSON key name, not by inspecting cell values
4. Replaces sensitive values using consistent, category-specific generators
4. Writes an anonymized zip preserving the original directory structure
5. Saves a bidirectional mapping file (JSON) with a `SENSITIVE_` prefix for later de-anonymization
6. Sets restrictive file permissions (0600) on the mapping file (macOS/Linux)
7. Validates mapping consistency (1:1 bijection) and integrity (SHA-256 hash) before completing

The mapping file is required for de-anonymization. Keep it secure.

## Security Features

The tool includes the following security hardening measures, informed by a STRIDE threat model:

- **Zip bomb protection.** Input zip files are validated for excessive compression ratios (>100:1), total uncompressed size (>2 GB), and entry count (>10,000).
- **Path traversal prevention.** Zip entries with absolute paths, `..` directory traversal sequences, or paths that escape the extraction root are rejected.
- **Salted hashing for MAC and IPv6.** MAC and IPv6 anonymization uses per-run random salts (`os.urandom`) combined with the original value, preventing offline brute-force reversal without access to the mapping file.
- **Mapping file integrity.** A SHA-256 hash of the mapping content is stored in the file metadata. On load, the hash is verified and a `ValueError` is raised if the file has been tampered with or corrupted.
- **Restrictive file permissions.** The mapping file is written with owner-only read/write permissions (0600) on macOS and Linux. On Windows, this step is skipped gracefully.
- **Sensitive file naming.** The mapping file uses a `SENSITIVE_` prefix by default to reduce the risk of accidental sharing alongside the anonymized export.
- **Log sanitization.** Error handlers do not include stack traces (`exc_info`) that could leak original sensitive values into log files.
- **Security warning.** A prominent warning is displayed after anonymization reminding the user not to share the mapping file with the anonymized export.

## Security Note

The mapping file contains the complete original-to-anonymized value mapping. Treat it with the same sensitivity as the original data. Do not share it alongside the anonymized export. The `SENSITIVE_` prefix in the filename serves as a visual reminder of this requirement.

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This library is licensed under the MIT-0 License. See the [LICENSE](LICENSE) file.
