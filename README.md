# CompilerSigner — Code Signing Utility

`CompilerSigner` is a code-signing utility for developers who need to sign executables, DLLs, or installers using either **X.509 certificates using RSA cryptography**, **OpenSSL PKCS#12 certificates** or **Microsoft’s SignTool.exe**.

## Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [Commands](#commands)
  - [generate-keys](#generate-keys)
  - [generate-cert](#generate-cert)
  - [sign](#sign)
  - [verify](#verify)
  - [show-cert](#show-cert)
  - [export-cert](#export-cert)
- [Global Options](#global-options)
- [Examples](#examples)
- [File Formats](#file-formats)
- [Security Best Practices](#security-best-practices)

## Installation

### Prerequisites

- Rust 1.70 or later

### Building from Source

```bash
git clone <repository-url>
cd CompilerSigner
cargo build --release
```

The compiled binary will be located at `target/release/CompilerSigner.exe`.

Optionally, move it to a folder in your system `PATH`:
```bash
copy target\release\CompilerSigner.exe C:\Tools\
```

### Dependencies in Cargo.toml

```toml
[dependencies]
rsa = { version = "0.9.8", features = ["sha2"] }
sha2 = "0.10"
base64 = "0.21"
pkcs8 = "0.10"
x509-cert = { version = "0.2.5", features = ["builder"], default-features = false }
der = "0.7"
spki = "0.7"
chrono = { version = "0.4", default-features = false, features = ["clock"] }
rand = "0.8"
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
clap = { version = "4.4", features = ["derive"] }
const-oid = "0.9"
openssl = { version = "0.10", features = ["vendored"] }
thiserror = "1.0"
which = "6.0"
anyhow = "1.0"
```

## Quick Start

```bash
# 1. Generate RSA key pair
CompilerSigner generate-keys

# 2. Generate a self-signed certificate
CompilerSigner generate-cert --cn "Your Name" --org "Your Company" --country US

# 3. Sign a file with the certificate
CompilerSigner sign myprogram.exe --with-cert

# 4. Verify the signature
CompilerSigner verify myprogram.exe
```

## Usage Overview

```bash
CompilerSigner <COMMAND> [OPTIONS]
```

### Commands
| Command | Description |
|----------|-------------|
| `generate-keys` | Generate a new RSA key pair |
| `generate-cert` | Generate a self-signed certificate for code signing |
| `sign`          | Sign a file with certificate |
| `verify`        | Verify a file signature |
| `show-cert`     | Show certificate information |
| `export-cert`   | Export certificate to different format |
| `sign-tool`     | Use Microsoft's SignTool.exe to sign Windows binaries |
| `help`          | Shows the help message or the help of the given subcommand(s) |

## Parameters

### generate-keys

Generate a new RSA key pair for signing.

**Usage:**
```bash
CompilerSigner generate-keys [OPTIONS]
```

**Options:**

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--bits <BITS>` | integer | 2048 | Key size in bits (2048, 3072, or 4096 recommended) |
| `--key-dir <PATH>` | string | keys | Directory to store keys |

**Output Files:**
- `keys/private_key.pem` - Private key (keep secret!)
- `keys/public_key.pem` - Public key (can be shared)

**Examples:**

```bash
# Generate 2048-bit keys (default)
CompilerSigner generate-keys

# Generate 4096-bit keys for extra security
CompilerSigner generate-keys --bits 4096

# Generate keys in a custom directory
CompilerSigner generate-keys --key-dir /secure/location
```

---

### generate-cert

Generate a self-signed X.509 certificate for code signing.

**Usage:**
```bash
CompilerSigner generate-cert --cn <NAME> [OPTIONS]
```

**Required Options:**

| Option | Type | Description |
|--------|------|-------------|
| `--cn <NAME>` | string | Common Name (your name or organization) |

**Optional Arguments:**

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--org <ORG>` | string | - | Organization name |
| `--country <CODE>` | string | - | Two-letter country code (e.g., US, UK, CA) |
| `--days <DAYS>` | integer | 365 | Certificate validity period in days |
| `--format <FORMAT>` | string | pem | Output format: `pem`, `der`, `cer`, or `pfx` |
| `--password <PASS>` | string | - | Password for PFX format (required if format is pfx) |
| `--key-dir <PATH>` | string | keys | Directory containing keys |

**Output Files:**
- `keys/certificate.pem` (or `.der`/`.cer` depending on format)

**Examples:**

```bash
# Basic certificate
CompilerSigner generate-cert --cn "John Doe"

# Certificate with full details
CompilerSigner generate-cert \
  --cn "John Doe" \
  --org "Acme Corporation" \
  --country US \
  --days 730

# Generate certificate in DER format
CompilerSigner generate-cert --cn "John Doe" --format der

# Generate certificate in CER format (Windows-friendly)
CompilerSigner generate-cert --cn "John Doe" --format cer

# Generate 5-year certificate
CompilerSigner generate-cert --cn "John Doe" --days 1825
```

---

### sign

Sign a file with your private key and optionally embed a certificate.

**Usage:**
```bash
CompilerSigner sign <FILE> [OPTIONS]
```

**Required Arguments:**

| Argument | Type | Description |
|----------|------|-------------|
| `<FILE>` | path | File to sign (any file type) |

**Options:**

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--with-cert` | flag | false | Include certificate in signature |
| `--cert <PATH>` | path | keys/certificate.pem | Path to specific certificate file |
| `--key-dir <PATH>` | string | keys | Directory containing keys |

**Output:**
- Creates a `.sig` file alongside the signed file (e.g., `myprogram.exe.sig`)

**Signature File Contents:**
- File name and size
- SHA-256 hash
- RSA-PSS signature
- Certificate (if `--with-cert` is used)
- Certificate details (subject, issuer, validity)

**Examples:**

```bash
# Sign without certificate (key-only)
CompilerSigner sign myprogram.exe

# Sign with default certificate
CompilerSigner sign myprogram.exe --with-cert

# Sign with specific certificate
CompilerSigner sign myprogram.exe --with-cert --cert path/to/mycert.cer

# Sign multiple files
CompilerSigner sign file1.exe --with-cert
CompilerSigner sign file2.dll --with-cert
CompilerSigner sign document.pdf --with-cert
```

---

### verify

Verify a file's signature to ensure it hasn't been tampered with.

**Usage:**
```bash
CompilerSigner verify <FILE> [OPTIONS]
```

**Required Arguments:**

| Argument | Type | Description |
|----------|------|-------------|
| `<FILE>` | path | File to verify (must have a matching .sig file) |

**Options:**

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--key-dir <PATH>` | string | keys | Directory containing keys |

**Verification Process:**
1. Checks if the file hash matches the hash in the signature
2. Verifies the signature using either:
   - The embedded certificate (if present)
   - The public key from the key directory

**Output:**
- ✓ Success: "Signature is VALID"
- ✗ Failure: "Verification FAILED" with reason

**Examples:**

```bash
# Verify a signed file
CompilerSigner verify myprogram.exe

# Verify with keys from custom directory
CompilerSigner verify myprogram.exe --key-dir /secure/location
```

**Exit Codes:**
- `0` - Signature is valid
- `1` - Signature is invalid or verification failed

---

### show-cert

Display information about a certificate.

**Usage:**
```bash
CompilerSigner show-cert [OPTIONS]
```

**Options:**

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--cert <PATH>` | path | keys/certificate.pem | Path to certificate file |
| `--key-dir <PATH>` | string | keys | Directory containing default certificate |

**Displayed Information:**
- Subject (who the certificate belongs to)
- Issuer (who signed the certificate)
- Serial number
- Validity period (from/to dates)
- File location

**Examples:**

```bash
# Show default certificate
CompilerSigner show-cert

# Show specific certificate
CompilerSigner show-cert --cert path/to/certificate.cer

# Show certificate from custom key directory
CompilerSigner show-cert --key-dir /secure/location
```

---

### export-cert

Export a certificate to a different format.

**Usage:**
```bash
CompilerSigner export-cert --format <FORMAT> --output <FILE> [OPTIONS]
```

**Required Options:**

| Option | Type | Description |
|--------|------|-------------|
| `--format <FORMAT>` | string | Output format: `pem`, `der`, `cer`, or `pfx` |
| `--output <FILE>` | path | Output file path |

**Optional Arguments:**

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--password <PASS>` | string | - | Password for PFX format (required if format is pfx) |
| `--key-dir <PATH>` | string | keys | Directory containing source certificate |

**Examples:**

```bash
# Export to DER format
CompilerSigner export-cert --format der --output certificate.der

# Export to CER format (Windows)
CompilerSigner export-cert --format cer --output certificate.cer

# Export to PEM format
CompilerSigner export-cert --format pem --output certificate.pem

# Export to PFX (shows OpenSSL command)
CompilerSigner export-cert --format pfx --output certificate.pfx --password mypass
```

---

### sign-tool

Sign a file using **Microsoft’s SignTool.exe**.

```bash
CompilerSigner signtool --file <FILE> --cert <CERT_PATH> --password <PASSWORD> [OPTIONS]
```

| Option | Type | Description |
|------|------|-------------|
| `--file <PATH>` | path | File to sign (required) |
| `--signtool <PATH>` | path | Custom path to `signtool.exe` (if not in PATH) |
| `--cert <PATH>` | path | Path to `.pfx` / `.p12` certificate (required) |
| `--password <PASS>` | string | Certificate password (required) |
| `--timestamp <URL>` | URL | Timestamp server URL (e.g., `http://timestamp.digicert.com`) |
| `--hash <HASH>` | string | Hash algorithm (`sha256`, `sha1`, etc.). Default: `sha256` |
| `--dual` | flag | Enables dual signing (`/as` switch in SignTool) |

**Example:**
```bash
CompilerSigner signtool -f app.exe -c certs\mycert.pfx -p "password" -t http://timestamp.digicert.com -h sha256
```

---

## Global Options

These options can be used with any command:

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--key-dir <PATH>` | string | keys | Directory for storing/reading keys and certificates. Defaults to the `cwd/keys` |
| `-h, --help` | flag | - | Display help information |
| `-V, --version` | flag | - | Display version information |

**Examples:**

```bash
# Use custom key directory for all operations
CompilerSigner --key-dir /secure/keys generate-keys
CompilerSigner --key-dir /secure/keys generate-cert --cn "John Doe"
CompilerSigner --key-dir /secure/keys sign myprogram.exe --with-cert

# Get help for specific command
CompilerSigner sign --help
CompilerSigner generate-cert --help
```

---

## Examples

### Complete Workflow

```bash
# Step 1: Generate keys
CompilerSigner generate-keys --bits 4096

# Step 2: Create certificate
CompilerSigner generate-cert \
  --cn "John Doe" \
  --org "Acme Corp" \
  --country US \
  --days 730

# Step 3: Sign your programs
CompilerSigner sign myapp.exe --with-cert
CompilerSigner sign mylib.dll --with-cert
CompilerSigner sign installer.msi --with-cert

# Step 4: Verify signatures
CompilerSigner verify myapp.exe
CompilerSigner verify mylib.dll
CompilerSigner verify installer.msi

# Step 5: View certificate details
CompilerSigner show-cert
```

### Batch Signing
Batch:
```batch
@echo off
REM Sign all executables and DLLs in the current directory

for %%f in (*.exe *.dll) do (
    if exist "%%f" (
        echo Signing %%f...
        CompilerSigner sign "%%f" --with-cert
    )
)

echo.
echo All files have been processed.
pause
```

### Verify All Files
Windows Batch:
```batch
@echo off
REM Verify all signed files in the current directory

for %%f in (*.sig) do (
    set "file=%%~nf"
    echo Verifying %%~nf...
    CompilerSigner verify "%%~nf"
    if %ERRORLEVEL% EQU 0 (
        echo %%~nf is valid
    ) else (
        echo %%~nf verification failed
    )
)

echo.
echo All files have been processed.
pause
```

---

## File Formats

### Certificate Formats

| Format | Extension | Type | Description | Use Case |
|--------|-----------|------|-------------|----------|
| PEM | `.pem` | Text | Base64-encoded with headers | Default, cross-platform |
| DER | `.der` | Binary | Raw binary encoding | Compact storage |
| CER | `.cer` | Binary | Same as DER | Windows compatibility |
| PFX/P12 | `.pfx`, `.p12` | Binary | Password-protected bundle | Requires OpenSSL (shows command) |

### Signature Format

Signature files (`.sig`) are JSON format containing:

```json
{
  "file": "myprogram.exe",
  "size": 1234567,
  "sha256": "base64-encoded-hash",
  "signature": "base64-encoded-signature",
  "certificate": "base64-encoded-cert (optional)",
  "cert_subject": "CN=John Doe,O=Company",
  "cert_issuer": "CN=John Doe,O=Company",
  "cert_valid_from": "2024-01-01 00:00:00 UTC",
  "cert_valid_to": "2025-01-01 00:00:00 UTC"
}
```

---

## Security Best Practices

### Key Management

1. **Protect Private Keys**
   - Never share your `private_key.pem`
   - Store in a secure location with restricted permissions
   - Consider using encrypted storage
   - Back up to secure offline storage

2. **Key Size**
   - Use at least 2048-bit keys (default)
   - Consider 4096-bit for long-term security
   - Larger keys provide more security but slower signing

3. **Certificate Validity**
   - Don't make certificates valid for too long (1-2 years recommended)
   - Renew certificates regularly
   - Keep track of expiration dates

### Signing Process

1. **Always verify after signing**
   ```bash
   CompilerSigner sign myapp.exe --with-cert
   CompilerSigner verify myapp.exe
   ```

2. **Use certificates for distribution**
   - Include `--with-cert` when signing files for others
   - Certificate proves identity without sharing keys

3. **Keep signature files with binaries**
   - Distribute `.sig` files alongside your programs
   - Users can verify authenticity

### Verification

1. **Always verify downloads**
   - Verify signatures before running programs
   - Check certificate details match expected signer

2. **Automate verification**
   - Integrate verification into CI/CD pipelines
   - Script verification for multiple files

---

## Troubleshooting

### Common Issues

**Error: "Private key not found"**
- Solution: Run `CompilerSigner generate-keys` first

**Error: "Certificate not found"**
- Solution: Run `CompilerSigner generate-cert --cn "Your Name"` after generating keys

**Error: "Signature file not found"**
- Solution: Ensure the `.sig` file exists alongside the file you're verifying

**Error: "Verification FAILED: File has been modified"**
- Meaning: The file has been changed since it was signed
- Solution: This is expected if the file was modified; re-sign if changes are legitimate

**OpenSSL build errors**
- Solution: Update `Cargo.toml` with `default-features = false` for x509-cert and chrono

### Getting Help

```bash
# General help
CompilerSigner --help

# Command-specific help
CompilerSigner sign --help
CompilerSigner generate-cert --help
CompilerSigner verify --help
```

---
