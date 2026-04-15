# L7: Claude Code Installed via Piped Shell Script

- **Severity**: Low
- **Category**: Application — Supply Chain
- **File**: `Containerfile:72`

## Issue

Claude Code is installed by piping a remote script to bash: `curl -fsSL https://claude.ai/install.sh | ... bash`. This pattern is vulnerable to man-in-the-middle or compromised CDN attacks at build time.

## Impact

A compromised install script could inject malicious code into the container image. The `-fsSL` flags ensure the download is from HTTPS, reducing MITM risk, but there is no integrity verification (checksum, signature).

## Recommendation

If Claude Code publishes checksums or release signatures, verify them after download. Alternatively, download the installer in a separate step and verify its hash before executing.
