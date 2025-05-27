# Checkmate

A home-made command-line utility written in Go for calculating and validating file checksums across directories with support for MD5, SHA1, and SHA256 hash algorithms.

## Installation

### Prerequisites

- Go 1.16 or higher

## Usage

### Basic Syntax

```bash
checkmate -dir <directory> [-hash <hash>]
```

### Examples

#### Calculate checksums for all files in a directory
```bash
checkmate -dir /dir/to/files
```

#### Validate files against a reference MD5 hash
```bash
checkmate -dir ./Documents -hash d41d8cd98f00b204e9800998ecf8427e
```

#### Validate files against a reference SHA256 hash
```bash
checkmate -dir ~/Downloads -hash e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

### Command Line Options

| Flag | Description | Required |
|------|-------------|----------|
| `-dir` | Target directory to scan | Yes |
| `-hash` | Reference hash for validation | No |
| `-help` | Display usage information | No |

## Supported Hash Algorithms

The tool automatically detects hash type based on string length:

| Algorithm | Length | Example |
|-----------|--------|---------|
| MD5 | 32 characters | `d41d8cd98f00b204e9800998ecf8427e` |
| SHA1 | 40 characters | `da39a3ee5e6b4b0d3255bfef95601890afd80709` |
| SHA256 | 64 characters | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |


## Example Output

```
CHECKSUM VALIDATION RESULTS
Directory: /home/user/mario/Documents
Files processed: 3
Reference hash (SHA256): E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855
Scan completed: 2024-01-15 14:30:25

MATCH  FILE           SIZE    MODIFIED         MD5              SHA1             SHA256
-----  ----           ----    --------         ---              ----             ------
✓      document1.pdf  2.3 MB  2024-01-15 10:15 a1b2c3d4...f9e8d7c6 1a2b3c4d...9f8e7d6c e3b0c442...52b855
✗      document2.pdf  1.8 MB  2024-01-14 16:22 b2c3d4e5...e8d7c6f5 2b3c4d5e...8e7d6c5f f4c1c298...b7852b
-      document3.pdf  945 KB  2024-01-13 09:45 c3d4e5f6...d7c6f5e4 3c4d5e6f...7d6c5e4f 5fc1c149...52b855

COMPLETE HASHES:
document1.pdf
   Match: ✓
   MD5:    a1b2c3d4e5f6789...
   SHA1:   1a2b3c4d5e6f789...
   SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855

STATISTICS:
Files matching reference: 1/3
Validation status: Partial match detected
```

## Dependencies

This tool uses only Go standard library packages:

- `crypto/md5`, `crypto/sha1`, `crypto/sha256` for hash calculations
- `flag` for command-line argument parsing
- `filepath` for cross-platform path handling
- `text/tabwriter` for formatted output
