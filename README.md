# ssh-transfer

A Perl script to securely transfer files using SFTP with automatic verification and cleanup.

## Features

- **SFTP Transfer**: Securely transfers files to and from remote servers using SSH/SFTP protocol
  - Upload files from local to remote server
  - Download files from remote to local machine
- **Transfer Verification**: Automatically verifies that the file was successfully transferred by checking:
  - Remote file existence
  - File size match between local and remote files
  - Optional checksum verification (MD5, SHA1, SHA256) for additional data integrity
- **Automatic Cleanup**: Removes the source file after successful transfer and verification
- **Flexible Authentication**: Supports both password and SSH key-based authentication
- **Error Handling**: Comprehensive error handling and logging
- **Safe by Default**: Only removes source file after successful verification

## Requirements

- Perl 5.10 or higher
- Net::SFTP::Foreign module

## Installation

1. Clone this repository:
```bash
git clone https://github.com/ccaabrw/ssh-transfer.git
cd ssh-transfer
```

2. Install the required Perl module:

**Using CPAN:**
```bash
cpan Net::SFTP::Foreign
```

**On Debian/Ubuntu:**
```bash
sudo apt-get install libnet-sftp-foreign-perl
```

**On RedHat/CentOS/Fedora:**
```bash
sudo yum install perl-Net-SFTP-Foreign
```

## Usage

### Basic Usage

Transfer a file to remote server using password authentication:
```bash
perl sftp_transfer.pl -H server.example.com -u username -p password /path/to/local/file.txt /remote/path/file.txt
```

Download a file from remote server using password authentication:
```bash
perl sftp_transfer.pl -H server.example.com -u username -p password -d /remote/path/file.txt /path/to/local/file.txt
```

Transfer a file using SSH key authentication:
```bash
perl sftp_transfer.pl -H server.example.com -u username -k ~/.ssh/id_rsa /path/to/local/file.txt /remote/path/file.txt
```

### Command Line Arguments

```
Usage:
    sftp_transfer.pl [options] <source_file> <destination_file>

Required Arguments:
    source_file                   Source file path (local for upload, remote for download)
    destination_file              Destination file path (remote for upload, local for download)
    -H, --host <hostname>         Remote server hostname or IP
    -u, --username <username>     Username for authentication

Authentication (one required):
    -p, --password <password>     Password for authentication
    -k, --key-file <path>         Path to SSH private key file

Optional Arguments:
    -h, --help                    Show this help message and exit
    -d, --download                Download mode: transfer from remote to local (default: upload)
    -P, --port <port>             SSH/SFTP port (default: 22)
    --no-remove                   Do not remove source file after transfer (for testing)
    -c, --checksum <algorithm>    Enable checksum verification (md5, sha1, or sha256)
    -v, --verbose                 Enable verbose logging
```

### Examples

#### Example 1: Upload to a custom port
```bash
perl sftp_transfer.pl -H server.example.com -P 2222 -u username -p password /path/to/file.txt /remote/path/file.txt
```

#### Example 2: Download from remote server
```bash
perl sftp_transfer.pl -H server.example.com -u username -p password -d /remote/path/file.txt /path/to/local/file.txt
```

#### Example 3: Download without removing remote file
```bash
perl sftp_transfer.pl -H server.example.com -u username -k ~/.ssh/id_rsa -d --no-remove /remote/path/file.txt /local/file.txt
```

#### Example 4: Upload with verbose logging
```bash
perl sftp_transfer.pl -H server.example.com -u username -p password -v /path/to/file.txt /remote/path/file.txt
```

#### Example 5: Download with checksum verification
```bash
perl sftp_transfer.pl -H server.example.com -u username -p password -d -c sha256 /remote/path/file.txt /local/file.txt
```

#### Example 6: Upload with MD5 checksum verification
```bash
perl sftp_transfer.pl -H server.example.com -u username -k ~/.ssh/id_rsa -c md5 /path/to/file.txt /remote/path/file.txt
```

## How It Works

The script performs the following steps:

### Upload Mode (default)
1. **Connect**: Establishes an SFTP connection to the remote server using the provided credentials
2. **Transfer**: Uploads the local file to the specified remote path
3. **Verify**: Confirms the transfer was successful by:
   - Checking that the remote file exists
   - Comparing file sizes to ensure they match
   - Optionally comparing checksums (MD5, SHA1, or SHA256) for additional integrity verification
4. **Cleanup**: Removes the source file only if verification passes
5. **Report**: Provides detailed logging of all operations

### Download Mode (-d flag)
1. **Connect**: Establishes an SFTP connection to the remote server using the provided credentials
2. **Transfer**: Downloads the remote file to the specified local path
3. **Verify**: Confirms the transfer was successful by:
   - Checking that the local file exists
   - Comparing file sizes to ensure they match
   - Optionally comparing checksums (MD5, SHA1, or SHA256) for additional integrity verification
4. **Cleanup**: Removes the remote source file only if verification passes
5. **Report**: Provides detailed logging of all operations

## Security Considerations

- The script uses `StrictHostKeyChecking=no` for host key verification. In production environments, you should implement proper host key verification.
- Passwords provided on the command line may be visible in process listings. Using SSH key authentication is recommended.
- The script only removes the source file after successful verification to prevent data loss.

## Exit Codes

- `0`: Success - file transferred, verified, and removed
- `1`: Failure - see log messages for details

## License

MIT License

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.