# ssh_copy

A Python script to securely transfer files using SFTP with automatic verification and cleanup.

## Features

- **SFTP Transfer**: Securely transfers files to remote servers using SSH/SFTP protocol
- **Transfer Verification**: Automatically verifies that the file was successfully transferred by checking:
  - Remote file existence
  - File size match between local and remote files
- **Automatic Cleanup**: Removes the source file after successful transfer and verification
- **Flexible Authentication**: Supports both password and SSH key-based authentication
- **Error Handling**: Comprehensive error handling and logging
- **Safe by Default**: Only removes source file after successful verification

## Requirements

- Python 3.6 or higher
- paramiko library

## Installation

1. Clone this repository:
```bash
git clone https://github.com/ccaabrw/ssh_copy.git
cd ssh_copy
```

2. Install the required dependencies:
```bash
pip install -r requirements.txt
```

## Usage

### Basic Usage

Transfer a file using password authentication:
```bash
python sftp_transfer.py -H server.example.com -u username -p password /path/to/local/file.txt /remote/path/file.txt
```

Transfer a file using SSH key authentication:
```bash
python sftp_transfer.py -H server.example.com -u username -k ~/.ssh/id_rsa /path/to/local/file.txt /remote/path/file.txt
```

### Command Line Arguments

```
positional arguments:
  local_file            Path to the local file to transfer
  remote_file           Destination path on the remote server

required arguments:
  -H HOST, --host HOST          Remote server hostname or IP
  -u USERNAME, --username USERNAME
                                Username for authentication

optional arguments:
  -h, --help                    Show this help message and exit
  -P PORT, --port PORT          SSH/SFTP port (default: 22)
  -p PASSWORD, --password PASSWORD
                                Password for authentication
  -k KEY_FILE, --key-file KEY_FILE
                                Path to SSH private key file
  --no-remove                   Do not remove source file after transfer (for testing)
  -v, --verbose                 Enable verbose logging
```

### Examples

#### Example 1: Transfer to a custom port
```bash
python sftp_transfer.py -H server.example.com -P 2222 -u username -p password /path/to/file.txt /remote/path/file.txt
```

#### Example 2: Test without removing source file
```bash
python sftp_transfer.py -H server.example.com -u username -k ~/.ssh/id_rsa --no-remove /path/to/file.txt /remote/path/file.txt
```

#### Example 3: Verbose logging
```bash
python sftp_transfer.py -H server.example.com -u username -p password -v /path/to/file.txt /remote/path/file.txt
```

## How It Works

The script performs the following steps:

1. **Connect**: Establishes an SFTP connection to the remote server using the provided credentials
2. **Transfer**: Uploads the local file to the specified remote path
3. **Verify**: Confirms the transfer was successful by:
   - Checking that the remote file exists
   - Comparing file sizes to ensure they match
4. **Cleanup**: Removes the source file only if verification passes
5. **Report**: Provides detailed logging of all operations

## Security Considerations

- The script uses `paramiko.AutoAddPolicy()` for host key verification. In production environments, you should implement proper host key verification.
- Passwords provided on the command line may be visible in process listings. Using SSH key authentication is recommended.
- The script only removes the source file after successful verification to prevent data loss.

## Exit Codes

- `0`: Success - file transferred, verified, and removed
- `1`: Failure - see log messages for details

## License

MIT License

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.