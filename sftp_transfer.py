#!/usr/bin/env python3
"""
SFTP File Transfer Script

This script transfers a file to a remote server using SFTP,
verifies the transfer was successful, and removes the source file.
"""

import argparse
import os
import sys
import logging
from pathlib import Path

try:
    import paramiko
except ImportError:
    print("Error: paramiko library is required. Install it with: pip install paramiko")
    sys.exit(1)


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class SFTPTransfer:
    """Handle SFTP file transfer operations."""
    
    def __init__(self, hostname, port, username, password=None, key_file=None):
        """
        Initialize SFTP connection parameters.
        
        Args:
            hostname: Remote server hostname or IP
            port: SSH/SFTP port (default 22)
            username: Username for authentication
            password: Password for authentication (optional)
            key_file: Path to private key file for authentication (optional)
        """
        self.hostname = hostname
        self.port = port
        self.username = username
        self.password = password
        self.key_file = key_file
        self.client = None
        self.sftp = None
    
    def connect(self):
        """Establish SFTP connection to remote server."""
        try:
            logger.info(f"Connecting to {self.hostname}:{self.port} as {self.username}")
            
            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            # Prepare connection parameters
            connect_kwargs = {
                'hostname': self.hostname,
                'port': self.port,
                'username': self.username,
            }
            
            # Add authentication method
            if self.key_file:
                logger.info(f"Using key file: {self.key_file}")
                connect_kwargs['key_filename'] = self.key_file
            elif self.password:
                logger.info("Using password authentication")
                connect_kwargs['password'] = self.password
            else:
                logger.error("No authentication method provided (password or key file)")
                return False
            
            self.client.connect(**connect_kwargs)
            self.sftp = self.client.open_sftp()
            logger.info("SFTP connection established")
            return True
            
        except Exception as e:
            logger.error(f"Failed to connect: {e}")
            return False
    
    def transfer_file(self, local_path, remote_path):
        """
        Transfer a file to the remote server.
        
        Args:
            local_path: Path to local file
            remote_path: Destination path on remote server
            
        Returns:
            bool: True if transfer successful, False otherwise
        """
        try:
            if not os.path.exists(local_path):
                logger.error(f"Local file not found: {local_path}")
                return False
            
            local_size = os.path.getsize(local_path)
            logger.info(f"Transferring {local_path} ({local_size} bytes) to {remote_path}")
            
            # Create remote directory if it doesn't exist
            remote_dir = os.path.dirname(remote_path)
            if remote_dir:
                try:
                    self.sftp.stat(remote_dir)
                except FileNotFoundError:
                    logger.info(f"Creating remote directory: {remote_dir}")
                    self._mkdir_recursive(remote_dir)
            
            # Transfer the file
            self.sftp.put(local_path, remote_path)
            logger.info("File transfer completed")
            return True
            
        except Exception as e:
            logger.error(f"File transfer failed: {e}")
            return False
    
    def _mkdir_recursive(self, remote_path):
        """Create remote directory recursively."""
        parts = remote_path.split('/')
        current_path = ''
        
        for part in parts:
            if not part:
                current_path = '/'
                continue
            
            current_path = os.path.join(current_path, part)
            try:
                self.sftp.stat(current_path)
            except FileNotFoundError:
                self.sftp.mkdir(current_path)
    
    def verify_transfer(self, local_path, remote_path):
        """
        Verify that the file was transferred successfully.
        
        Checks:
        1. Remote file exists
        2. File sizes match
        
        Args:
            local_path: Path to local file
            remote_path: Path to remote file
            
        Returns:
            bool: True if verification successful, False otherwise
        """
        try:
            logger.info("Verifying file transfer...")
            
            # Check if remote file exists
            try:
                remote_stat = self.sftp.stat(remote_path)
            except FileNotFoundError:
                logger.error(f"Remote file not found: {remote_path}")
                return False
            
            # Compare file sizes
            local_size = os.path.getsize(local_path)
            remote_size = remote_stat.st_size
            
            logger.info(f"Local file size: {local_size} bytes")
            logger.info(f"Remote file size: {remote_size} bytes")
            
            if local_size != remote_size:
                logger.error("File sizes do not match!")
                return False
            
            logger.info("✓ File transfer verified successfully")
            return True
            
        except Exception as e:
            logger.error(f"Verification failed: {e}")
            return False
    
    def close(self):
        """Close SFTP and SSH connections."""
        if self.sftp:
            self.sftp.close()
        if self.client:
            self.client.close()
        logger.info("Connection closed")


def remove_source_file(file_path):
    """
    Remove the source file after successful transfer.
    
    Args:
        file_path: Path to file to remove
        
    Returns:
        bool: True if removal successful, False otherwise
    """
    try:
        logger.info(f"Removing source file: {file_path}")
        os.remove(file_path)
        logger.info("✓ Source file removed successfully")
        return True
    except Exception as e:
        logger.error(f"Failed to remove source file: {e}")
        return False


def main():
    """Main entry point for the script."""
    parser = argparse.ArgumentParser(
        description='Transfer a file using SFTP, verify transfer, and remove source file',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Transfer using password authentication
  %(prog)s -H server.example.com -u username -p password /path/to/file.txt /remote/path/file.txt
  
  # Transfer using SSH key
  %(prog)s -H server.example.com -u username -k ~/.ssh/id_rsa /path/to/file.txt /remote/path/file.txt
  
  # Transfer to a different port
  %(prog)s -H server.example.com -P 2222 -u username -p password /path/to/file.txt /remote/path/file.txt
        """
    )
    
    parser.add_argument('local_file', help='Path to the local file to transfer')
    parser.add_argument('remote_file', help='Destination path on the remote server')
    parser.add_argument('-H', '--host', required=True, help='Remote server hostname or IP')
    parser.add_argument('-P', '--port', type=int, default=22, help='SSH/SFTP port (default: 22)')
    parser.add_argument('-u', '--username', required=True, help='Username for authentication')
    parser.add_argument('-p', '--password', help='Password for authentication')
    parser.add_argument('-k', '--key-file', help='Path to SSH private key file')
    parser.add_argument('--no-remove', action='store_true', 
                       help='Do not remove source file after transfer (for testing)')
    parser.add_argument('-v', '--verbose', action='store_true', 
                       help='Enable verbose logging')
    
    args = parser.parse_args()
    
    # Set logging level
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    # Validate authentication method
    if not args.password and not args.key_file:
        logger.error("Either --password or --key-file must be provided")
        return 1
    
    # Validate local file exists
    if not os.path.exists(args.local_file):
        logger.error(f"Local file not found: {args.local_file}")
        return 1
    
    # Initialize SFTP transfer
    sftp_transfer = SFTPTransfer(
        hostname=args.host,
        port=args.port,
        username=args.username,
        password=args.password,
        key_file=args.key_file
    )
    
    try:
        # Step 1: Connect to remote server
        if not sftp_transfer.connect():
            logger.error("Failed to establish SFTP connection")
            return 1
        
        # Step 2: Transfer the file
        if not sftp_transfer.transfer_file(args.local_file, args.remote_file):
            logger.error("File transfer failed")
            return 1
        
        # Step 3: Verify the transfer
        if not sftp_transfer.verify_transfer(args.local_file, args.remote_file):
            logger.error("File transfer verification failed")
            return 1
        
        # Step 4: Remove source file (unless --no-remove flag is set)
        if not args.no_remove:
            if not remove_source_file(args.local_file):
                logger.error("Failed to remove source file")
                return 1
        else:
            logger.info("Skipping source file removal (--no-remove flag set)")
        
        logger.info("✓ All operations completed successfully")
        return 0
        
    except KeyboardInterrupt:
        logger.warning("\nOperation cancelled by user")
        return 1
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        return 1
    finally:
        sftp_transfer.close()


if __name__ == '__main__':
    sys.exit(main())
