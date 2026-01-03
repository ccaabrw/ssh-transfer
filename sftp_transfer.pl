#!/usr/bin/env perl

=head1 NAME

sftp_transfer.pl - Transfer files via SFTP with verification and cleanup

=head1 SYNOPSIS

    sftp_transfer.pl [options] <local_file> <remote_file>

    Options:
        -H, --host <hostname>       Remote server hostname or IP (required)
        -u, --username <username>   Username for authentication (required)
        -p, --password <password>   Password for authentication
        -k, --key-file <path>       Path to SSH private key file
        -P, --port <port>           SSH/SFTP port (default: 22)
        --no-remove                 Do not remove source file after transfer
        -c, --checksum <algorithm>  Enable checksum verification (md5, sha1, sha256)
        -v, --verbose               Enable verbose logging
        -h, --help                  Show this help message

=head1 DESCRIPTION

This script transfers a file to a remote server using SFTP, verifies the
transfer was successful by comparing file sizes and optionally checksums,
and removes the source file after successful verification.

=head1 EXAMPLES

    # Transfer using password authentication
    sftp_transfer.pl -H server.example.com -u username -p password /path/to/file.txt /remote/path/file.txt

    # Transfer using SSH key
    sftp_transfer.pl -H server.example.com -u username -k ~/.ssh/id_rsa /path/to/file.txt /remote/path/file.txt

    # Transfer to a different port
    sftp_transfer.pl -H server.example.com -P 2222 -u username -p password /path/to/file.txt /remote/path/file.txt

    # Transfer with SHA256 checksum verification
    sftp_transfer.pl -H server.example.com -u username -p password -c sha256 /path/to/file.txt /remote/path/file.txt

=cut

use strict;
use warnings;
use Getopt::Long qw(:config no_ignore_case);
use Pod::Usage;
use File::Basename;
use File::Spec;
use Digest::MD5;
use Digest::SHA;

# Check for required modules
BEGIN {
    eval {
        require Net::SFTP::Foreign;
        Net::SFTP::Foreign->import();
    };
    if ($@) {
        print STDERR "Error: Net::SFTP::Foreign module is required.\n";
        print STDERR "Install it with: cpan Net::SFTP::Foreign\n";
        print STDERR "Or on Debian/Ubuntu: apt-get install libnet-sftp-foreign-perl\n";
        exit 1;
    }
}

# Global variables
my $verbose = 0;

# Parse command line options
my %opts = (
    port => 22,
    help => 0,
    'no-remove' => 0,
    verbose => 0,
    checksum => undef,
);

GetOptions(
    'H|host=s'      => \$opts{host},
    'u|username=s'  => \$opts{username},
    'p|password=s'  => \$opts{password},
    'k|key-file=s'  => \$opts{key_file},
    'P|port=i'      => \$opts{port},
    'no-remove'     => \$opts{'no-remove'},
    'c|checksum=s'  => \$opts{checksum},
    'v|verbose'     => \$opts{verbose},
    'h|help'        => \$opts{help},
) or pod2usage(2);

# Show help if requested
pod2usage(-verbose => 2, -exitval => 0) if $opts{help};

# Set verbose flag
$verbose = $opts{verbose};

# Validate required arguments
my $local_file = shift @ARGV;
my $remote_file = shift @ARGV;

unless (defined $local_file && defined $remote_file) {
    print STDERR "Error: Both local_file and remote_file arguments are required\n\n";
    pod2usage(2);
}

unless (defined $opts{host}) {
    print STDERR "Error: --host is required\n\n";
    pod2usage(2);
}

unless (defined $opts{username}) {
    print STDERR "Error: --username is required\n\n";
    pod2usage(2);
}

unless (defined $opts{password} || defined $opts{key_file}) {
    log_error("Either --password or --key-file must be provided");
    exit 1;
}

# Validate checksum algorithm if provided
if (defined $opts{checksum}) {
    unless ($opts{checksum} =~ /^(md5|sha1|sha256)$/i) {
        log_error("Invalid checksum algorithm: $opts{checksum}. Must be one of: md5, sha1, sha256");
        exit 1;
    }
    $opts{checksum} = lc($opts{checksum});
    log_info("Checksum verification enabled: $opts{checksum}");
}

# Validate local file exists
unless (-f $local_file) {
    log_error("Local file not found: $local_file");
    exit 1;
}

# Main execution
exit main();

sub main {
    eval {
        # Step 1: Connect to remote server
        log_info("Connecting to $opts{host}:$opts{port} as $opts{username}");
        my $sftp = connect_sftp();
        unless ($sftp) {
            log_error("Failed to establish SFTP connection");
            return 1;
        }
        
        # Step 2: Transfer the file
        log_info("Transferring $local_file to $remote_file");
        unless (transfer_file($sftp, $local_file, $remote_file)) {
            log_error("File transfer failed");
            return 1;
        }
        
        # Step 3: Verify the transfer
        log_info("Verifying file transfer...");
        unless (verify_transfer($sftp, $local_file, $remote_file)) {
            log_error("File transfer verification failed");
            return 1;
        }
        
        # Step 4: Remove source file (unless --no-remove flag is set)
        unless ($opts{'no-remove'}) {
            unless (remove_source_file($local_file)) {
                log_error("Failed to remove source file");
                return 1;
            }
        } else {
            log_info("Skipping source file removal (--no-remove flag set)");
        }
        
        log_success("All operations completed successfully");
        return 0;
    };
    
    if ($@) {
        log_error("Unexpected error: $@");
        return 1;
    }
}

sub connect_sftp {
    my %sftp_opts = (
        host => $opts{host},
        user => $opts{username},
        port => $opts{port},
    );
    
    # Add authentication method
    if (defined $opts{key_file}) {
        log_info("Using key file: $opts{key_file}");
        $sftp_opts{key_path} = $opts{key_file};
    } elsif (defined $opts{password}) {
        log_info("Using password authentication");
        $sftp_opts{password} = $opts{password};
    }
    
    # Additional options for better compatibility
    # WARNING: StrictHostKeyChecking=no disables host key verification
    # This makes the connection vulnerable to man-in-the-middle attacks
    # In production, you should properly manage known_hosts or use custom verification
    $sftp_opts{more} = ['-o', 'StrictHostKeyChecking=no'];
    
    my $sftp = Net::SFTP::Foreign->new(%sftp_opts);
    
    if ($sftp->error) {
        log_error("Connection failed: " . $sftp->error);
        return undef;
    }
    
    log_info("SFTP connection established");
    return $sftp;
}

sub transfer_file {
    my ($sftp, $local, $remote) = @_;
    
    # Get local file size
    my $local_size = -s $local;
    log_info("File size: $local_size bytes");
    
    # Create remote directory if needed
    my $remote_dir = dirname($remote);
    if ($remote_dir && $remote_dir ne '' && $remote_dir ne '.' && $remote_dir ne '/') {
        log_debug("Ensuring remote directory exists: $remote_dir");
        $sftp->mkpath($remote_dir);
        if ($sftp->error) {
            log_error("Failed to create remote directory: " . $sftp->error);
            return 0;
        }
    }
    
    # Transfer the file
    $sftp->put($local, $remote);
    
    if ($sftp->error) {
        log_error("Transfer failed: " . $sftp->error);
        return 0;
    }
    
    log_info("File transfer completed");
    return 1;
}

sub calculate_local_checksum {
    my ($file, $algorithm) = @_;
    
    log_debug("Calculating $algorithm checksum for local file: $file");
    
    open(my $fh, '<', $file) or do {
        log_error("Cannot open file for checksum: $!");
        return undef;
    };
    binmode($fh);
    
    my $digest;
    if ($algorithm eq 'md5') {
        $digest = Digest::MD5->new;
    } elsif ($algorithm eq 'sha1') {
        $digest = Digest::SHA->new(1);
    } elsif ($algorithm eq 'sha256') {
        $digest = Digest::SHA->new(256);
    } else {
        log_error("Unsupported checksum algorithm: $algorithm");
        close($fh);
        return undef;
    }
    
    $digest->addfile($fh);
    close($fh);
    
    my $checksum = $digest->hexdigest;
    log_debug("Local $algorithm checksum: $checksum");
    return $checksum;
}

sub calculate_remote_checksum {
    my ($sftp, $remote_file, $algorithm) = @_;
    
    log_debug("Calculating $algorithm checksum for remote file: $remote_file");
    
    # Map algorithm to the appropriate command
    my $cmd;
    if ($algorithm eq 'md5') {
        # Try different MD5 commands (md5sum on Linux, md5 on macOS/BSD)
        $cmd = "(md5sum '$remote_file' 2>/dev/null || md5 -r '$remote_file' 2>/dev/null) | awk '{print \$1}'";
    } elsif ($algorithm eq 'sha1') {
        $cmd = "(sha1sum '$remote_file' 2>/dev/null || shasum -a 1 '$remote_file' 2>/dev/null) | awk '{print \$1}'";
    } elsif ($algorithm eq 'sha256') {
        $cmd = "(sha256sum '$remote_file' 2>/dev/null || shasum -a 256 '$remote_file' 2>/dev/null) | awk '{print \$1}'";
    } else {
        log_error("Unsupported checksum algorithm: $algorithm");
        return undef;
    }
    
    # Execute command via SSH
    my $output = $sftp->system($cmd);
    
    if ($sftp->error) {
        log_error("Failed to calculate remote checksum: " . $sftp->error);
        return undef;
    }
    
    # Read the output
    my $checksum;
    if (defined $output) {
        $checksum = $output;
        $checksum =~ s/^\s+|\s+$//g;  # Trim whitespace
    }
    
    # The system() method doesn't return command output directly in Net::SFTP::Foreign
    # We need to use a different approach - download a small chunk or use a temp file
    # Let's use a more reliable method with backtick-style capture
    
    # Create a temporary file to capture output
    my $temp_remote = "/tmp/.sftp_checksum_$$";
    my $temp_local = "/tmp/.sftp_checksum_local_$$";
    
    # Execute command and redirect output to temp file
    $sftp->system("$cmd > $temp_remote 2>&1");
    
    if ($sftp->error) {
        log_error("Failed to execute remote checksum command: " . $sftp->error);
        return undef;
    }
    
    # Download the temp file
    $sftp->get($temp_remote, $temp_local);
    
    if ($sftp->error) {
        log_error("Failed to retrieve checksum result: " . $sftp->error);
        # Clean up remote temp file
        $sftp->system("rm -f $temp_remote");
        return undef;
    }
    
    # Read the checksum from local temp file
    if (open(my $fh, '<', $temp_local)) {
        $checksum = <$fh>;
        close($fh);
        if (defined $checksum) {
            $checksum =~ s/^\s+|\s+$//g;  # Trim whitespace
        }
        unlink($temp_local);
    } else {
        log_error("Failed to read checksum result: $!");
        $sftp->system("rm -f $temp_remote");
        return undef;
    }
    
    # Clean up remote temp file
    $sftp->system("rm -f $temp_remote");
    
    unless ($checksum && $checksum =~ /^[a-f0-9]+$/i) {
        log_error("Invalid checksum format received: " . ($checksum || 'empty'));
        return undef;
    }
    
    log_debug("Remote $algorithm checksum: $checksum");
    return lc($checksum);
}

sub verify_transfer {
    my ($sftp, $local, $remote) = @_;
    
    # Get remote file attributes
    my $remote_attrs = $sftp->stat($remote);
    
    unless ($remote_attrs) {
        log_error("Remote file not found: $remote");
        log_error("SFTP error: " . $sftp->error) if $sftp->error;
        return 0;
    }
    
    # Get file sizes
    my $local_size = -s $local;
    my $remote_size = $remote_attrs->{size};
    
    log_info("Local file size: $local_size bytes");
    log_info("Remote file size: $remote_size bytes");
    
    # Compare sizes
    if ($local_size != $remote_size) {
        log_error("File sizes do not match!");
        return 0;
    }
    
    log_success("File size verification passed");
    
    # Perform checksum verification if requested
    if (defined $opts{checksum}) {
        log_info("Performing checksum verification using $opts{checksum}...");
        
        my $local_checksum = calculate_local_checksum($local, $opts{checksum});
        unless (defined $local_checksum) {
            log_error("Failed to calculate local checksum");
            return 0;
        }
        
        my $remote_checksum = calculate_remote_checksum($sftp, $remote, $opts{checksum});
        unless (defined $remote_checksum) {
            log_error("Failed to calculate remote checksum");
            return 0;
        }
        
        log_info("Local checksum:  $local_checksum");
        log_info("Remote checksum: $remote_checksum");
        
        if ($local_checksum ne $remote_checksum) {
            log_error("Checksum verification failed! Files do not match.");
            return 0;
        }
        
        log_success("Checksum verification passed");
    }
    
    log_success("File transfer verified successfully");
    return 1;
}

sub remove_source_file {
    my ($file) = @_;
    
    log_info("Removing source file: $file");
    
    if (unlink($file)) {
        log_success("Source file removed successfully");
        return 1;
    } else {
        log_error("Failed to remove source file: $!");
        return 0;
    }
}

# Logging functions
sub log_info {
    my ($message) = @_;
    my $timestamp = get_timestamp();
    print "$timestamp - INFO - $message\n";
}

sub log_error {
    my ($message) = @_;
    my $timestamp = get_timestamp();
    print STDERR "$timestamp - ERROR - $message\n";
}

sub log_success {
    my ($message) = @_;
    my $timestamp = get_timestamp();
    print "$timestamp - SUCCESS - ✓ $message\n";
}

sub log_debug {
    my ($message) = @_;
    return unless $verbose;
    my $timestamp = get_timestamp();
    print "$timestamp - DEBUG - $message\n";
}

sub get_timestamp {
    my ($sec, $min, $hour, $mday, $mon, $year) = localtime(time);
    return sprintf("%04d-%02d-%02d %02d:%02d:%02d",
                   $year + 1900, $mon + 1, $mday, $hour, $min, $sec);
}

__END__

=head1 EXIT CODES

=over 4

=item * 0 - Success: file transferred, verified, and removed

=item * 1 - Failure: see error messages for details

=back

=head1 AUTHOR

Created for the ssh-transfer project

=head1 LICENSE

MIT License

=cut
