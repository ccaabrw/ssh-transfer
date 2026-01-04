<#
.SYNOPSIS
    Transfer files via SFTP with verification and cleanup

.DESCRIPTION
    This script transfers files between local and remote servers using SFTP.
    It can upload files to a remote server or download files from a remote server.
    The transfer is verified by comparing file sizes and optionally checksums,
    and the source file is removed after successful verification.

.PARAMETER Host
    Remote server hostname or IP address (required)

.PARAMETER Username
    Username for authentication (required)

.PARAMETER Password
    Password for authentication (use either Password or KeyFile)

.PARAMETER KeyFile
    Path to SSH private key file (use either Password or KeyFile)

.PARAMETER Port
    SSH/SFTP port (default: 22)

.PARAMETER Download
    Enable download mode: transfer from remote to local (default: upload)

.PARAMETER NoRemove
    Do not remove source file after transfer

.PARAMETER Checksum
    Enable checksum verification (MD5, SHA1, SHA256)

.PARAMETER Verbose
    Enable verbose logging

.PARAMETER SourceFile
    Source file path (local for upload, remote for download)

.PARAMETER DestinationFile
    Destination file path (remote for upload, local for download)

.EXAMPLE
    # Upload using password authentication
    .\sftp_transfer.ps1 -Host server.example.com -Username user -Password pass -SourceFile C:\file.txt -DestinationFile /remote/file.txt

.EXAMPLE
    # Upload using SSH key
    .\sftp_transfer.ps1 -Host server.example.com -Username user -KeyFile C:\Users\user\.ssh\id_rsa -SourceFile C:\file.txt -DestinationFile /remote/file.txt

.EXAMPLE
    # Download from remote server
    .\sftp_transfer.ps1 -Host server.example.com -Username user -Password pass -Download -SourceFile /remote/file.txt -DestinationFile C:\file.txt

.EXAMPLE
    # Upload with SHA256 checksum verification
    .\sftp_transfer.ps1 -Host server.example.com -Username user -Password pass -Checksum SHA256 -SourceFile C:\file.txt -DestinationFile /remote/file.txt

.NOTES
    Requires Posh-SSH module (Install-Module -Name Posh-SSH)
    Exit Codes:
        0 - Success: file transferred, verified, and removed
        1 - Failure: see error messages for details
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true, HelpMessage="Remote server hostname or IP")]
    [string]$Host,
    
    [Parameter(Mandatory=$true, HelpMessage="Username for authentication")]
    [string]$Username,
    
    [Parameter(HelpMessage="Password for authentication")]
    [string]$Password,
    
    [Parameter(HelpMessage="Path to SSH private key file")]
    [string]$KeyFile,
    
    [Parameter(HelpMessage="SSH/SFTP port")]
    [int]$Port = 22,
    
    [Parameter(HelpMessage="Download mode: transfer from remote to local")]
    [switch]$Download,
    
    [Parameter(HelpMessage="Do not remove source file after transfer")]
    [switch]$NoRemove,
    
    [Parameter(HelpMessage="Enable checksum verification (MD5, SHA1, SHA256)")]
    [ValidateSet('MD5', 'SHA1', 'SHA256')]
    [string]$Checksum,
    
    [Parameter(Mandatory=$true, Position=0, HelpMessage="Source file path")]
    [string]$SourceFile,
    
    [Parameter(Mandatory=$true, Position=1, HelpMessage="Destination file path")]
    [string]$DestinationFile
)

# Set strict mode
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Module check
$moduleName = 'Posh-SSH'
if (-not (Get-Module -ListAvailable -Name $moduleName)) {
    Write-LogError "Error: $moduleName module is required."
    Write-LogError "Install it with: Install-Module -Name $moduleName -Force"
    exit 1
}

# Import the module
try {
    Import-Module $moduleName -ErrorAction Stop
} catch {
    Write-LogError "Failed to import $moduleName module: $_"
    exit 1
}

#region Logging Functions

function Get-Timestamp {
    return Get-Date -Format "yyyy-MM-dd HH:mm:ss"
}

function Write-LogInfo {
    param([string]$Message)
    $timestamp = Get-Timestamp
    Write-Host "$timestamp - INFO - $Message"
}

function Write-LogError {
    param([string]$Message)
    $timestamp = Get-Timestamp
    Write-Host "$timestamp - ERROR - $Message" -ForegroundColor Red
}

function Write-LogSuccess {
    param([string]$Message)
    $timestamp = Get-Timestamp
    Write-Host "$timestamp - SUCCESS - ✓ $Message" -ForegroundColor Green
}

function Write-LogDebug {
    param([string]$Message)
    if ($VerbosePreference -eq 'Continue') {
        $timestamp = Get-Timestamp
        Write-Host "$timestamp - DEBUG - $Message" -ForegroundColor Gray
    }
}

#endregion

#region SFTP Functions

function Connect-SftpServer {
    param(
        [string]$Hostname,
        [string]$User,
        [int]$PortNumber,
        [string]$Pass,
        [string]$Key
    )
    
    try {
        $sessionParams = @{
            ComputerName = $Hostname
            Port = $PortNumber
            Credential = $null
            AcceptKey = $true
        }
        
        if ($Key) {
            Write-LogInfo "Using key file: $Key"
            if (-not (Test-Path $Key)) {
                Write-LogError "Key file not found: $Key"
                return $null
            }
            $sessionParams['KeyFile'] = $Key
            # Create a dummy credential for key-based auth
            $securePassword = ConvertTo-SecureString "dummy" -AsPlainText -Force
            $sessionParams['Credential'] = New-Object System.Management.Automation.PSCredential($User, $securePassword)
        } elseif ($Pass) {
            Write-LogInfo "Using password authentication"
            $securePassword = ConvertTo-SecureString $Pass -AsPlainText -Force
            $sessionParams['Credential'] = New-Object System.Management.Automation.PSCredential($User, $securePassword)
        } else {
            Write-LogError "Either Password or KeyFile must be provided"
            return $null
        }
        
        $session = New-SFTPSession @sessionParams -ErrorAction Stop
        Write-LogInfo "SFTP connection established"
        return $session
    } catch {
        Write-LogError "Connection failed: $_"
        return $null
    }
}

function Transfer-SftpFile {
    param(
        [object]$Session,
        [string]$LocalPath,
        [string]$RemotePath
    )
    
    try {
        # Get local file size
        $localFile = Get-Item $LocalPath
        Write-LogInfo "File size: $($localFile.Length) bytes"
        
        # Create remote directory if needed
        $remoteDir = Split-Path $RemotePath -Parent
        if ($remoteDir -and $remoteDir -ne '' -and $remoteDir -ne '.' -and $remoteDir -ne '/') {
            Write-LogDebug "Ensuring remote directory exists: $remoteDir"
            try {
                # Create parent directories recursively
                $null = Set-SFTPItem -SessionId $Session.SessionId -Path $remoteDir -ItemType Directory -ErrorAction SilentlyContinue
            } catch {
                # Directory might already exist, which is fine
            }
        }
        
        # Transfer the file
        Set-SFTPItem -SessionId $Session.SessionId -Path $LocalPath -Destination $RemotePath -Force -ErrorAction Stop
        
        Write-LogInfo "File transfer completed"
        return $true
    } catch {
        Write-LogError "Transfer failed: $_"
        return $false
    }
}

function Download-SftpFile {
    param(
        [object]$Session,
        [string]$RemotePath,
        [string]$LocalPath
    )
    
    try {
        # Get remote file size
        $remoteFile = Get-SFTPItem -SessionId $Session.SessionId -Path $RemotePath -ErrorAction Stop
        if (-not $remoteFile) {
            Write-LogError "Remote file not found: $RemotePath"
            return $false
        }
        Write-LogInfo "File size: $($remoteFile.Length) bytes"
        
        # Create local directory if needed
        $localDir = Split-Path $LocalPath -Parent
        if ($localDir -and $localDir -ne '' -and -not (Test-Path $localDir)) {
            Write-LogDebug "Ensuring local directory exists: $localDir"
            New-Item -Path $localDir -ItemType Directory -Force | Out-Null
        }
        
        # Download the file
        Get-SFTPItem -SessionId $Session.SessionId -Path $RemotePath -Destination $LocalPath -Force -ErrorAction Stop
        
        Write-LogInfo "File download completed"
        return $true
    } catch {
        Write-LogError "Download failed: $_"
        return $false
    }
}

function Get-LocalChecksum {
    param(
        [string]$FilePath,
        [string]$Algorithm
    )
    
    try {
        Write-LogDebug "Calculating $Algorithm checksum for local file: $FilePath"
        $hash = Get-FileHash -Path $FilePath -Algorithm $Algorithm -ErrorAction Stop
        Write-LogDebug "Local $Algorithm checksum: $($hash.Hash)"
        return $hash.Hash.ToLower()
    } catch {
        Write-LogError "Failed to calculate local checksum: $_"
        return $null
    }
}

function Get-RemoteChecksum {
    param(
        [object]$Session,
        [string]$RemotePath,
        [string]$Algorithm
    )
    
    try {
        Write-LogDebug "Calculating $Algorithm checksum for remote file: $RemotePath"
        
        # Map algorithm to the appropriate command
        $cmd = switch ($Algorithm) {
            'MD5'    { "(md5sum '$RemotePath' 2>/dev/null || md5 -r '$RemotePath' 2>/dev/null) | awk '{print `$1}'" }
            'SHA1'   { "(sha1sum '$RemotePath' 2>/dev/null || shasum -a 1 '$RemotePath' 2>/dev/null) | awk '{print `$1}'" }
            'SHA256' { "(sha256sum '$RemotePath' 2>/dev/null || shasum -a 256 '$RemotePath' 2>/dev/null) | awk '{print `$1}'" }
            default  { 
                Write-LogError "Unsupported checksum algorithm: $Algorithm"
                return $null
            }
        }
        
        # Execute command on remote server
        $result = Invoke-SSHCommand -SessionId $Session.SessionId -Command $cmd -ErrorAction Stop
        
        if ($result.ExitStatus -ne 0) {
            Write-LogError "Failed to execute remote checksum command"
            return $null
        }
        
        $checksum = $result.Output.Trim()
        
        # Validate checksum format
        $expectedLengths = @{
            'MD5'    = 32
            'SHA1'   = 40
            'SHA256' = 64
        }
        
        $expectedLength = $expectedLengths[$Algorithm]
        if (-not ($checksum -match '^[a-f0-9]+$' -and $checksum.Length -eq $expectedLength)) {
            Write-LogError "Invalid checksum format received: $checksum (expected $expectedLength hex characters)"
            return $null
        }
        
        Write-LogDebug "Remote $Algorithm checksum: $checksum"
        return $checksum.ToLower()
    } catch {
        Write-LogError "Failed to calculate remote checksum: $_"
        return $null
    }
}

function Test-SftpTransfer {
    param(
        [object]$Session,
        [string]$LocalPath,
        [string]$RemotePath,
        [string]$ChecksumAlgorithm
    )
    
    try {
        # Get remote file attributes
        $remoteFile = Get-SFTPItem -SessionId $Session.SessionId -Path $RemotePath -ErrorAction Stop
        if (-not $remoteFile) {
            Write-LogError "Remote file not found: $RemotePath"
            return $false
        }
        
        # Get file sizes
        $localFile = Get-Item $LocalPath
        $localSize = $localFile.Length
        $remoteSize = $remoteFile.Length
        
        Write-LogInfo "Local file size: $localSize bytes"
        Write-LogInfo "Remote file size: $remoteSize bytes"
        
        # Compare sizes
        if ($localSize -ne $remoteSize) {
            Write-LogError "File sizes do not match!"
            return $false
        }
        
        Write-LogSuccess "File size verification passed"
        
        # Perform checksum verification if requested
        if ($ChecksumAlgorithm) {
            Write-LogInfo "Performing checksum verification using $ChecksumAlgorithm..."
            
            $localChecksum = Get-LocalChecksum -FilePath $LocalPath -Algorithm $ChecksumAlgorithm
            if (-not $localChecksum) {
                Write-LogError "Failed to calculate local checksum"
                return $false
            }
            
            $remoteChecksum = Get-RemoteChecksum -Session $Session -RemotePath $RemotePath -Algorithm $ChecksumAlgorithm
            if (-not $remoteChecksum) {
                Write-LogError "Failed to calculate remote checksum"
                return $false
            }
            
            Write-LogInfo "Local checksum:  $localChecksum"
            Write-LogInfo "Remote checksum: $remoteChecksum"
            
            if ($localChecksum -ne $remoteChecksum) {
                Write-LogError "Checksum verification failed! Files do not match."
                return $false
            }
            
            Write-LogSuccess "Checksum verification passed"
        }
        
        Write-LogSuccess "File transfer verified successfully"
        return $true
    } catch {
        Write-LogError "Verification failed: $_"
        return $false
    }
}

function Remove-LocalFile {
    param([string]$FilePath)
    
    try {
        Write-LogInfo "Removing source file: $FilePath"
        Remove-Item -Path $FilePath -Force -ErrorAction Stop
        Write-LogSuccess "Source file removed successfully"
        return $true
    } catch {
        Write-LogError "Failed to remove source file: $_"
        return $false
    }
}

function Remove-RemoteSftpFile {
    param(
        [object]$Session,
        [string]$RemotePath
    )
    
    try {
        Write-LogInfo "Removing remote file: $RemotePath"
        Remove-SFTPItem -SessionId $Session.SessionId -Path $RemotePath -Force -ErrorAction Stop
        Write-LogSuccess "Remote file removed successfully"
        return $true
    } catch {
        Write-LogError "Failed to remove remote file: $_"
        return $false
    }
}

#endregion

#region Main Script

function Main {
    try {
        # Validate authentication method
        if (-not $Password -and -not $KeyFile) {
            Write-LogError "Either -Password or -KeyFile must be provided"
            return 1
        }
        
        # Validate checksum algorithm if provided
        if ($Checksum) {
            Write-LogInfo "Checksum verification enabled: $Checksum"
        }
        
        # Validate source file exists based on mode
        if ($Download) {
            # In download mode, we'll check remote file existence after connecting
            Write-LogDebug "Download mode: will verify remote file exists after connection"
        } else {
            # In upload mode, check local file exists
            if (-not (Test-Path $SourceFile)) {
                Write-LogError "Local file not found: $SourceFile"
                return 1
            }
        }
        
        # Step 1: Connect to remote server
        Write-LogInfo "Connecting to ${Host}:${Port} as $Username"
        $session = Connect-SftpServer -Hostname $Host -User $Username -PortNumber $Port -Pass $Password -Key $KeyFile
        if (-not $session) {
            Write-LogError "Failed to establish SFTP connection"
            return 1
        }
        
        try {
            if ($Download) {
                # Download mode: remote -> local
                $remoteFile = $SourceFile
                $localFile = $DestinationFile
                Write-LogInfo "Download mode: $remoteFile -> $localFile"
                
                # Verify remote file exists
                $remoteFileInfo = Get-SFTPItem -SessionId $session.SessionId -Path $remoteFile -ErrorAction SilentlyContinue
                if (-not $remoteFileInfo) {
                    Write-LogError "Remote file not found: $remoteFile"
                    return 1
                }
                
                # Step 2: Download the file
                Write-LogInfo "Downloading $remoteFile to $localFile"
                if (-not (Download-SftpFile -Session $session -RemotePath $remoteFile -LocalPath $localFile)) {
                    Write-LogError "File download failed"
                    return 1
                }
                
                # Step 3: Verify the transfer
                Write-LogInfo "Verifying file download..."
                if (-not (Test-SftpTransfer -Session $session -LocalPath $localFile -RemotePath $remoteFile -ChecksumAlgorithm $Checksum)) {
                    Write-LogError "File download verification failed"
                    return 1
                }
                
                # Step 4: Remove remote source file (unless -NoRemove flag is set)
                if (-not $NoRemove) {
                    if (-not (Remove-RemoteSftpFile -Session $session -RemotePath $remoteFile)) {
                        Write-LogError "Failed to remove remote source file"
                        return 1
                    }
                } else {
                    Write-LogInfo "Skipping remote file removal (-NoRemove flag set)"
                }
            } else {
                # Upload mode: local -> remote
                $localFile = $SourceFile
                $remoteFile = $DestinationFile
                Write-LogInfo "Upload mode: $localFile -> $remoteFile"
                
                # Step 2: Transfer the file
                Write-LogInfo "Transferring $localFile to $remoteFile"
                if (-not (Transfer-SftpFile -Session $session -LocalPath $localFile -RemotePath $remoteFile)) {
                    Write-LogError "File transfer failed"
                    return 1
                }
                
                # Step 3: Verify the transfer
                Write-LogInfo "Verifying file transfer..."
                if (-not (Test-SftpTransfer -Session $session -LocalPath $localFile -RemotePath $remoteFile -ChecksumAlgorithm $Checksum)) {
                    Write-LogError "File transfer verification failed"
                    return 1
                }
                
                # Step 4: Remove local source file (unless -NoRemove flag is set)
                if (-not $NoRemove) {
                    if (-not (Remove-LocalFile -FilePath $localFile)) {
                        Write-LogError "Failed to remove source file"
                        return 1
                    }
                } else {
                    Write-LogInfo "Skipping source file removal (-NoRemove flag set)"
                }
            }
            
            Write-LogSuccess "All operations completed successfully"
            return 0
        } finally {
            # Clean up SFTP session
            if ($session) {
                Remove-SFTPSession -SessionId $session.SessionId -ErrorAction SilentlyContinue | Out-Null
            }
        }
    } catch {
        Write-LogError "Unexpected error: $_"
        return 1
    }
}

# Execute main function and exit with its return code
$exitCode = Main
exit $exitCode

#endregion
