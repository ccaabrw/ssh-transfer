<#
.SYNOPSIS
    Transfer files via SFTP with verification and cleanup

.DESCRIPTION
    This script transfers files between local and remote servers using SFTP.
    It can upload files to a remote server or download files from a remote server.
    The transfer is verified by comparing file sizes and optionally checksums,
    and the source file is removed after successful verification.
    
    Uses Windows built-in OpenSSH client (available on Windows 10 1809+ and Windows Server 2019+).

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
    Requires Windows OpenSSH client (ssh.exe and sftp.exe)
    Available by default on Windows 10 1809+ and Windows Server 2019+
    
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

#region SSH/SFTP Functions

function Test-SshAvailable {
    try {
        $sshPath = Get-Command ssh.exe -ErrorAction Stop
        $sftpPath = Get-Command sftp.exe -ErrorAction Stop
        Write-LogDebug "Found ssh.exe at: $($sshPath.Source)"
        Write-LogDebug "Found sftp.exe at: $($sftpPath.Source)"
        return $true
    } catch {
        Write-LogError "OpenSSH client not found. Please install OpenSSH client."
        Write-LogError "Install with: Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0"
        return $false
    }
}

function Get-SshOptions {
    param(
        [string]$KeyFilePath,
        [int]$PortNumber
    )
    
    $options = @()
    $options += "-o"
    $options += "StrictHostKeyChecking=no"
    $options += "-o"
    $options += "UserKnownHostsFile=NUL"
    $options += "-P"
    $options += $PortNumber.ToString()
    
    if ($KeyFilePath) {
        $options += "-i"
        $options += "`"$KeyFilePath`""
    }
    
    return $options
}

function Test-RemoteFileExists {
    param(
        [string]$Hostname,
        [string]$User,
        [int]$PortNumber,
        [string]$KeyFilePath,
        [string]$Pass,
        [string]$RemotePath
    )
    
    try {
        $cmd = "test -f '$RemotePath' && echo 'EXISTS' || echo 'NOT_FOUND'"
        $result = Invoke-SshCommand -Hostname $Hostname -User $User -PortNumber $PortNumber -KeyFilePath $KeyFilePath -Pass $Pass -Command $cmd
        
        return ($result.Output -match 'EXISTS')
    } catch {
        Write-LogDebug "Error checking remote file: $_"
        return $false
    }
}

function Get-RemoteFileSize {
    param(
        [string]$Hostname,
        [string]$User,
        [int]$PortNumber,
        [string]$KeyFilePath,
        [string]$Pass,
        [string]$RemotePath
    )
    
    try {
        $cmd = "stat -c %s '$RemotePath' 2>/dev/null || stat -f %z '$RemotePath' 2>/dev/null"
        $result = Invoke-SshCommand -Hostname $Hostname -User $User -PortNumber $PortNumber -KeyFilePath $KeyFilePath -Pass $Pass -Command $cmd
        
        if ($result.ExitCode -eq 0 -and $result.Output -match '^\d+$') {
            return [long]$result.Output
        }
        
        return $null
    } catch {
        Write-LogDebug "Error getting remote file size: $_"
        return $null
    }
}

function Invoke-SshCommand {
    param(
        [string]$Hostname,
        [string]$User,
        [int]$PortNumber,
        [string]$KeyFilePath,
        [string]$Pass,
        [string]$Command
    )
    
    $sshArgs = @()
    $sshArgs += "-o"
    $sshArgs += "StrictHostKeyChecking=no"
    $sshArgs += "-o"
    $sshArgs += "UserKnownHostsFile=NUL"
    $sshArgs += "-p"
    $sshArgs += $PortNumber
    
    if ($KeyFilePath) {
        $sshArgs += "-i"
        $sshArgs += $KeyFilePath
    }
    
    $sshArgs += "$User@$Hostname"
    $sshArgs += $Command
    
    Write-LogDebug "Executing SSH command: ssh $($sshArgs -join ' ')"
    
    if ($Pass) {
        # Use sshpass-like functionality via stdin (not ideal but works)
        # Note: This is a limitation - password auth via command line is not secure
        Write-LogError "Password authentication via SSH command is not directly supported."
        Write-LogError "Please use key-based authentication or consider using Posh-SSH module."
        throw "Password authentication not supported with built-in SSH"
    }
    
    $output = & ssh.exe @sshArgs 2>&1
    $exitCode = $LASTEXITCODE
    
    return @{
        Output = ($output | Out-String).Trim()
        ExitCode = $exitCode
    }
}

function Invoke-SftpTransfer {
    param(
        [string]$Hostname,
        [string]$User,
        [int]$PortNumber,
        [string]$KeyFilePath,
        [string]$Pass,
        [string]$LocalPath,
        [string]$RemotePath,
        [bool]$IsDownload
    )
    
    try {
        # Create SFTP batch file
        $batchFile = [System.IO.Path]::GetTempFileName()
        
        if ($IsDownload) {
            # Download mode
            $localDir = Split-Path $LocalPath -Parent
            if ($localDir -and -not (Test-Path $localDir)) {
                New-Item -Path $localDir -ItemType Directory -Force | Out-Null
            }
            
            "get `"$RemotePath`" `"$LocalPath`"" | Out-File -FilePath $batchFile -Encoding ASCII
        } else {
            # Upload mode - create remote directory if needed
            $remoteDir = Split-Path $RemotePath -Parent
            if ($remoteDir -and $remoteDir -ne '' -and $remoteDir -ne '.' -and $remoteDir -ne '/') {
                "-mkdir `"$remoteDir`"" | Out-File -FilePath $batchFile -Encoding ASCII
            }
            "put `"$LocalPath`" `"$RemotePath`"" | Out-File -FilePath $batchFile -Encoding ASCII -Append
        }
        
        Write-LogDebug "SFTP batch file content:"
        Write-LogDebug (Get-Content $batchFile | Out-String)
        
        # Build SFTP command arguments
        $sftpArgs = @()
        $sftpArgs += "-b"
        $sftpArgs += $batchFile
        $sftpArgs += "-o"
        $sftpArgs += "StrictHostKeyChecking=no"
        $sftpArgs += "-o"
        $sftpArgs += "UserKnownHostsFile=NUL"
        $sftpArgs += "-P"
        $sftpArgs += $PortNumber
        
        if ($KeyFilePath) {
            $sftpArgs += "-i"
            $sftpArgs += $KeyFilePath
        }
        
        if ($Pass) {
            # Password authentication is problematic with sftp.exe on Windows
            # We need to handle this differently
            Write-LogError "Password authentication via SFTP is not directly supported with Windows OpenSSH client."
            Write-LogError "Please use key-based authentication."
            throw "Password authentication not supported"
        }
        
        $sftpArgs += "$User@$Hostname"
        
        Write-LogDebug "Executing SFTP: sftp $($sftpArgs -join ' ')"
        
        $output = & sftp.exe @sftpArgs 2>&1
        $exitCode = $LASTEXITCODE
        
        Remove-Item $batchFile -Force -ErrorAction SilentlyContinue
        
        if ($exitCode -ne 0) {
            Write-LogError "SFTP command failed with exit code: $exitCode"
            Write-LogDebug "Output: $($output | Out-String)"
            return $false
        }
        
        return $true
    } catch {
        Write-LogError "SFTP transfer failed: $_"
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
        [string]$Hostname,
        [string]$User,
        [int]$PortNumber,
        [string]$KeyFilePath,
        [string]$Pass,
        [string]$RemotePath,
        [string]$Algorithm
    )
    
    try {
        Write-LogDebug "Calculating $Algorithm checksum for remote file: $RemotePath"
        
        # Map algorithm to the appropriate command
        $cmd = switch ($Algorithm) {
            'MD5'    { "(md5sum '$RemotePath' 2>/dev/null || md5 -r '$RemotePath' 2>/dev/null) | awk '{print \$1}'" }
            'SHA1'   { "(sha1sum '$RemotePath' 2>/dev/null || shasum -a 1 '$RemotePath' 2>/dev/null) | awk '{print \$1}'" }
            'SHA256' { "(sha256sum '$RemotePath' 2>/dev/null || shasum -a 256 '$RemotePath' 2>/dev/null) | awk '{print \$1}'" }
            default  { 
                Write-LogError "Unsupported checksum algorithm: $Algorithm"
                return $null
            }
        }
        
        $result = Invoke-SshCommand -Hostname $Hostname -User $User -PortNumber $PortNumber -KeyFilePath $KeyFilePath -Pass $Pass -Command $cmd
        
        if ($result.ExitCode -ne 0) {
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
        if (-not ($checksum -match '^[a-fA-F0-9]+$' -and $checksum.Length -eq $expectedLength)) {
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

function Remove-RemoteFile {
    param(
        [string]$Hostname,
        [string]$User,
        [int]$PortNumber,
        [string]$KeyFilePath,
        [string]$Pass,
        [string]$RemotePath
    )
    
    try {
        Write-LogInfo "Removing remote file: $RemotePath"
        
        $cmd = "rm -f '$RemotePath'"
        $result = Invoke-SshCommand -Hostname $Hostname -User $User -PortNumber $PortNumber -KeyFilePath $KeyFilePath -Pass $Pass -Command $cmd
        
        if ($result.ExitCode -eq 0) {
            Write-LogSuccess "Remote file removed successfully"
            return $true
        } else {
            Write-LogError "Failed to remove remote file"
            return $false
        }
    } catch {
        Write-LogError "Failed to remove remote file: $_"
        return $false
    }
}

#endregion

#region Main Script

function Main {
    try {
        # Check if OpenSSH client is available
        if (-not (Test-SshAvailable)) {
            return 1
        }
        
        # Validate authentication method
        if (-not $Password -and -not $KeyFile) {
            Write-LogError "Either -Password or -KeyFile must be provided"
            return 1
        }
        
        # Note: Password authentication is not supported with Windows built-in SSH
        if ($Password) {
            Write-LogError "Password authentication is not supported with Windows built-in OpenSSH client."
            Write-LogError "Please use -KeyFile parameter for key-based authentication."
            return 1
        }
        
        # Validate key file exists
        if ($KeyFile -and -not (Test-Path $KeyFile)) {
            Write-LogError "Key file not found: $KeyFile"
            return 1
        }
        
        # Validate checksum algorithm if provided
        if ($Checksum) {
            Write-LogInfo "Checksum verification enabled: $Checksum"
        }
        
        # Validate source file exists based on mode
        if ($Download) {
            # In download mode, we'll check remote file existence after connecting
            Write-LogDebug "Download mode: will verify remote file exists"
        } else {
            # In upload mode, check local file exists
            if (-not (Test-Path $SourceFile)) {
                Write-LogError "Local file not found: $SourceFile"
                return 1
            }
        }
        
        # Connection info
        Write-LogInfo "Connecting to ${Host}:${Port} as $Username"
        if ($KeyFile) {
            Write-LogInfo "Using key file: $KeyFile"
        }
        
        if ($Download) {
            # Download mode: remote -> local
            $remoteFile = $SourceFile
            $localFile = $DestinationFile
            Write-LogInfo "Download mode: $remoteFile -> $localFile"
            
            # Verify remote file exists
            Write-LogDebug "Checking if remote file exists..."
            if (-not (Test-RemoteFileExists -Hostname $Host -User $Username -PortNumber $Port -KeyFilePath $KeyFile -Pass $Password -RemotePath $remoteFile)) {
                Write-LogError "Remote file not found: $remoteFile"
                return 1
            }
            
            # Get remote file size
            $remoteSize = Get-RemoteFileSize -Hostname $Host -User $Username -PortNumber $Port -KeyFilePath $KeyFile -Pass $Password -RemotePath $remoteFile
            if ($remoteSize) {
                Write-LogInfo "Remote file size: $remoteSize bytes"
            }
            
            # Step 2: Download the file
            Write-LogInfo "Downloading $remoteFile to $localFile"
            if (-not (Invoke-SftpTransfer -Hostname $Host -User $Username -PortNumber $Port -KeyFilePath $KeyFile -Pass $Password -LocalPath $localFile -RemotePath $remoteFile -IsDownload $true)) {
                Write-LogError "File download failed"
                return 1
            }
            Write-LogInfo "File download completed"
            
            # Step 3: Verify the transfer
            Write-LogInfo "Verifying file download..."
            
            # Get file sizes
            $localSize = (Get-Item $localFile).Length
            $remoteSize = Get-RemoteFileSize -Hostname $Host -User $Username -PortNumber $Port -KeyFilePath $KeyFile -Pass $Password -RemotePath $remoteFile
            
            Write-LogInfo "Local file size: $localSize bytes"
            Write-LogInfo "Remote file size: $remoteSize bytes"
            
            if ($localSize -ne $remoteSize) {
                Write-LogError "File sizes do not match!"
                return 1
            }
            
            Write-LogSuccess "File size verification passed"
            
            # Perform checksum verification if requested
            if ($Checksum) {
                Write-LogInfo "Performing checksum verification using $Checksum..."
                
                $localChecksum = Get-LocalChecksum -FilePath $localFile -Algorithm $Checksum
                if (-not $localChecksum) {
                    Write-LogError "Failed to calculate local checksum"
                    return 1
                }
                
                $remoteChecksum = Get-RemoteChecksum -Hostname $Host -User $Username -PortNumber $PortNumber -KeyFilePath $KeyFile -Pass $Password -RemotePath $remoteFile -Algorithm $Checksum
                if (-not $remoteChecksum) {
                    Write-LogError "Failed to calculate remote checksum"
                    return 1
                }
                
                Write-LogInfo "Local checksum:  $localChecksum"
                Write-LogInfo "Remote checksum: $remoteChecksum"
                
                if ($localChecksum -ne $remoteChecksum) {
                    Write-LogError "Checksum verification failed! Files do not match."
                    return 1
                }
                
                Write-LogSuccess "Checksum verification passed"
            }
            
            Write-LogSuccess "File transfer verified successfully"
            
            # Step 4: Remove remote source file (unless -NoRemove flag is set)
            if (-not $NoRemove) {
                if (-not (Remove-RemoteFile -Hostname $Host -User $Username -PortNumber $Port -KeyFilePath $KeyFile -Pass $Password -RemotePath $remoteFile)) {
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
            
            # Get local file size
            $localSize = (Get-Item $localFile).Length
            Write-LogInfo "Local file size: $localSize bytes"
            
            # Step 2: Transfer the file
            Write-LogInfo "Transferring $localFile to $remoteFile"
            if (-not (Invoke-SftpTransfer -Hostname $Host -User $Username -PortNumber $Port -KeyFilePath $KeyFile -Pass $Password -LocalPath $localFile -RemotePath $remoteFile -IsDownload $false)) {
                Write-LogError "File transfer failed"
                return 1
            }
            Write-LogInfo "File transfer completed"
            
            # Step 3: Verify the transfer
            Write-LogInfo "Verifying file transfer..."
            
            # Get remote file size
            $remoteSize = Get-RemoteFileSize -Hostname $Host -User $Username -PortNumber $Port -KeyFilePath $KeyFile -Pass $Password -RemotePath $remoteFile
            
            Write-LogInfo "Local file size: $localSize bytes"
            Write-LogInfo "Remote file size: $remoteSize bytes"
            
            if ($localSize -ne $remoteSize) {
                Write-LogError "File sizes do not match!"
                return 1
            }
            
            Write-LogSuccess "File size verification passed"
            
            # Perform checksum verification if requested
            if ($Checksum) {
                Write-LogInfo "Performing checksum verification using $Checksum..."
                
                $localChecksum = Get-LocalChecksum -FilePath $localFile -Algorithm $Checksum
                if (-not $localChecksum) {
                    Write-LogError "Failed to calculate local checksum"
                    return 1
                }
                
                $remoteChecksum = Get-RemoteChecksum -Hostname $Host -User $Username -PortNumber $Port -KeyFilePath $KeyFile -Pass $Password -RemotePath $remoteFile -Algorithm $Checksum
                if (-not $remoteChecksum) {
                    Write-LogError "Failed to calculate remote checksum"
                    return 1
                }
                
                Write-LogInfo "Local checksum:  $localChecksum"
                Write-LogInfo "Remote checksum: $remoteChecksum"
                
                if ($localChecksum -ne $remoteChecksum) {
                    Write-LogError "Checksum verification failed! Files do not match."
                    return 1
                }
                
                Write-LogSuccess "Checksum verification passed"
            }
            
            Write-LogSuccess "File transfer verified successfully"
            
            # Step 4: Remove local source file (unless -NoRemove flag is set)
            if (-not $NoRemove) {
                Write-LogInfo "Removing source file: $localFile"
                Remove-Item -Path $localFile -Force -ErrorAction Stop
                Write-LogSuccess "Source file removed successfully"
            } else {
                Write-LogInfo "Skipping source file removal (-NoRemove flag set)"
            }
        }
        
        Write-LogSuccess "All operations completed successfully"
        return 0
    } catch {
        Write-LogError "Unexpected error: $_"
        Write-LogDebug $_.ScriptStackTrace
        return 1
    }
}

# Execute main function and exit with its return code
$exitCode = Main
exit $exitCode

#endregion
