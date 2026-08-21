param (
    [Parameter(Mandatory = $true)]
    [string]$LocalFolderPath,

    [Parameter(Mandatory = $true)]
    [string]$SharePointSiteId,

    [Parameter(Mandatory = $true)]
    [string]$DriveName,

    [string]$TargetFolderPath,

    [Parameter(Mandatory = $true)]
    [string]$TenantId,

    [Parameter(Mandatory = $true)]
    [string]$ClientId,

    [Parameter(Mandatory = $true)]
    [string]$ClientSecret,

    [string]$LogFile,
    [switch]$Overwrite
)

# =========================
# Script Configuration
# =========================
$Quiet = $true
$script:LogFilePath = $null
$ChunkSizeBytes = 5MB

# Summary Counters
$script:Summary = [ordered]@{
    TotalFiles   = 0
    Uploaded     = 0
    Overwritten  = 0
    Skipped      = 0
    Failed       = 0
    Folders      = 0
}

# =========================
# Logging Functions
# =========================

function Initialize-LogFile {
    if (-not $LogFile) {
        $scriptName = "Script"
        try {
            if ($MyInvocation.MyCommand.Path) {
                $scriptName = [System.IO.Path]::GetFileNameWithoutExtension($MyInvocation.MyCommand.Path)
            }
        } catch {}

        $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
        $script:LogFilePath = Join-Path $PWD.Path "$scriptName-$timestamp.log"
    } else {
        $script:LogFilePath = $LogFile
    }

    $folder = Split-Path $script:LogFilePath -Parent
    if ($folder -and -not (Test-Path $folder)) {
        New-Item -Path $folder -ItemType Directory -Force | Out-Null
    }

    New-Item -Path $script:LogFilePath -ItemType File -Force | Out-Null
}

function Write-Log {
    [CmdletBinding(PositionalBinding = $false)]
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('INFO','WARN','ERROR','ABORT')][string]$Level = 'INFO'
    )
    if (-not $script:LogFilePath) { Initialize-LogFile }
    $line = "{0} [{1}] {2}" -f (Get-Date).ToString('o'), $Level, $Message
    Add-Content -Path $script:LogFilePath -Value $line -Encoding UTF8
    if (-not $Quiet) { [Console]::WriteLine($line) }
}

function Write-LogObject {
    [CmdletBinding(PositionalBinding = $false)]
    param(
        [Parameter(Mandatory)][string]$Label,
        [AllowNull()][object]$Data,
        [ValidateSet('INFO','WARN','ERROR','ABORT')][string]$Level = 'INFO',
        [int]$Depth = 6
    )
    try {
        $json = ConvertTo-Json -Depth $Depth -InputObject $Data
	Write-Log -Level $Level -Message "${Label}:`n$json"
    } catch {
        Write-Log -Level 'ERROR' -Message "$Label serialization failed: $($_.Exception.Message)"
    }
}

# =========================
# Graph Functions
# =========================

function Connect-ToGraph {
    Write-Log -Message "Requesting Graph API token"

    $body = @{
        grant_type    = 'client_credentials'
        client_id     = $ClientId
        client_secret = $ClientSecret
        scope         = 'https://graph.microsoft.com/.default'
    }

    try {
        $token = Invoke-RestMethod `
            -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" `
            -Method POST `
            -ContentType 'application/x-www-form-urlencoded' `
            -Body $body

        Write-Log -Message "Graph token acquired"
        return $token.access_token
    } catch {
        Write-Log -Level 'ABORT' -Message "Failed to acquire Graph token: $($_.Exception.Message)"
        throw
    }
}

function Get-DriveId {
    param ([string]$AccessToken)

    $url = "https://graph.microsoft.com/v1.0/sites/${SharePointSiteId}/drives"
    $drives = (Invoke-RestMethod -Headers @{ Authorization = "Bearer $AccessToken" } -Uri $url).value
    $drive = $drives | Where-Object { $_.name -eq $DriveName }

    if (-not $drive) {
        Write-Log -Level 'ABORT' -Message "Drive '$DriveName' not found"
        throw
    }

    if (
        $drive.driveType -ne 'documentLibrary' -or
        $drive.name -match 'Preservation' -or
        $drive.description -match 'ediscovery|hold|cannot be deleted'
    ) {
        Write-LogObject -Label "Requested Drive (RESTRICTED)" -Data $drive -Level 'ERROR'
        throw
    }

    Write-LogObject -Label "Using Drive" -Data $drive -Level 'INFO'
    return $drive.id
}

function Ensure-GraphFolder {
    param ($AccessToken, $DriveId, $FolderPath)

    $segments = $FolderPath -split '/'
    $current = ''

    foreach ($segment in $segments) {
        $current = if ($current) { "$current/$segment" } else { $segment }
        $encoded = [System.Web.HttpUtility]::UrlPathEncode($current)
        $url = "https://graph.microsoft.com/v1.0/drives/${DriveId}/root:/${encoded}"

        try {
            Invoke-RestMethod -Headers @{ Authorization = "Bearer $AccessToken" } -Uri $url -Method GET -ErrorAction Stop | Out-Null
        } catch {
            $parent = Split-Path $current -Parent -ErrorAction SilentlyContinue
            $parentEncoded = if ($parent) { [System.Web.HttpUtility]::UrlPathEncode($parent) }
            $createUrl = if ($parentEncoded) {
                "https://graph.microsoft.com/v1.0/drives/${DriveId}/root:/${parentEncoded}:/children"
            } else {
                "https://graph.microsoft.com/v1.0/drives/${DriveId}/root/children"
            }

            Invoke-RestMethod `
                -Headers @{ Authorization = "Bearer $AccessToken"; 'Content-Type' = 'application/json' } `
                -Uri $createUrl `
                -Method POST `
                -Body (@{ name=$segment; folder=@{} } | ConvertTo-Json) | Out-Null

            $script:Summary.Folders++
            Write-Log -Message "Created folder: $current"
        }
    }
}

function Upload-File {
    param ($AccessToken, $DriveId, $GraphPath, $LocalFile)

    $script:Summary.TotalFiles++

    $encoded = [System.Web.HttpUtility]::UrlPathEncode($GraphPath)
    $checkUrl  = "https://graph.microsoft.com/v1.0/drives/${DriveId}/root:/${encoded}"
$uploadUrl = "${checkUrl}:/content"

    $exists = $false
    try {
        Invoke-RestMethod -Headers @{ Authorization = "Bearer $AccessToken" } -Uri $checkUrl -Method GET -ErrorAction Stop | Out-Null
        $exists = $true
        Write-Log -Level 'WARN' -Message "File already exists: $GraphPath"
    } catch {}

    if ($exists -and -not $Overwrite) {
        Write-Log -Message "Skipping existing file: $GraphPath"
        $script:Summary.Skipped++
        return
    }

    $fileSize = (Get-Item $LocalFile).Length
    try {
        if ($fileSize -le 4MB) {
            Invoke-RestMethod `
                -Headers @{ Authorization = "Bearer $AccessToken" } `
                -Uri $uploadUrl `
                -Method PUT `
                -Body ([System.IO.File]::ReadAllBytes($LocalFile)) `
                -ContentType 'application/octet-stream' | Out-Null
        } else {
            Chunked-Upload -AccessToken $AccessToken -DriveId $DriveId -GraphPath $GraphPath -LocalFile $LocalFile
        }

        if ($exists) { $script:Summary.Overwritten++ }
        else { $script:Summary.Uploaded++ }

        Write-Log -Message "Uploaded: $GraphPath"
    } catch {
        $script:Summary.Failed++
        Write-Log -Level 'ERROR' -Message "Upload failed: $GraphPath - $($_.Exception.Message)"
    }
}

function Chunked-Upload {
    [CmdletBinding(PositionalBinding = $false)]
    param (
        [Parameter(Mandatory)]
        [string]$AccessToken,

        [Parameter(Mandatory)]
        [string]$DriveId,

        [Parameter(Mandatory)]
        [string]$GraphPath,

        [Parameter(Mandatory)]
        [string]$LocalFile
    )

    $encodedPath = [System.Web.HttpUtility]::UrlPathEncode($GraphPath)
    $uploadSessionUrl = "https://graph.microsoft.com/v1.0/drives/${DriveId}/root:/${encodedPath}:/createUploadSession"

    Write-Log -Message "Creating upload session for: $GraphPath"

    try {
        $sessionRequestBody = @{
			item = @{
					"@microsoft.graph.conflictBehavior" = if ($Overwrite) { "replace" } else { "fail" }
			}
	} | ConvertTo-Json -Depth 3


        $uploadSession = Invoke-RestMethod `
            -Headers @{
                Authorization  = "Bearer $AccessToken"
                "Content-Type" = "application/json"
            } `
            -Uri $uploadSessionUrl `
            -Method POST `
            -Body $sessionRequestBody `
            -ErrorAction Stop

        if (-not $uploadSession.uploadUrl) {
            throw "Upload session created but uploadUrl was not returned."
        }

        Write-Log -Message "Upload session created successfully."
		Write-Log -Message "Upload session URL: $uploadUrl"

    }
    catch {
	Write-Log -Level 'ERROR' -Message "Failed to create upload session for $GraphPath}: $($_.Exception.Message)"

        if ($_.Exception.Response) {
            try {
                $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
                $responseBody = $reader.ReadToEnd()
                Write-Log -Level 'ERROR' -Message "Upload session error response: $responseBody"
            } catch {}
        }

        throw
    }

    $uploadUrl  = $uploadSession.uploadUrl
    $fileStream = [System.IO.File]::OpenRead($LocalFile)
    $fileSize   = $fileStream.Length
    $bytesSent  = 0
    $chunkIndex = 0

    try {
        while ($bytesSent -lt $fileSize) {
            $remaining = $fileSize - $bytesSent
            $chunkSize = [Math]::Min($ChunkSizeBytes, $remaining)

            $buffer = New-Object byte[] $chunkSize
            $read   = $fileStream.Read($buffer, 0, $chunkSize)

            if ($read -le 0) {
                throw "Unexpected end of file while reading $LocalFile"
            }

            $start = $bytesSent
            $end   = $start + $read - 1

            $headers = @{
                Authorization     = "Bearer $AccessToken"
                "Content-Length"  = $read
                "Content-Range"   = "bytes $start-$end/$fileSize"
            }

            Write-Log -Message "Uploading chunk $chunkIndex (bytes $start-$end)"

            try {
                Invoke-RestMethod `
                    -Uri $uploadUrl `
                    -Method PUT `
                    -Headers $headers `
                    -Body $buffer `
                    -ErrorAction Stop | Out-Null
            }
            catch {
                Write-Log -Level 'ERROR' -Message "Chunk $chunkIndex failed (bytes $start-$end): $($_.Exception.Message)"

                if ($_.Exception.Response) {
                    try {
                        $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
                        $responseBody = $reader.ReadToEnd()
                        Write-Log -Level 'ERROR' -Message "Chunk error response: $responseBody"
                    } catch {}
                }

                Write-Log -Message "Retrying chunk $chunkIndex after 2 seconds..."
                Start-Sleep -Seconds 2

                try {
                    Invoke-RestMethod `
                        -Uri $uploadUrl `
                        -Method PUT `
                        -Headers $headers `
                        -Body $buffer `
                        -ErrorAction Stop | Out-Null

                    Write-Log -Message "Retry succeeded for chunk $chunkIndex"
                }
                catch {
                    Write-Log -Level 'ERROR' -Message "Chunk $chunkIndex retry failed: $($_.Exception.Message)"

                    if ($_.Exception.Response) {
                        try {
                            $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
                            $retryBody = $reader.ReadToEnd()
                            Write-Log -Level 'ERROR' -Message "Retry error response: $retryBody"
                        } catch {}
                    }

                    throw
                }
            }

            $bytesSent += $read
            $chunkIndex++
        }

        Write-Log -Message "All chunks uploaded successfully for $GraphPath"
    }
    finally {
        $fileStream.Close()
    }
}


# =========================
# MAIN
# =========================

Initialize-LogFile
Write-Log -Message "Script started"
Write-Log -Message ("Overwrite is {0}" -f ($Overwrite.IsPresent))

if (-not (Test-Path $LocalFolderPath)) {
    Write-Log -Level 'ABORT' -Message "Local folder does not exist: $LocalFolderPath"
    throw
}

$token   = Connect-ToGraph
$driveId = Get-DriveId -AccessToken $token

$rootName = Split-Path $LocalFolderPath -Leaf
$basePath = if ($TargetFolderPath) { "$TargetFolderPath/$rootName" } else { $rootName }

# === Create all folders, including empty ones ===
$folders = Get-ChildItem -Path $LocalFolderPath -Recurse -Directory | Where-Object {
    -not ($_.Attributes -match 'Hidden|System')
}

foreach ($folder in $folders) {
    $relative = $folder.FullName.Substring($LocalFolderPath.Length).TrimStart('\','/')
    $graphFolderPath = "$basePath/$($relative -replace '\\','/')"
    Ensure-GraphFolder -AccessToken $token -DriveId $driveId -FolderPath $graphFolderPath
}

# === Upload files ===
$files = Get-ChildItem $LocalFolderPath -Recurse -File | Where-Object {
    -not ($_.Attributes -match 'Hidden|System')
}

foreach ($file in $files) {
    $relative = $file.FullName.Substring($LocalFolderPath.Length).TrimStart('\','/')
    $graphPath = "$basePath/$($relative -replace '\\','/')"
    Upload-File -AccessToken $token -DriveId $driveId -GraphPath $graphPath -LocalFile $file.FullName
}

Write-LogObject -Label "Summary" -Data $script:Summary -Level 'INFO'
Write-Log -Message "Script completed"
