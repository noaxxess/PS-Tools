<#
.SYNOPSIS
  Trace-first by Sender + date range -> gather unique MessageIds -> query Unified Audit Log (UAL),
  OR fast-path by MessageId(s). Attaches transport Sender/From/Recipient/Subject/Status/Size/ReceivedTime to all UAL rows.
  Exports TZ-only timestamps; skips CSV when 0 results. PS 5.1 compatible.

.PARAMETER MessageId
  One or more Internet Message IDs. You can include <angle brackets>; script normalizes to bare IDs.
  If -MessageId is provided and dates are omitted, defaults to the last 10 days ending now.

.PARAMETER Sender
  Envelope MAIL FROM to trace. If exact sender returns 0 and -TraceDomainFallback is supplied,
  script fetches the window and client-filters *@<sender-domain>.

.PARAMETER StartDate / EndDate
  If you pass day-only dates, the script includes the full EndDate day automatically (23:59:59).
  Required if using -Sender without -MessageId. Optional if -MessageId is provided (defaults to last 10 days).

.PARAMETER TimeZone
  Display timezone for timestamps (Windows ID, IANA like 'America/New_York', or ±HH:MM). Defaults to local.

.PARAMETER CsvPath / LogPath
  Optional explicit output paths. If omitted, files are created in $env:TEMP with a datestamp.

.PARAMETER DumpRaw
  Dumps parsed UAL JSON per record into a sibling "_raw" folder next to the CSV.

.PARAMETER TraceDomainFallback
  If exact -Sender returns 0 rows, fetches the window and client-filters *@<sender-domain>.
#>

[CmdletBinding()]
param(
    [string[]]$MessageId,
    [string]$Sender,
    [datetime]$StartDate,
    [datetime]$EndDate,
    [string]$TimeZone,
    [string]$CsvPath,
    [string]$LogPath,
    [switch]$DumpRaw,
    [switch]$TraceDomainFallback
)

#region Utilities
function New-Timestamp { Get-Date -Format "yyyyMMdd_HHmmss" }

function Resolve-DefaultPath {
    param([ValidateSet('log','csv')][string]$Kind)
    $dir = $env:TEMP
    if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $stamp = New-Timestamp
    $name = if ($Kind -eq 'log') { "TraceThenAudit_$stamp.log" } else { "TraceThenAudit_$stamp.csv" }
    Join-Path $dir $name
}

$Script:LogFile = if ($LogPath) { $LogPath } else { Resolve-DefaultPath -Kind log }

function Write-Log {
    param([ValidateSet('INFO','WARN','ERROR')][string]$Level = 'INFO',[Parameter(Mandatory)][string]$Message)
    $ts = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ss.fffffffK")
    $line = "$ts [$Level] $Message"
    Write-Host $line
    try { Add-Content -LiteralPath $Script:LogFile -Value $line -Encoding UTF8 } catch { Write-Host "$ts [ERROR] Failed to write log: $($_.Exception.Message)" }
}

# Normalize MessageId (strip quotes and angle brackets)
function Normalize-MessageId {
    param([string]$Id)
    if (-not $Id) { return $null }
    $s = $Id.Trim()
    if ($s.Length -ge 2 -and $s.StartsWith('"') -and $s.EndsWith('"')) { $s = $s.Substring(1, $s.Length-2) }
    if ($s.Length -ge 2 -and $s.StartsWith("'") -and $s.EndsWith("'")) { $s = $s.Substring(1, $s.Length-2) }
    if ($s.Length -ge 2 -and $s.StartsWith('<') -and $s.EndsWith('>')) { $s = $s.Substring(1, $s.Length-2) }
    return $s
}

# Expand to both bare + bracketed for trace lookups
function Expand-MessageIdForms {
    param([string]$BareId)
    if (-not $BareId) { return @() }
    @($BareId, "<$BareId>")
}

# Fallback: extract InternetMessageId (or MessageId) from raw JSON text via regex
function FastExtract-MessageIdFromJsonText {
    param([string]$JsonText)
    if (-not $JsonText) { return $null }
    $m = [regex]::Match($JsonText, '"InternetMessageId"\s*:\s*"([^"]+)"')
    if ($m.Success) { return $m.Groups[1].Value }
    $m = [regex]::Match($JsonText, '"MessageId"\s*:\s*"([^"]+)"')
    if ($m.Success) { return $m.Groups[1].Value }
    return $null
}

# Choose the best InternetMessageId from an audit JSON object,
# preferring any that match our traced MessageIds ($CandidateIds).
function Select-AuditInternetMessageId {
    param(
        $auditObj,
        [string[]]$CandidateIds
    )
    if (-not $auditObj) { return $null }

    $allIds = @()

    # Top-level possibilities
    if ($auditObj.InternetMessageId)                          { $allIds += $auditObj.InternetMessageId }
    if ($auditObj.MessageId)                                  { $allIds += $auditObj.MessageId }
    if ($auditObj.Item -and $auditObj.Item.InternetMessageId) { $allIds += $auditObj.Item.InternetMessageId }
    if ($auditObj.AffectedItems) {
        foreach ($ai in $auditObj.AffectedItems) {
            if ($ai.InternetMessageId) { $allIds += $ai.InternetMessageId }
        }
    }
    # Aggregated "MailItemsAccessed" style (Folders[*].FolderItems[*].InternetMessageId)
    if ($auditObj.Folders) {
        foreach ($f in $auditObj.Folders) {
            if ($f.FolderItems) {
                foreach ($fi in $f.FolderItems) {
                    if ($fi.InternetMessageId) { $allIds += $fi.InternetMessageId }
                }
            }
        }
    }
    # ExtendedProperties last
    if (-not $allIds.Count -and $auditObj.ExtendedProperties) {
        $ep = $auditObj.ExtendedProperties | Where-Object { $_.Name -match 'InternetMessageId|MessageId' } | Select-Object -First 1
        if ($ep -and $ep.Value) { $allIds += $ep.Value }
    }

    $norm = $allIds | ForEach-Object { Normalize-MessageId $_ } | Where-Object { $_ } | Select-Object -Unique
    if ($CandidateIds -and $CandidateIds.Count) {
        foreach ($c in $CandidateIds) { if ($norm -contains $c) { return $c } }
    }
    if ($norm.Count) { return $norm[0] }
    return $null
}

# TZ helpers (PS 5.1)
function Resolve-TimeZoneInfo {
    param([string]$Tz)
    if (-not $Tz -or $Tz.Trim() -eq '') { return [TimeZoneInfo]::Local }
    if ($Tz -match '^(UTC|Zulu)$')      { return [TimeZoneInfo]::Utc }
    if ($Tz -match '^[+-]\d{2}:?\d{2}$'){ return $null } # fixed offset handled in Convert-FromUtc
    $ianaToWindows = @{
        'America/New_York'    = 'Eastern Standard Time'
        'America/Chicago'     = 'Central Standard Time'
        'America/Denver'      = 'Mountain Standard Time'
        'America/Los_Angeles' = 'Pacific Standard Time'
        'America/Phoenix'     = 'US Mountain Standard Time'
        'America/Anchorage'   = 'Alaskan Standard Time'
        'America/Honolulu'    = 'Hawaiian Standard Time'
        'Europe/London'       = 'GMT Standard Time'
        'Europe/Paris'        = 'Romance Standard Time'
        'Europe/Berlin'       = 'W. Europe Standard Time'
        'UTC'                 = 'UTC'
    }
    $id = if ($ianaToWindows.ContainsKey($Tz)) { $ianaToWindows[$Tz] } else { $Tz }
    try { [TimeZoneInfo]::FindSystemTimeZoneById($id) } catch { Write-Log -Level WARN -Message "Could not resolve time zone '$Tz'. Using Local."; [TimeZoneInfo]::Local }
}
function Convert-FromUtc {
    param([Parameter(Mandatory)][datetime]$UtcDate,[string]$Tz)
    if ($Tz -and $Tz -match '^[+-]\d{2}:?\d{2}$') {
        $sign  = if ($Tz[0] -eq '-') { -1 } else { 1 }
        $nums  = ($Tz -replace '^[+-]','') -replace ':',''
        $hours = [int]$nums.Substring(0,2); $mins=[int]$nums.Substring(2,2)
        return ($UtcDate).AddHours($sign*$hours).AddMinutes($sign*$mins)
    }
    $tzInfo = Resolve-TimeZoneInfo -Tz $Tz
    try { [TimeZoneInfo]::ConvertTimeFromUtc([DateTime]::SpecifyKind($UtcDate,[DateTimeKind]::Utc), $tzInfo) }
    catch { Write-Log -Level WARN -Message "Time convert failed for '$UtcDate' -> '$($tzInfo.Id)': $($_.Exception.Message)"; $UtcDate }
}

# Module/connection helpers
function Ensure-EXOModule {
    $min = [Version]'3.7.0'
    $installed = $null
    try { $installed = Get-InstalledModule -Name ExchangeOnlineManagement -ErrorAction Stop } catch { }
    if ($installed -and ($installed.Version -ge $min)) {
        Write-Log -Level INFO -Message ("ExchangeOnlineManagement {0} already installed." -f $installed.Version)
    } else {
        Write-Log -Level INFO -Message "Installing/Updating ExchangeOnlineManagement (min 3.7.0)..."
        Install-Module -Name ExchangeOnlineManagement -Scope CurrentUser -MinimumVersion 3.7.0 -Force -AllowClobber -ErrorAction Stop
    }
    Import-Module ExchangeOnlineManagement -ErrorAction Stop
    Write-Log -Level INFO -Message ("Module imported: ExchangeOnlineManagement {0}" -f (Get-Module ExchangeOnlineManagement).Version)
}
function Connect-EXO { Write-Log -Level INFO -Message "Connecting to Exchange Online..."; Connect-ExchangeOnline -ShowBanner:$false -ErrorAction Stop; Write-Log -Level INFO -Message "Connected to Exchange Online." }
function Disconnect-EXO { try { Disconnect-ExchangeOnline -Confirm:$false } catch { } ; Write-Log -Level INFO -Message "Disconnected from Exchange Online." }

function Get-DomainFromAddress {
    param([string]$Address)
    if (-not $Address) { return $null }
    $a = $Address.Trim()
    $at = $a.IndexOf('@')
    if ($at -gt 0 -and $a.Length -gt ($at+1)) { return $a.Substring($at+1) }
    $null
}

# Safe "first non-null" that flattens arrays
function First-NotNull {
    param([Parameter(ValueFromRemainingArguments = $true)]$Values)
    foreach ($v in $Values) {
        if ($null -eq $v) { continue }
        if ($v -is [System.Array]) {
            foreach ($w in $v) {
                if ($null -ne $w -and $w -ne '') { return $w }
            }
        } else {
            if ($v -ne '') { return $v }
        }
    }
    return $null
}
#endregion Utilities

#region Validate inputs + defaults
Write-Log -Level INFO -Message "=== Trace-Then-Audit Start ==="
Write-Log -Level INFO -Message "Log file: $Script:LogFile"

# Require at least MessageId OR Sender
if ((-not $MessageId -or $MessageId.Count -eq 0) -and (-not $Sender -or $Sender.Trim() -eq '')) {
    Write-Log -Level ERROR -Message "Provide -MessageId (one or more) OR -Sender."
    throw "Missing search parameter."
}

# If MessageId provided and a date is missing, default to last 10 days ending now
$hasStart = $PSBoundParameters.ContainsKey('StartDate') -and $StartDate
$hasEnd   = $PSBoundParameters.ContainsKey('EndDate')   -and $EndDate
if ($MessageId -and $MessageId.Count -gt 0 -and (-not $hasStart -or -not $hasEnd)) {
    if (-not $hasEnd)   { $EndDate   = Get-Date }
    if (-not $hasStart) { $StartDate = $EndDate.AddDays(-10) }
    Write-Log -Level INFO -Message ("Dates not fully specified with -MessageId; defaulting to last 10 days: {0:u} .. {1:u}" -f $StartDate, $EndDate)
}

# If still missing dates (i.e., Sender path without MessageId), throw
if ((-not $StartDate) -or (-not $EndDate)) {
    Write-Log -Level ERROR -Message "StartDate and EndDate are required when -Sender is used without -MessageId."
    throw "Dates required for sender-based trace."
}

# Validate order & normalize day-only to inclusive end-of-day
if ($StartDate -ge $EndDate) { Write-Log -Level ERROR -Message "StartDate must be earlier than EndDate."; throw "Invalid date range." }
if ($StartDate.Hour -eq 0 -and $StartDate.Minute -eq 0 -and $StartDate.Second -eq 0) { $StartDate = $StartDate.Date }
if ($EndDate.Hour   -eq 0 -and $EndDate.Minute   -eq 0   -and $EndDate.Second   -eq 0) { $EndDate   = $EndDate.Date.AddDays(1).AddSeconds(-1) }
Write-Log -Level INFO -Message ("Normalized window: {0:u} .. {1:u}" -f $StartDate, $EndDate)

$tzLabel = if ($TimeZone -and $TimeZone.Trim() -ne '') { $TimeZone } else { ([TimeZoneInfo]::Local).Id }
Write-Log -Level INFO -Message ("Display TZ: {0}" -f $tzLabel)

# Prepare CSV path (log only right before export)
$CsvFile = if ($CsvPath) { $CsvPath } else { Resolve-DefaultPath -Kind csv }
$csvDir  = Split-Path -Path $CsvFile -Parent
if (-not (Test-Path -LiteralPath $csvDir)) { New-Item -ItemType Directory -Path $csvDir -Force | Out-Null }

# Optional raw JSON dump folder (audit JSON)
$rawOutDir = $null
if ($DumpRaw) {
    $base = [IO.Path]::GetFileNameWithoutExtension($CsvFile)
    $rawOutDir = Join-Path $csvDir ($base + "_raw")
    if (-not (Test-Path -LiteralPath $rawOutDir)) { New-Item -ItemType Directory -Path $rawOutDir -Force | Out-Null }
    Write-Log -Level INFO -Message "Raw JSON dump enabled -> $rawOutDir"
}
#endregion

#region Connect
try { Ensure-EXOModule; Connect-EXO } catch { Write-Log -Level ERROR -Message "Setup/connect failed: $($_.Exception.Message)"; throw }
#endregion

#region Core helpers (UAL + V2 trace)
function Invoke-AuditSearch {
    param([datetime]$Start,[datetime]$End,[string]$FreeTextBare)
    $args = @{ StartDate=$Start; EndDate=$End; ResultSize=5000; ErrorAction='Stop'; FreeText=$FreeTextBare }
    Write-Log -Level INFO -Message ("Search-UnifiedAuditLog Start={0:u} End={1:u} FreeText='{2}'" -f $Start,$End,$FreeTextBare)
    $sw=[Diagnostics.Stopwatch]::StartNew(); $res=Search-UnifiedAuditLog @args; $sw.Stop()
    Write-Log -Level INFO -Message ("UAL returned {0} record(s) in {1} ms for MessageId '{2}'." -f (($res|Measure-Object).Count), $sw.ElapsedMilliseconds, $FreeTextBare)
    $res
}

# Robust: sanitize inputs and fall back to per-MessageId if the batch call throws
function Get-MessageTraceV2Paged {
    param(
        [datetime]$Start,[datetime]$End,
        [string[]]$MessageIds,
        [string[]]$SenderAddresses,
        [int]$ResultSize = 5000
    )

    # Sanitize inputs (trim, drop null/empty/<>, dedupe)
    $cleanMsgIds = @()
    if ($MessageIds) {
        $cleanMsgIds = $MessageIds |
            Where-Object { $_ -and $_.ToString().Trim() -ne '' -and $_.ToString().Trim() -ne '<>' } |
            ForEach-Object { $_.ToString().Trim() } |
            Select-Object -Unique
    }
    $cleanSenders = @()
    if ($SenderAddresses) {
        $cleanSenders = $SenderAddresses |
            Where-Object { $_ -and $_.ToString().Trim() -ne '' } |
            ForEach-Object { $_.ToString().Trim() } |
            Select-Object -Unique
    }

    # If nothing to filter on, don't call the cmdlet
    if (-not $cleanMsgIds.Count -and -not $cleanSenders.Count) {
        Write-Log -Level WARN -Message "Get-MessageTraceV2 skipped: no MessageIds or SenderAddresses after sanitization."
        return @()
    }

    $argsBase = @{ StartDate=$Start; EndDate=$End; ResultSize=$ResultSize; ErrorAction='Stop' }
    if ($cleanMsgIds.Count)  { $argsBase.MessageId     = $cleanMsgIds }
    if ($cleanSenders.Count) { $argsBase.SenderAddress = $cleanSenders }

    $all=@()

    try {
        Write-Log -Level INFO -Message ("Get-MessageTraceV2 window {0:u}..{1:u}, ResultSize={2}, MsgIdCount={3}, Sender='{4}', StartRecip='{5}'" -f `
            $argsBase.StartDate,$argsBase.EndDate,$argsBase.ResultSize, $cleanMsgIds.Count, ($cleanSenders -join ';'), $argsBase.StartingRecipientAddress)

        $batch = Get-MessageTraceV2 @argsBase
        $count = ($batch|Measure-Object).Count
        Write-Log -Level INFO -Message ("Trace V2 returned {0} row(s)." -f $count)
        $all += $batch

        # Handle paging only if needed
        if ($count -ge $ResultSize) {
            $more=$true; $loop=0
            while($more){
                $loop++; if($loop -gt 60){ Write-Log -Level WARN -Message "Trace paging loop guard reached."; break }
                $last = $batch[-1]
                $recv = $null
                if     ($last.PSObject.Properties['Received'])     { $recv = $last.Received }
                elseif ($last.PSObject.Properties['ReceivedTime']) { $recv = $last.ReceivedTime }
                if (-not $last.RecipientAddress -or -not $recv) { break }
                $argsBase.StartingRecipientAddress = $last.RecipientAddress
                $argsBase.EndDate = $recv

                Write-Log -Level INFO -Message ("Get-MessageTraceV2 paging: StartRecip='{0}', EndDate='{1:u}'" -f $argsBase.StartingRecipientAddress,$argsBase.EndDate)
                $batch = Get-MessageTraceV2 @argsBase
                $c2 = ($batch|Measure-Object).Count
                Write-Log -Level INFO -Message ("Trace V2 returned {0} row(s) (paged)." -f $c2)
                if ($c2 -eq 0) { break }
                $all += $batch
                if ($c2 -lt $ResultSize) { $more=$false }
            }
        }

        return $all
    }
    catch {
        # Batch failed — fall back to one-by-one MessageId calls (non-throwing)
        $msg = $_.Exception.Message
        Write-Log -Level WARN -Message ("Batch Get-MessageTraceV2 failed ({0}). Falling back to per-MessageId requests." -f $msg)

        # If only senders were provided (no message IDs), we can't split — rethrow
        if (-not $cleanMsgIds.Count) {
            Write-Log -Level ERROR -Message "No MessageIds to split; rethrowing."
            throw
        }

        foreach ($mid in $cleanMsgIds) {
            try {
                Write-Log -Level INFO -Message ("Fallback trace for MessageId '{0}'" -f $mid)
                $rowset = Get-MessageTraceV2 -StartDate $Start -EndDate $End -MessageId $mid -ResultSize $ResultSize -ErrorAction Stop
                $all += $rowset
            } catch {
                Write-Log -Level WARN -Message ("Fallback trace failed for '{0}': {1}" -f $mid, $_.Exception.Message)
            }
        }
        return $all
    }
}
#endregion

#region Build normalized MessageId set
$msgIdSet = @()

# a) Explicit -MessageId values
if ($MessageId) {
    foreach ($mid in $MessageId) {
        $bare = Normalize-MessageId $mid
        if ($bare) { $msgIdSet += $bare }
    }
}

# b) Sender trace-first (optional)
$traceIndex = @{}   # map by BOTH bare and <bare> -> trace row
if ($Sender -and $Sender.Trim() -ne '') {
    Write-Log -Level INFO -Message ("Tracing by Sender '{0}'..." -f $Sender)
    $traceHits = Get-MessageTraceV2Paged -Start $StartDate -End $EndDate -SenderAddresses @($Sender) -ResultSize 5000

    if (($traceHits|Measure-Object).Count -eq 0 -and $TraceDomainFallback) {
        $dom = Get-DomainFromAddress -Address $Sender
        if ($dom) {
            Write-Log -Level WARN -Message "Exact sender returned 0 rows. Domain fallback enabled; fetching window and client-filtering *@$dom"
            $window = Get-MessageTraceV2Paged -Start $StartDate -End $EndDate -ResultSize 5000
            if ($window) { $traceHits = $window | Where-Object { $_.SenderAddress -like "*@$dom" } }
        }
    }

    $rawCount = ($traceHits|Measure-Object).Count
    Write-Log -Level INFO -Message ("Trace returned {0} row(s)." -f $rawCount)

    foreach ($row in $traceHits) {
        $rawMid = $row.MessageId
        if ($rawMid) {
            $bare = Normalize-MessageId $rawMid
            if ($bare) {
                if (-not $traceIndex.ContainsKey($bare))         { $traceIndex[$bare] = $row }
                $br = "<$bare>"
                if (-not $traceIndex.ContainsKey($br))           { $traceIndex[$br]   = $row }
                $msgIdSet += $bare
            }
        }
    }
}

# Sanitize & Deduplicate ID set (defensive)
$msgIdSet = $msgIdSet |
    Where-Object { $_ -and $_.ToString().Trim() -ne '' -and $_.ToString().Trim() -ne '<>' } |
    ForEach-Object { $_.ToString().Trim() } |
    Select-Object -Unique

Write-Log -Level INFO -Message ("Unique normalized MessageId(s): {0}" -f (($msgIdSet -join ', ')))
Write-Log -Level INFO -Message ("Total unique IDs: {0}" -f (($msgIdSet|Measure-Object).Count))

if (($msgIdSet|Measure-Object).Count -eq 0) {
    Write-Log -Level INFO -Message "0 results returned for the specified criteria; skipping CSV creation."
    Disconnect-EXO
    Write-Log -Level INFO -Message "=== Completed (0 results) ==="
    return
}
#endregion

#region UAL by each unique normalized MessageId (one call per ID)
$raw=@()
foreach ($bareId in $msgIdSet) {
    $raw += Invoke-AuditSearch -Start $StartDate -End $EndDate -FreeTextBare $bareId
}
#endregion

#region Expand UAL rows and attach transport fields
$expanded = foreach ($r in $raw) {
    $auditObj = $null
    try { if ($r.AuditData) { $auditObj = $r.AuditData | ConvertFrom-Json -ErrorAction Stop } } catch { Write-Log -Level WARN -Message ("JSON parse failed for RecordId {0}: {1}" -f $r.Id, $_.Exception.Message) }

    if ($DumpRaw -and $auditObj) {
        try {
            $safeId  = if ($r.Id) { $r.Id } else { (Get-Random) }
            $safeKey = ($safeId -replace '[^\w\-]','_')
            $safeDt  = (Get-Date $r.CreationDate -ErrorAction SilentlyContinue).ToString('yyyyMMdd_HHmmss')
            if (-not $safeDt) { $safeDt = (Get-Date).ToString('yyyyMMdd_HHmmss') }
            $file = Join-Path $rawOutDir ("record_{0}_{1}.json" -f $safeDt, $safeKey)
            $auditObj | ConvertTo-Json -Depth 20 | Out-File -FilePath $file -Encoding UTF8
        } catch { Write-Log -Level WARN -Message "Raw dump failed: $($_.Exception.Message)" }
    }

    # Operation
    $op = if ($r.Operation) { $r.Operation } elseif ($auditObj) { First-NotNull $auditObj.Operation $auditObj.OperationName } else { $null }

    # Recipient (audit fallback)
    $recipientAudit = $null
    if ($auditObj) {
        if     ($auditObj.Recipient)                            { $recipientAudit = $auditObj.Recipient }
        elseif ($auditObj.RecipientAddress)                     { $recipientAudit = $auditObj.RecipientAddress }
        elseif ($auditObj.Recipients)                           { $recipientAudit = ($auditObj.Recipients -join ';') }
        elseif ($auditObj.Item -and $auditObj.Item.Recipients)  { $recipientAudit = ($auditObj.Item.Recipients -join ';') }
        elseif ($auditObj.AffectedItems -and $auditObj.AffectedItems.Count -gt 0 -and $auditObj.AffectedItems[0].Recipients) { $recipientAudit = ($auditObj.AffectedItems[0].Recipients -join ';') }
        if (-not $recipientAudit -and $auditObj.ExtendedProperties) { 
            $recipientAudit = ($auditObj.ExtendedProperties | Where-Object { $_.Name -match 'Recipient|To(Address)?' } | Select-Object -First 1).Value
        }
    }

    # Internet Message Id (prefer the one from our traced ID set)
    $internetIdBare = Select-AuditInternetMessageId -auditObj $auditObj -CandidateIds $msgIdSet
    if (-not $internetIdBare -and $r.AuditData) {
        $internetIdBare = Normalize-MessageId (FastExtract-MessageIdFromJsonText -JsonText $r.AuditData)
    }

    # Subject (audit fallback)
    $subjectAudit = $null
    if ($auditObj) {
        if     ($auditObj.Subject)                              { $subjectAudit = $auditObj.Subject }
        elseif ($auditObj.Item -and $auditObj.Item.Subject)     { $subjectAudit = $auditObj.Item.Subject }
        elseif ($auditObj.AffectedItems -and $auditObj.AffectedItems.Count -gt 0 -and $auditObj.AffectedItems[0].Subject) { $subjectAudit = $auditObj.AffectedItems[0].Subject }
        if (-not $subjectAudit -and $auditObj.ExtendedProperties) { 
            $subjectAudit = ($auditObj.ExtendedProperties | Where-Object { $_.Name -eq 'Subject' } | Select-Object -First 1).Value
        }
    }

    $creationTz = if ($r.CreationDate) { Convert-FromUtc -UtcDate $r.CreationDate -Tz $tzLabel } else { $null }

    $candidates = @($r.Id)
    if ($auditObj) { $candidates += @($auditObj.Id, $auditObj.RecordId, $auditObj.CorrelationId, $auditObj.InternalId) }
    $recId = First-NotNull $candidates

    # Attach transport (by bare or bracketed)
    $tr = $null
    if ($internetIdBare) {
        if     ($traceIndex.ContainsKey($internetIdBare))         { $tr = $traceIndex[$internetIdBare] }
        elseif ($traceIndex.ContainsKey("<$internetIdBare>"))     { $tr = $traceIndex["<$internetIdBare>"] }
    }

    $senderOut = $null; $fromOut=$null; $recipientX=$recipientAudit; $subjectX=$subjectAudit
    $recvUtc=$null; $statusX=$null; $sizeX=$null

    if ($tr) {
        if ($tr.PSObject.Properties['SenderAddress'])    { $senderOut = $tr.SenderAddress }
        if ($tr.PSObject.Properties['From'])             { $fromOut   = $tr.From }
        elseif ($tr.PSObject.Properties['FromAddress'])  { $fromOut   = $tr.FromAddress }
        if ($tr.PSObject.Properties['RecipientAddress']) { $recipientX = $tr.RecipientAddress }
        if ($tr.PSObject.Properties['Subject'] -and $tr.Subject) { $subjectX = $tr.Subject }
        if ($tr.PSObject.Properties['Status'])           { $statusX = $tr.Status }
        if ($tr.PSObject.Properties['Size'])             { $sizeX   = $tr.Size }
        if     ($tr.PSObject.Properties['Received'])     { $recvUtc = $tr.Received }
        elseif ($tr.PSObject.Properties['ReceivedTime']) { $recvUtc = $tr.ReceivedTime }
    }

    [pscustomobject]@{
        CreationDate       = $creationTz
        MessageId          = $internetIdBare      # bare (no <>)
        Sender             = $senderOut
        FromHeader         = $fromOut
        Recipient          = $recipientX
        Subject            = $subjectX
        TraceStatus        = $statusX
        TraceSize          = $sizeX
        TraceReceivedTime  = $(if ($recvUtc) { Convert-FromUtc -UtcDate $recvUtc -Tz $tzLabel } else { $null })
        Operation          = $op
        ActorUserId        = ($r.UserIds -join ';')
        RecordType         = $r.RecordType
        AuditRecordId      = $recId
        RawAuditDataJson   = $r.AuditData
    }
}

# If we have UAL rows but are missing some trace rows (e.g., fast-path by ID), enrich by MessageId forms
$expandedCount = ($expanded|Measure-Object).Count
if ($expandedCount -gt 0) {
    $needTraceBare = @()
    $seen=@{}
    foreach ($midBare in ($expanded | Select-Object -ExpandProperty MessageId | Where-Object { $_ -and $_ -ne '' })) {
        if (-not $traceIndex.ContainsKey($midBare) -and -not $traceIndex.ContainsKey("<$midBare>") -and -not $seen.ContainsKey($midBare)) {
            $needTraceBare += $midBare; $seen[$midBare]=$true
        }
    }

    if ($needTraceBare.Count -gt 0) {
        # Query both bare + bracketed forms to maximize matches
        $expandedForms = @()
        foreach ($b in $needTraceBare) { $expandedForms += (Expand-MessageIdForms $b) }

        # Sanitize
        $expandedForms = $expandedForms |
            Where-Object { $_ -and $_.ToString().Trim() -ne '' -and $_.ToString().Trim() -ne '<>' } |
            ForEach-Object { $_.ToString().Trim() } |
            Select-Object -Unique

        if ($expandedForms.Count -gt 0) {
            # Try once via the robust paged helper (has its own fallback)
            $t = @()
            try {
                $t = Get-MessageTraceV2Paged -Start $StartDate -End $EndDate -MessageIds $expandedForms -ResultSize 5000
            } catch {
                # As a final safety net, split per ID here too
                Write-Log -Level WARN -Message ("Chunk enrichment failed: {0}. Falling back per-ID in enrichment loop." -f $_.Exception.Message)
                foreach ($mid in $expandedForms) {
                    try {
                        Write-Log -Level INFO -Message ("Enrichment fallback for MessageId '{0}'" -f $mid)
                        $t += Get-MessageTraceV2 -StartDate $StartDate -EndDate $EndDate -MessageId $mid -ResultSize 5000 -ErrorAction Stop
                    } catch {
                        Write-Log -Level WARN -Message ("Enrichment per-ID failed for '{0}': {1}" -f $mid, $_.Exception.Message)
                    }
                }
            }

            foreach ($row in $t) {
                $bare = Normalize-MessageId $row.MessageId
                if ($bare) {
                    if (-not $traceIndex.ContainsKey($bare))       { $traceIndex[$bare]       = $row }
                    if (-not $traceIndex.ContainsKey("<$bare>"))   { $traceIndex["<$bare>"]   = $row }
                }
            }

            # Re-attach transport columns for rows that got a match
            $expanded = $expanded | ForEach-Object {
                $row = $_; $tr=$null
                if ($row.MessageId -and $traceIndex.ContainsKey($row.MessageId)) { $tr = $traceIndex[$row.MessageId] }
                elseif ($row.MessageId -and $traceIndex.ContainsKey("<$($row.MessageId)>")) { $tr = $traceIndex["<$($row.MessageId)>"] }
                if (-not $tr) { return $row }

                $senderOut = if ($tr.PSObject.Properties['SenderAddress']) { $tr.SenderAddress } else { $row.Sender }
                $fromOut   = if ($tr.PSObject.Properties['From']) { $tr.From } elseif ($tr.PSObject.Properties['FromAddress']) { $tr.FromAddress } else { $row.FromHeader }
                $recipientX= if ($tr.PSObject.Properties['RecipientAddress']) { $tr.RecipientAddress } else { $row.Recipient }
                $subjectX  = if ($tr.PSObject.Properties['Subject'] -and $tr.Subject) { $tr.Subject } else { $row.Subject }
                $statusX   = if ($tr.PSObject.Properties['Status']) { $tr.Status } else { $row.TraceStatus }
                $sizeX     = if ($tr.PSObject.Properties['Size'])   { $tr.Size }   else { $row.TraceSize }
                $recvUtc   = $null; if ($tr.PSObject.Properties['Received']) { $recvUtc = $tr.Received } elseif ($tr.PSObject.Properties['ReceivedTime']) { $recvUtc = $tr.ReceivedTime }

                [pscustomobject]@{
                    CreationDate       = $row.CreationDate
                    MessageId          = $row.MessageId
                    Sender             = $senderOut
                    FromHeader         = $fromOut
                    Recipient          = $recipientX
                    Subject            = $subjectX
                    TraceStatus        = $statusX
                    TraceSize          = $sizeX
                    TraceReceivedTime  = $(if ($recvUtc) { Convert-FromUtc -UtcDate $recvUtc -Tz $tzLabel } else { $row.TraceReceivedTime })
                    Operation          = $row.Operation
                    ActorUserId        = $row.ActorUserId
                    RecordType         = $row.RecordType
                    AuditRecordId      = $row.AuditRecordId
                    RawAuditDataJson   = $row.RawAuditDataJson
                }
            }
        }
    }
}
#endregion

#region Export (skip CSV if 0) — enforce consistent column order
$finalCount = ($expanded|Measure-Object).Count
if ($finalCount -eq 0) {
    Write-Log -Level INFO -Message "0 results returned for the specified criteria; skipping CSV creation."
    Disconnect-EXO
    Write-Log -Level INFO -Message "=== Completed (0 results) ==="
    return
}

# Final, consistent column order
$columns = @(
    'CreationDate',
    'MessageId',
    'Sender',
    'FromHeader',
    'Recipient',
    'Subject',
    'TraceStatus',
    'TraceSize',
    'TraceReceivedTime',
    'Operation',
    'ActorUserId',
    'RecordType',
    'AuditRecordId',
    'RawAuditDataJson'
)

Write-Log -Level INFO -Message "CSV output: $CsvFile"
try {
    $expanded | Select-Object $columns | Sort-Object CreationDate | Export-Csv -Path $CsvFile -NoTypeInformation -Encoding UTF8
    Write-Log -Level INFO -Message ("Exported {0} record(s) to CSV: {1}" -f $finalCount, $CsvFile)
} catch {
    Write-Log -Level ERROR -Message "Failed to export CSV: $($_.Exception.Message)"
    throw
}
#endregion

#region Cleanup
Disconnect-EXO
Write-Log -Level INFO -Message "=== Trace-Then-Audit Completed Successfully ==="
#endregion
