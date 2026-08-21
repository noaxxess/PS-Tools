param (
    [Parameter(Mandatory = $true)]
    [string]$LogFile,

    [Parameter(Mandatory = $true)]
    [string]$OutputFolder
)

#Function to Log progress/results
function Write-Log {

    param (
        [string]$LogString
    )

    $logFile = Join-Path $Global:OutputFolder $Global:LogFile
    $Stamp = (Get-Date).ToString("yyyy/MM/dd HH:mm:ss")
    $LogMessage = "$Stamp $LogString"
    $LogMessage | Out-File -FilePath $logFile -Encoding utf8 -Append
}

#function to fix output of scans. Sometimes nullbytes and spaces are inserted and results are not readable
function Fix-Utf16File {

    param (
        [Parameter(Mandatory)]
        [string]$Path
    )

    # Read as bytes
    $bytes = [System.IO.File]::ReadAllBytes($Path)

    # Filter out all 0 bytes
    $cleanBytes = $bytes | Where-Object { $_ -ne 0 }

    # Decode as ASCII (basic fix)
    $text = [System.Text.Encoding]::ASCII.GetString($cleanBytes)

    # Save as UTF8
    [System.IO.File]::WriteAllText($Path, $text, [System.Text.Encoding]::UTF8)
}



#Function to Run SFC, save the output, and return result for analysis
function Run-SfcScan {

    $currentTD = (Get-Date).ToString("yyyyMMddHHmm")

    Write-Log "Starting SFC scan..."
    $outputFile = Join-Path $Global:OutputFolder "sfc_output-$currentTD.txt"
    sfc /scannow 2>&1 | Out-File -FilePath $outputFile
    Write-Log "Scan complete.Output Saved to $outputFile"

    # Clean Up OutputFile
    Write-Log "Scan complete. Cleaning up output..."
    Fix-Utf16File -Path $outputFile

    #Get End Result
    $normalizedResult = (Get-Content $outputFile).Trim()
    Write-Log "Output cleaned and saved to normalizedResult variable."
    
    if ($normalizedResult -match "Windows Resource Protection did not find any integrity violations") {
        
        Write-Log "SFC scan result: No integrity violations found."
        Write-Log "Scan Successful. Removing $outputFile"
        Remove-Item $outputFile
        Write-Log "$outputFile Removed" 
        return "NoViolations"

    } elseif ($normalizedResult -match "Windows Resource Protection could not perform the requested operation") {
        
        Write-Log "SFC scan result: Could not perform the requested operation."
        return "CouldNotRun"

    } elseif ($normalizedResult -match "Windows Resource Protection found corrupt files") {
        
        Write-Log "SFC scan result: Integrity violations found."
        return "ViolationsFound"

    } else {
        
        Write-Log "SFC scan result: Unexpected or unknown result."
        return "Unknown"

    }
}

#Function to DISM Check Health, save the output, and return result for analysis
function Run-DismCheckHealth {


    Write-Log "Starting DISM CheckHealth..."

    $currentTD = (Get-Date).ToString("yyyyMMddHHmm")

    $outputFile = Join-Path $Global:OutputFolder "dism_ch-$currentTD.txt"

    dism /online /cleanup-image /checkhealth 2>&1 | Out-File -FilePath $outputFile
    Write-Log "Scan complete.Output Saved to $outputFile"

    # Clean Up OutputFile
    Write-Log "Scan complete. Cleaning up output..."
    Fix-Utf16File -Path $outputFile

    #Get End Result
    $normalizedResult = (Get-Content $outputFile).Trim()
    Write-Log "Output cleaned and saved to normalizedResult variable."
    
    if ($normalizedResult -match "No component store corruption detected") {
        
        Write-Log "DISM CheckHealth result: No corruption detected."
        Write-Log "Scan Successful. Removing $outputFile"
        Remove-Item $outputFile
        Write-Log "$outputFile Removed" 
        return "NoCorruption"

    } elseif ($normalizedResult -match "The component store is repairable") {
       
        Write-Log "DISM CheckHealth result: Corruption detected and repairable."
        return "Repairable"

    } elseif ($normalizedResult -match "The component store cannot be repaired") {
        
        Write-Log "DISM CheckHealth result: Corruption detected but not repairable."
        return "NotRepairable"

    } else {

        Write-Log "DISM CheckHealth result: Unexpected or unknown result."
        return "Unknown"

    }
}

#Function to DISM Scanhealth, save the output, and return result for analysis
function Run-DismScanHealth {

    Write-Log "Starting DISM ScanHealth..."

    $currentTD = (Get-Date).ToString("yyyyMMddHHmm")

    $outputFile = Join-Path $Global:OutputFolder "dism_sh-$currentTD.txt"

    dism /online /cleanup-image /scanhealth 2>&1 | Out-File -FilePath $outputFile -Encoding string

    Write-Log "Scan complete.Output Saved to $outputFile"

    # Clean Up OutputFile
    Write-Log "Scan complete. Cleaning up output..."
    Fix-Utf16File -Path $outputFile

    #Get End Result
    $normalizedResult = (Get-Content $outputFile).Trim()
    Write-Log "Output cleaned and saved to normalizedResult variable."
    $normalizedResult = (Get-Content $outputFile).Trim()

    if ($normalizedResult -match "No component store corruption detected") {
        
        Write-Log "DISM ScanHealth result: No corruption detected."
        Write-Log "Scan Successful. Removing $outputFile"
        Remove-Item $outputFile
        Write-Log "$outputFile Removed" 
        return "NoCorruption"

    } elseif ($normalizedResult -match "The component store is repairable") {
        
        Write-Log "DISM ScanHealth result: Corruption detected and repairable."
        return "Repairable"
    
    } elseif ($normalizedResult -match "The component store cannot be repaired") {
    
        Write-Log "DISM ScanHealth result: Corruption detected but not repairable."
        return "NotRepairable"
    
    } else {
        
        Write-Log "DISM ScanHealth result: Unexpected or unknown result."
        return "Unknown"
    
    }
}

#Function to Run DISM Restore Health, save the output, and return result for analysis
function Run-DismRestoreHealth {

    Write-Log "Starting DISM RestoreHealth..."
    $outputFile = Join-Path $Global:OutputFolder "dism_rh-$currentTD.txt"

    dism /online /cleanup-image /restorehealth 2>&1 | Out-File -FilePath $outputFile -Encoding string

    Write-Log "Scan complete.Output Saved to $outputFile"

    # Clean Up OutputFile
    Write-Log "Scan complete. Cleaning up output..."
    Fix-Utf16File -Path $outputFile

    #Get End Result
    $normalizedResult = (Get-Content $outputFile).Trim()
    Write-Log "Output cleaned and saved to normalizedResult variable."
    $normalizedResult = (Get-Content $outputFile).Trim()

    if ($normalizedResult -match "The restore operation completed successfully" -or $normalizedResult -match "The operation completed successfully") {

        Write-Log "DISM RestoreHealth result: Completed successfully."
        Write-Log "Corruption repaired. Removing $outputFile"
        Remove-Item $outputFile
        Write-Log "$outputFile Removed" 
        return "Success"

    } elseif ($normalizedResult -match "The restore operation failed") {

        Write-Log "DISM Restore Helath result: Failed."
        return "Failed"

    } else {

        Write-Log "DISM RestoreHealth result: Unexpected or unknown result."
        return "Unknown"

    }
}

# Give Log parameters global scope
$Global:LogFile = $LogFile
$Global:OutputFolder = $OutputFolder

# Ensure output folder exists. If not, create it.
if (-not (Test-Path $Global:OutputFolder)) {

    New-Item -ItemType Directory -Path $Global:OutputFolder | Out-Null

}

#Run SFC Scan and save result to variable
$sfcStatus = Run-SfcScan

#Run DISM Check Health and save result to variable
$dismStatus = Run-DismCheckHealth

#Analyze results and run further scan/repair if necessary
if ($sfcStatus -eq "NoCorruption" -and $dismStatus -eq "NoCorruption") {

    Write-Log "Scanning Complete. No Issues Found."
    return $sfcStatus

} else {

    $dismScanStatus = Run-DismScanHealth

    if ($dismScanStatus -eq "Repairable") {

        $dismRestoreStatus = Run-DismRestoreHealth

        if(!($dismRestoreStatus -eq "Success")){

            Write-Log "DISM Restore Result: $dismRestoreStatus"
            Write-Log "DISM Unsuccessful please check CBS log and troubleshoot further."
            return $dismRestoreStatus
        
        } else {
        
            Write-Log "Clearing old sfcStatus variable."
            $sfcStatus = ""
            Write-Log "Running second SFC scan..."
            $sfcStatus = Run-SfcScan
            Write-Log "SFC Result: $sfcStatus"
            Write-Log "Scanning and repair concluded."
            return $dismRestoreStatus
            
        }

    } else {

        Write-Log "DISM ScanHalth Result: $dismScanStatus"
        Write-Log "Please check CBS log and troubleshoot further"
        return $dismScanStatus
        
    }
}
