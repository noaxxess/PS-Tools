
Param(
    # Parameter help description
    [Parameter(ValueFromPipeline = $true, Mandatory=$True, HelpMessage = "Enter ServerName to Connect to")]
    [String]
    $ServerName,

    [Parameter(ValueFromPipeline = $true, Mandatory=$True, HelpMessage = "Enter User Name")]
    [String]
    $UserName,

    [Parameter(ValueFromPipeline = $true, Mandatory=$True, HelpMessage = "Enter Password")]
    [String]
    $Pass
)

$Password = ConvertTo-SecureString "$Pass" -AsPlainText -Force

$Cred = New-Object System.Management.Automation.PSCredential("$UserName", $Pass)

$Day = (Get-Date).Day
$Month = (Get-Date).Month
$Year = (Get-Date).Year
$Now = "$Month" + "$Day" + "$Year"


$ScriptBlock1 = Get-Bpamodel | Select Name, ID | Export-CSV -Path "C:\Temp\BPA_Model_List-$Now.csv"

$Session = New-PSSession -ComputerName $ServerName -Credential $Cred
Invoke-Command -Session $Session -ScriptBlock $ScriptBlock1

Copy-Item -Path "C:\Temp\BPA_Model_List-$Now.csv" -Destination "C:\Temp\BPA_Model_List-$Now.csv" -FromSession $Session

$Session | Remove-PSSession

