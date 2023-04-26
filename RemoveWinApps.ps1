$packages = 'Microsoft.3DBuilder',
    'Microsoft.BingFinance', 
    'Microsoft.BingFoodAndDrink', 
    'Microsoft.BingHealthAndFitness',
    'Microsoft.BingTravel',
    'Microsoft.Getstarted',
    'Microsoft.Wallet',
    'Microsoft.windowscommunicationsapps',
    'Microsoft.WindowsReadingList',
    'Microsoft.ZuneVideo',
    'Microsoft.XboxIdentityProvider',
    'Microsoft.XboxGameCallableUI',
    'Microsoft.SkypeApp',
    'Microsoft.WindowsAlarms',
    'Microsoft.ZuneMusic',
    'Microsoft.XboxSpeechToTextOverlay',
    'Microsoft.XboxGameOverlay',
    'Microsoft.XboxApp',
    'Microsoft.WindowsSoundRecorder',
    'Microsoft.WindowsPhone',
    'Microsoft.WindowsMaps',
    'Microsoft.People',
    'Microsoft.OneConnect',
    'Microsoft.Office.Sway', 
    'Microsoft.Microsoft3DViewer',
    'Microsoft.Messaging',
    'Microsoft.DesktopAppInstaller',
    'Microsoft.ConnectivityStore',
    'Microsoft.CommsPhone',
    'Microsoft.BingWeather', 
    'Microsoft.BingSports',
    'Microsoft.BingNews',
    'Microsoft.Appconnector' 

ForEach ($package in $packages) { 
    
    Get-AppxPackage -Name $package -AllUsers | Remove-AppxPackage

    Get-AppXProvisionedPackage -Online |
        where Name -EQ $package |
        Remove-AppxProvisionedPackage -Online

}