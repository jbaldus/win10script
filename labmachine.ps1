##########
# Tweaked Win10 Initial Setup Script
#
#     > powershell -nop -c "iex(New-Object Net.WebClient).DownloadString('https://git.io/Jkk2m')"
#

Function InstallChocolatey {
	Write-Output "Installing Chocolatey"
	Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
	choco install chocolatey-core.extension -y
}

Function DebloatAll {

    $Bloatware = @(
        #Windows10 Bloat
        "Microsoft.3DBuilder"
        "Microsoft.AppConnector"
        "Microsoft.BingFinance"
        "Microsoft.BingNews"
        "Microsoft.BingSports"
        "Microsoft.BingTranslator"
        "Microsoft.BingWeather"
        "Microsoft.CommsPhone"
        "Microsoft.ConnectivityStore"
        "Microsoft.GetHelp"
        "Microsoft.Getstarted"
        "Microsoft.Messaging"
        "Microsoft.Microsoft3DViewer"
        "Microsoft.MicrosoftPowerBIForWindows"
        "Microsoft.MicrosoftSolitaireCollection"
        "Microsoft.MicrosoftStickyNotes"
        "Microsoft.NetworkSpeedTest"
        "Microsoft.News"
        "Microsoft.Office.Lens"
        "Microsoft.Office.OneNote"
        "Microsoft.Office.Sway"
        "Microsoft.OneConnect"
        "Microsoft.People"
        "Microsoft.Print3D"
        "Microsoft.RemoteDesktop"
        "Microsoft.SkypeApp"
        "Microsoft.StorePurchaseApp"
        "Microsoft.Wallet"
        "Microsoft.WindowsAlarms"
        "Microsoft.WindowsCamera"
        "microsoft.windowscommunicationsapps"
        "Microsoft.WindowsFeedbackHub"
        "Microsoft.WindowsMaps"
        "Microsoft.WindowsPhone"
        "Microsoft.ZuneMusic"
        "Microsoft.ZuneVideo"

        #Sponsored Windows 10 AppX Apps
        #Add sponsored/featured apps to remove in the "*AppName*" format
        "*EclipseManager*"
        "*ActiproSoftwareLLC*"
        "*AdobeSystemsIncorporated.AdobePhotoshopExpress*"
        "*Duolingo-LearnLanguagesforFree*"
        "*PandoraMediaInc*"
        "*CandyCrush*"
        "*BubbleWitch3Saga*"
        "*Wunderlist*"
        "*Flipboard*"
        "*Twitter*"
        "*Facebook*"
        "*Spotify*"
        "*RoyalRevolt*"
        "*Sway*"
        "*Speed Test*"
        "*Dolby*"
        "2414FC7A.Viber"
        "41038Axilesoft.ACGMediaPlayer"
        "4DF9E0F8.Netflix"
        "64885BlueEdge.OneCalendar"
        "7EE7776C.LinkedInforWindows"
        "828B5831.HiddenCityMysteryofShadows"
        "89006A2E.AutodeskSketchBook"
        "A278AB0D.DisneyMagicKingdoms"
        "A278AB0D.MarchofEmpires"
        "CAF9E577.Plex"
        "D52A8D61.FarmVille2CountryEscape"
        "DB6EA5DB.CyberLinkMediaSuiteEssentials"
        "Drawboard.DrawboardPDF"
        "Facebook.Facebook"
        "GAMELOFTSA.Asphalt8Airborne"
        "KeeperSecurityInc.Keeper"
        "SpotifyAB.SpotifyMusic"
        "WinZipComputing.WinZipUniversal"
        "XINGAG.XING"
             
        #Optional: Typically not removed but you can if you need to for some reason
        #"*Microsoft.Advertising.Xaml_10.1712.5.0_x64__8wekyb3d8bbwe*"
        #"*Microsoft.Advertising.Xaml_10.1712.5.0_x86__8wekyb3d8bbwe*"
        #"*Microsoft.MSPaint*"
        #"*Microsoft.MicrosoftStickyNotes*"
        #"*Microsoft.Windows.Photos*"
        #"*Microsoft.WindowsCalculator*"
    )
    foreach ($Bloat in $Bloatware) {
        Get-AppxPackage -Name $Bloat| Remove-AppxPackage
        Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like $Bloat | Remove-AppxProvisionedPackage -Online
        Write-Output "Trying to remove $Bloat."
    }
}

# Uninstall Windows Store
Function UninstallWindowsStore {
	Write-Output "Uninstalling Windows Store..."
	Get-AppxPackage "Microsoft.DesktopAppInstaller" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.WindowsStore" | Remove-AppxPackage
}

# Disable Xbox features
Function DisableXboxFeatures {
	Write-Output "Disabling Xbox features..."
	Get-AppxPackage "Microsoft.XboxApp" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.XboxIdentityProvider" | Remove-AppxPackage -ErrorAction SilentlyContinue
	Get-AppxPackage "Microsoft.XboxSpeechToTextOverlay" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.XboxGameOverlay" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.Xbox.TCUI" | Remove-AppxPackage
	Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_Enabled" -Type DWord -Value 0
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Name "AllowGameDVR" -Type DWord -Value 0
}

# Relaunch the script with administrator privileges
Function RequireAdmin {
	If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
		Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" $PSCommandArgs" -WorkingDirectory $pwd -Verb RunAs
		Exit
	}
}

Function CreateRestorePoint {
    Write-Output "Creating Restore Point incase something bad happens"
    Enable-ComputerRestore -Drive "C:\"
    Checkpoint-Computer -Description "RestorePoint1" -RestorePointType "MODIFY_SETTINGS"
  }

Function InstallFirefoxPolicies {
    if ( -not (Test-Path -Path "C:\Program Files\Mozilla Firefox") ) {
        choco install firefox -y
    }
    New-Item -ItemType Directory -Force -Path "C:\Program Files\Mozilla Firefox\distribution" | Out-Null
    Import-Module BitsTransfer
    Start-BitsTransfer -Source "https://raw.githubusercontent.com/jbaldus/win10script/master/firefox-policies.json" -Destination "C:\Program Files\Mozilla Firefox\distribution\policies.json"
}

Function InstallPacketTracer {
    Write-Output "Start file server on teacher computer"
    WaitForKey
    $PTURL = "http://10.130.37.29/PacketTracer-7.3.1-win64-setup.exe"
    Import-Module BitsTransfer
    Start-BitsTransfer -Source $PTURL -Destination "C:\PT.exe"
    C:\PT.exe
}

Function InstallITSoftware {
    $Apps = @(
        "notepadplusplus.install"
        "7zip"
        "vlc"
        "virtualbox"
        "inkscape"
        "vscode"
        "putty.install"
        "microsoft-windows-terminal"
        "wireshark"
        "gimp"
        "python3"
        "adblockpluschrome"
        "ublockorigin-chrome"
        "lastpass-chrome"
    )
    choco install $Apps -y

    InstallFirefoxPolicies
    InstallPacketTracer
}

# Wait for key press
Function WaitForKey {
	Write-Output "Press any key to continue..."
	[Console]::ReadKey($true) | Out-Null
}


$tweaks = @(
    "RequireAdmin"
    "CreateRestorePoint"
    "InstallChocolatey"
    "DebloatAll"
    "UninstallWindowsStore"
    "DisableXboxFeatures"
    "InstallITSoftware"
)

# Call the desired tweak functions
$tweaks | ForEach { Invoke-Expression $_ }