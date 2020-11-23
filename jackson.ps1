##########
# Tweaked Win10 Initial Setup Script
#
#     > iex(New-Object Net.WebClient).DownloadString('https://git.io/Jk6rq')
#

Function InstallChocolatey {
	Write-Output "Installing Chocolatey"
	Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
	choco install chocolatey-core.extension -y
}

Function DebloatAll {

    $Bloatware = @(
        #Windows10 Bloat
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
        "Microsoft.Wallet"
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

# Relaunch the script with administrator privileges
Function RequireAdmin {
	If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
		Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" $PSCommandArgs" -WorkingDirectory $pwd -Verb RunAs
		Exit
	}
}

Function CreateRestorePoint {
    Write-Output "Creating Restore Point in case something bad happens"
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
    $IP = Read-Host "What is the IP address of teacher computer?"
    Write-Output "Rename PacketTracer installater to PacketTracer.exe on teacher computer"
    Write-Output "Start file server on teacher computer with 'python -m http.server' in the directory containing PacketTracer.exe"
    WaitForKey
    $PTURL = "http://$IP/PacketTracer.exe"
    Import-Module BitsTransfer
    Start-BitsTransfer -Source $PTURL -Destination "C:\PT.exe"
    C:\PT.exe
}

Function InstallSoftware {
    InstallPacketTracer
    $Apps = @(
        "notepadplusplus.install"
        "7zip"
        "adobereader"
        "vlc"
        "googlechrome"
        "adblockpluschrome"
        "ublockorigin-chrome"
        "lastpass-chrome"
    )
    foreach ($App in $Apps) {
        choco install $App -y
    }

    InstallFirefoxPolicies
}

# Wait for key press
Function WaitForKey {
	Write-Output "Press any key to continue..."
	[Console]::ReadKey($true) | Out-Null
}

# Unpin all Taskbar icons - Note: This function has no counterpart. You have to pin the icons back manually.
Function UnpinTaskbarIcons {
	Write-Output "Unpinning all Taskbar icons..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Taskband" -Name "Favorites" -Type Binary -Value ([byte[]](255))
	Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Taskband" -Name "FavoritesResolve" -ErrorAction SilentlyContinue
}


$tweaks = @(
    "RequireAdmin"
    "CreateRestorePoint"
    "InstallChocolatey"
    "DebloatAll"
    "InstallSoftware"
    "UnpinTaskbarIcons"
)

# Call the desired tweak functions
$tweaks | ForEach { Invoke-Expression $_ }