Function ChangeReg {
  param ([string] $RegKey,
         [string] $Value,
         [string] $SvcName,
         [Int] $CheckValue,
         [Int] $SetData)
  Write-Host "Checking if $SvcName is enabled" -ForegroundColor Green
  if (!(Test-Path $RegKey)){
      Write-Host "Registry Key for service $SvcName does not exist, creating it now" -ForegroundColor Yellow
      New-Item -Path (Split-Path $RegKey) -Name (Split-Path $RegKey -Leaf) 
     }
 $ErrorActionPreference = 'Stop'
 try{
      Get-ItemProperty -Path $RegKey -Name $Value 
      if((Get-ItemProperty -Path $RegKey -Name $Value).$Value -eq $CheckValue) {
          Write-Host "$SvcName is enabled, disabling it now" -ForegroundColor Green
          Set-ItemProperty -Path $RegKey -Name $Value -Value $SetData -Force
         }
      if((Get-ItemProperty -Path $RegKey -Name $Value).$Value -eq $SetData){
             Write-Host "$SvcName is disabled" -ForegroundColor Green
         }
     } catch [System.Management.Automation.PSArgumentException] {
       Write-Host "Registry entry for service $SvcName doesn't exist, creating and setting to disable now" -ForegroundColor Yellow
       New-ItemProperty -Path $RegKey -Name $Value -Value $SetData -Force
      }
   }
  
 # Disabling Advertising ID
 $RegKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo"
 $Value = "Enabled"
 $SvcName = "Advertising ID"
 $CheckValue = 1
 $SetData = 0
 ChangeReg -RegKey $RegKey -Value $Value -SvcName $SvcName -CheckValue $CheckValue -SetData $SetData
 #Telemetry Disable
 $RegKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
 $Value = "AllowTelemetry"
 $SvcName = "Telemetry"
 $CheckValue = 1
 $SetData = 0        
 ChangeReg -RegKey $RegKey -Value $Value -SvcName $SvcName -CheckValue $CheckValue -SetData $SetData
 #Infection Information Disable
 $RegKey = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\MRT"
 $Value = "Enabled"
 $SvcName = "DontReportInfectionInformation"
 $CheckValue = 1
 $SetData = 0
 #Application Telemetry Disable
 $RegKey = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat"
 $Value = "Enabled"
 $SvcName = "DisableInventory"
 $CheckValue = 1
 $SetData = 0
 #Disable Program Compatibility
 $RegKey = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat"
 $Value = "Enabled"
 $SvcName = "DisablePCA"
 $CheckValue = 1
 $SetData = 0
 #Disable Steps Recorder
 $RegKey = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat"
 $Value = "Enabled"
 $SvcName = "DisableUAR"
 $CheckValue = 1
 $SetData = 0
 #Disable Customer Experience
 $RegKey = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\SQMClient\Windows"
 $Value = "Enabled"
 $SvcName = "CEIPEnable"
 $CheckValue = 0
 $SetData = 0
 #Disable Inventory Collection
 $RegKey = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat"
 $Value = "Enabled"
 $SvcName = "AITEnable"
 $CheckValue = 0
 $SetData = 0
 #Remove OneDrive
 $RegKey = "HKEY_CLASSES_ROOT\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}"
 $Value = "Enabled"
 $SvcName = "System.IsPinnedToNameSpaceTree"
 $CheckValue = 0
 $SetData = 0
 #Disable Tamper Protection
 $RegKey = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Features"
 $Value = "Enabled"
 $SvcName = "TamperProtection"
 $CheckValue = 0
 $SetData = 0
 #Malware Protection Disable
 $RegKey = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet"
 $Value = "Enabled"
 $SvcName = "SpyNetReporting"
 $CheckValue = 0
 $SetData = 0
 $RegKey = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet"
 $Value = "Enabled"
 $SvcName = "SubmitSamplesConsent"
 $CheckValue = 2
 $SetData = 0
 #Disable Malicious Software Reporting
 $RegKey = "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\MRT"
 $Value = "Enabled"
 $SvcName = "DontReportInfectionInformation"
 $CheckValue = 1
 $SetData = 0
 #Defender Enhanced Notifications
 $RegKey = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting"
 $Value = "Enabled"
 $SvcName = "DisableEnhancedNotifications"
 $CheckValue = 1
 $SetData = 0
 #Anti Spyware
 $RegKey = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender"
 $Value = "Enabled"
 $SvcName = "DisableAntiSpyware"
 $CheckValue = 1
 $SetData = 0
 #SmartScreen Disable
 $RegKey = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost\EnableWebContentEvaluation"
 $Value = "Enabled"
 $SvcName = "Smart Screen"
 $CheckValue = 1
 $SetData = 0
 ChangeReg -RegKey $RegKey -Value $Value -SvcName $SvcName -CheckValue $CheckValue -SetData $SetData
 Write-Host "Disabling DiagTrack Services" -ForegroundColor Green 
 Get-Service -Name DiagTrack | Set-Service -StartupType Disabled | Stop-Service
 Get-Service -Name dmwappushservice | Set-Service -StartupType Disabled | Stop-Service
 Write-Host "DiagTrack Services are disabled" -ForegroundColor Green 
 Write-Host "Disabling telemetry scheduled tasks" -ForegroundColor Green
 $tasks ="SmartScreenSpecific","ProgramDataUpdater","Microsoft Compatibility Appraiser","AitAgent","Proxy","Consolidator",
         "KernelCeipTask","BthSQM","CreateObjectTask","Microsoft-Windows-DiskDiagnosticDataCollector","WinSAT",
         "GatherNetworkInfo","FamilySafetyMonitor","FamilySafetyRefresh","SQM data sender","OfficeTelemetryAgentFallBack",
         "OfficeTelemetryAgentLogOn"
 $ErrorActionPreference = 'Stop'
 $tasks | %{
    try{
       Get-ScheduledTask -TaskName $_ | Disable-ScheduledTask
       } catch [Microsoft.PowerShell.Cmdletization.Cim.CimJobException] { 
    "task $($_.TargetObject) is not found"
    }
 }