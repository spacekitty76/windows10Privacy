# For regedit.ps1
* Open powershell as admin
* Run `Set-ExecutionPolicy unrestricted`
* Run `Import-Module ScheduledTasks` 
  * For some reason this doesn't work in VSCode
* Run the script
  * It won't find every service
* Run `Set-ExecutionPolicy restricted`
    
