#Powershell style.
#Only compatible from Windows 8 and up

if ([Environment]::OSVersion.Version -lt (new-object 'Version' 10,0)) {
    Exit
}

ipmo ScheduledTasks

Function GetStringFromIniFile( [parameter(mandatory = $true)][string]$iniFile, [parameter(mandatory = $true)][string]$key) {
    $iniContent = Get-Content $iniFile
    [string]$regex = "^\s*${key}\s*=\s*`"(?<value>.*)`"\s*;\s*$"

    $matchingLines = $iniContent -match $regex
    if ($matchingLines.Length -lt 1) {
        throw "Key '$key' not found in INI file '$iniFile'"
    } elseif ($matchingLines.Length -gt 1) {
        throw "More than one '$key' key found in INI file '$iniFile'"
    }
    # At this point we know the regular expression matches and there is exactly one match
    $matchingLines[0] -match $regex | Out-Null
    return $matches.value
}

[string]$keytalk_install_path = GetStringFromIniFile $env:allusersprofile\KeyTalk\resept.ini 'Install'
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).Date
[string] $command_to_execute = $keytalk_install_path + '\ReseptConfigTool.exe'
[string] $args_to_execute = '"'+$command_to_execute+'" task validatecert'
$action = New-ScheduledTaskAction -Execute $keytalk_install_path'\RunSilentAsync.vbs' -Argument $args_to_execute
# Keep the task name in sync with ReseptClientInstaller.wxs 'UnScheduleValidateCertificate'. Removal is based on task name.
[string]$task_name = 'KeyTalk Certificate Validation Check'
$description = 'Checks whether the KeyTalk certificate is still valid on a regular basis'

Register-ScheduledTask -Action $action -Trigger $trigger -TaskName $task_name -Description $description

$task = Get-ScheduledTask -TaskName $task_name
$task.Triggers.Repetition.Duration = "P10950D" # 30 years should be plenty
$task.Triggers.Repetition.Interval = "PT5M" # 5 minute interval

$task | Set-ScheduledTask