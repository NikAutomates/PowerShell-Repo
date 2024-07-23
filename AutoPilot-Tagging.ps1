$clientid = "40fdbbd4-dc75-4e90-9430-50929c1ef1ce"
$Secret = Get-AutomationVariable -Name 'ClientSecret-MEM'
$TenantName = "apex4health.com"
$resource = "https://graph.microsoft.com/"
$grouptag = "Standard"

$Body = @{
    Grant_Type    = "client_credentials"
    Scope         = "https://graph.microsoft.com/.default"
    client_Id     = $clientID
    Client_Secret = $Secret
} 

$TokenResponse = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$TenantName/oauth2/v2.0/token" -Method POST -Body $Body
$GraphUrl = 'https://graph.microsoft.com/beta/deviceManagement/windowsAutopilotDeviceIdentities/'
$Data = Invoke-RestMethod -Headers @{Authorization = "Bearer $($TokenResponse.access_token)"} -Uri $GraphUrl -Method Get
$Devices = ($Data | Select-Object Value).Value | 
    Where-Object {$_.groupTag -ne "Standard" -and $_.model -ne "Virtual Machine"} | 
       Select-Object -ExpandProperty ID


$body = '{"groupTag":"'+$groupTag+'"}'

foreach ($device in $Devices) {
    $GraphUrl = "https://graph.microsoft.com/beta/deviceManagement/windowsAutopilotDeviceIdentities/$device/UpdateDeviceProperties"
    Invoke-RestMethod -Headers @{Authorization = "Bearer $($TokenResponse.access_token)"} -Uri $GraphUrl -Body $body -Method Post -ContentType 'application/json'
    Write-Output ($device + ' has been tagged: ' + $grouptag)
}

$GraphURLDeviceMgmt = "https://graph.microsoft.com/beta/deviceManagement/windowsAutopilotSettings/sync"
Invoke-RestMethod -Headers @{Authorization = "Bearer $($TokenResponse.access_token)"} -Uri $GraphURLDeviceMgmt -Method Post
