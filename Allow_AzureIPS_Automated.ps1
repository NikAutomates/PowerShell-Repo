$RootPageResponse = Invoke-RestMethod -Uri "https://www.microsoft.com/en-us/download/details.aspx?id=56519"
[string]$JsonDownloadUri = [regex]::Matches($RootPageResponse, 'https?://[A-Za-z0-9./_-]+\.json').value[0]

$AzureAutomationIPS = ((Invoke-RestMethod -Uri $JsonDownloadUri).values | 
Where-Object { $_.Properties.systemService.Equals('AzureAutomation') `
-or $_.name.Equals('AzureCloud.eastus')}).Properties.addressPrefixes

return $AzureAutomationIPS
