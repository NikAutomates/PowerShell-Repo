###Consent the following permissions on ClientID###

<#
DeviceManagementConfiguration.ReadWrite.All
DeviceManagementServiceConfig.ReadWrite.All
Group.ReadWrite.All
Directory.ReadWrite.All
#>
function Get-OAuthToken {
    [CmdletBinding()]
    param (
        [parameter(Mandatory = $true)]
        [string]$ClientID,
        [parameter(Mandatory = $true)]
        [string]$ClientSecret,
        [parameter(Mandatory = $true)]
        [string]$TenantName  
    )

    [hashtable]$Body = [System.Collections.Specialized.OrderedDictionary]::new()
    [hashtable]$TokenSplat = [System.Collections.Specialized.OrderedDictionary]::new()
 
    [hashtable]$Body.Add("Grant_Type", [string]"client_credentials")
    [hashtable]$Body.Add("Scope", [string]"https://graph.microsoft.com/.default")
    [hashtable]$Body.Add("client_Id", [string]$ClientID) #add client ID here
    [hashtable]$Body.Add("Client_Secret", [string]$ClientSecret) #Use keyvault to extract secret
    [hashtable]$TokenSplat.Add("Uri", [string]"https://login.microsoftonline.com/$($TenantName)/oauth2/v2.0/token") #add tenant name here
    [hashtable]$TokenSplat.Add("Method", [string]"POST")
    [hashtable]$TokenSplat.Add("Body", [hashtable]$Body)
 
    $global:Token = (Invoke-RestMethod @TokenSplat).access_token

}
 
$TokenSplat.clear()
 
<#
.SYNOPSIS
   This function performs REST API Calls against the Graph API Endpoints
.DESCRIPTION
   This function can be used with a bearer token you retrieve, or by escrowing a bearer token which is called as a nested function
.NOTES
   Author: Nik Chikersal
   Date: 4/12/2024
   Version: V1.1.0
   If using -UseDelegatedPermissions Param, configure the following URLs as re-direct URIs on your app reg:
   https://login.microsoftonline.com/common/oauth2/nativeclient
   https://login.live.com/oauth20_desktop.srf
   msalb4991893-6d74-4d48-a870-b6af8858ccb0://auth
   Type: Mobile and desktop applications
   Public flows: ON
   Ensure to Assign the proper delegated graph API permissions on the app reg
   If using -UseMSI Param, ensure the script is running in an Azure Automation Account within a PowerShell Runbook
   Change Log:
   4/16/2024 - Added additional param validation and -BearerToken as optional positional param
   4/19/2024 - Added -UseDelegatedPermissions as optional positional param
.LINK
https://www.powershellgallery.com/packages/Graph/
     
.EXAMPLE
   Invoke-GraphAPIRequest -ClientID "8c193358-c9c9-4255e-acd8c28f4a" -TenantName "MyDomain.com" -URL "https://graph.microsoft.com/v1.0/devices" -Method GET -RunbookUserName "ClientSecret-Graph"
   This example will retrieve a bearer token from the credential in the Automation Account and autmatically set it on the Runbooks canvas, then perform a REST API Call
 
   Invoke-GraphAPIRequest -ClientID "8c193358-c9c9-4255-bc0e-acd8c28f4a" -TenantName "MyDomain.com" -URL "https://graph.microsoft.com/v1.0/devices" -Method GET -LocalTest
   This example will retrieve a bearer token from the clientSecret entered into the prompt, then perform a REST API Call
 
   Invoke-GraphAPIRequest -URL "https://graph.microsoft.com/v1.0/devices" -Method GET -AccessToken "ZiVm9waEZQWjVsd1lxMHB3V2wtdmxsUXBYSkpTTkkiLCJhbGciOiJSUzI1NiIsIng1dCI6In"
   This example will allow you to pass in your own Bearer Token and perform a REST API call
   Invoke-GraphAPIRequest -URL "https://graph.microsoft.com/v1.0/devices" -Method GET -UseMSI
   This example will allow you to retrieve a bearer token using an MSI and perform a REST API Call
   Invoke-GraphAPIRequest -ClientID "8c193358-c9c9-4255-bc0e-acd8c28f4a" -TenantName "MyDomain.com" -URL "https://graph.microsoft.com/v1.0/devices" -Method GET -UseDelegatedPermissions
   This example will retrieve a bearer token from the ClientID using delegated permissions and the configured app registration re-direct URIs for auth, followed by a REST API Call
   Invoke-GraphAPIRequest -ClientID "8c193358-c9c9-4255e-acd8c28f4a" -TenantName "MyDomain.com" -URL "https://graph.microsoft.com/v1.0/devices" -Method POST -JsonBody $body -RunbookUserName "ClientSecret-Graph"
   This example will retrieve a bearer token from the credential in the Automation Account and autmatically set it on the Runbooks canvas, then perform a POST REST API Call
 
   Invoke-GraphAPIRequest -ClientID "8c193358-c9c9-4255-bc0e-acd8c28f4a" -TenantName "MyDomain.com" -URL "https://graph.microsoft.com/v1.0/devices" -Method POST -JsonBody $body -LocalTest
   This example will retrieve a bearer token from the clientSecret entered into the prompt, then perform a POST REST API Call
 
   Invoke-GraphAPIRequest -URL "https://graph.microsoft.com/v1.0/devices" -Method POST -JsonBody $body -AccessToken "ZiVm9waEZQWjVsd1lxMHB3V2wtdmxsUXBYSkpTTkkiLCJhbGciOiJSUzI1NiIsIng1dCI6In"
   This example will allow you to pass in your own Bearer Token and perform a POST REST API call
   Invoke-GraphAPIRequest -ClientID "8c193358-c9c9-4255-bc0e-acd8c28f4a" -TenantName "MyDomain.com" -URL "https://graph.microsoft.com/v1.0/devices" -Method POST -JsonBody $body -UseDelegatedPermissions
   This example will retrieve a bearer token from the ClientID using delegated permissions and the configured app registration re-direct URIs for auth, followed by a POST REST API Call
   Invoke-GraphAPIRequest -URL "https://graph.microsoft.com/v1.0/devices" -Method GET -UseMSI
   This example will allow you to retrieve a bearer token using an MSI and perform a POST REST API Call
#>
function Invoke-GraphAPIRequest {
    [CmdletBinding()]
    [Alias('Invoke-APIRequest')]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [ArgumentCompleter({
                param(
                    [string]$commandName,
                    [string]$parameterName,
                    [string]$wordToComplete,
                    [System.Management.Automation.Language.CommandAst]$commandAst,
                    [System.Collections.IDictionary]$fakeBoundParameters
                )
 
                [array]$GraphURLs = [System.Collections.Generic.List[object]](
                    'https://graph.microsoft.com/v1.0/users',
                    'https://graph.microsoft.com/v1.0/groups'
                )
 
                $ArgCompletionResults = [System.Collections.Generic.List[System.Management.Automation.CompletionResult]]::new()
                foreach ($Url in $GraphURLs) {
                    if ($Url -like "$wordToComplete*") {
                        [void]$ArgCompletionResults.Add(
                            [System.Management.Automation.CompletionResult]::new($Url, $Url, 'ParameterValue', $Url)
                        )
                    }
                }
                return $ArgCompletionResults
            })]
        [ValidatePattern('^https?')]
        [ValidateNotNullOrEmpty()]
        [string]$GraphURL,
        [Parameter(Mandatory = $false, ValueFromPipeline = [boolean]$true, ValueFromPipelineByPropertyName = [boolean]$true)]
        [ValidateNotNullOrEmpty()][ValidateLength('30', '36')]
        [string]$ClientID,
        [Parameter(Mandatory = $false, ValueFromPipeline = [boolean]$true, ValueFromPipelineByPropertyName = [boolean]$true)]
        [ValidateNotNullOrEmpty()]
        [string]$TenantName,
        [Parameter(Mandatory = $true, ValueFromPipeline = [boolean]$true, ValueFromPipelineByPropertyName = [boolean]$true)]
        [ValidateSet("GET", "DELETE", "POST", "PATCH", "PUT")][ValidateNotNullOrEmpty()]
        [string]$Method,
        [Parameter(Mandatory = $false, ValueFromPipeline = [boolean]$true, ValueFromPipelineByPropertyName = [boolean]$true)]
        <#[ArgumentCompletions('$JsonBody', '(Get-Content -Path JsonFile.json)')]#>
        [string]$JsonBody,
        [Parameter(Mandatory = $false)]
        [switch]$LocalTest,
        [Parameter(Mandatory = $false, ValueFromPipeline = [boolean]$true, ValueFromPipelineByPropertyName = [boolean]$true)]
        [string]$RunbookUsername,
        [Parameter(Mandatory = $false, ValueFromPipeline = [boolean]$true, ValueFromPipelineByPropertyName = [boolean]$true)]
        [switch]$UseDelegatedPermissions,
        [Parameter(Mandatory = $false, ValueFromPipeline = [boolean]$true, ValueFromPipelineByPropertyName = [boolean]$true)]
        [switch]$UseMSI,
        [Parameter(Mandatory = $false, ValueFromPipeline = [boolean]$true, ValueFromPipelineByPropertyName = [boolean]$true)]
        [string]$AccessToken
    )
   
    begin {
       
        $global:Results = [System.Collections.ArrayList]::new()
        #Var checks necessary here, if user enters CTRL + C during the API Call (s), The end block won't intiliaze to the (dispose) cleanup method call
 
        $VarCheck = [System.Collections.Generic.List[object]]($ChildHash, $SplatArgs)
        foreach ($var in $VarCheck) {
            if (-not ([string]::IsNullOrEmpty($var))) {
                $ChildHash.Clear()
                $SplatArgs.Clear()
            }
        }
        #Param validation to ensure the correct switch or string input object params are being passed into the function
        if (-not $PSCmdlet.MyInvocation.BoundParameters["AccessToken"] -and
           (-not $PSCmdlet.MyInvocation.BoundParameters["RunbookUsername"] -and
           (-not $PSCmdlet.MyInvocation.BoundParameters["LocalTest"] -and
           (-not $PSCmdlet.MyInvocation.BoundParameters["UseDelegatedPermissions"] -and
           (-not $PSCmdlet.MyInvocation.BoundParameters["UseMSI"]))))) {
           
            throw "You must include at least one of the following parameters: -LocalTest, -RunbookUserName, -AccessToken, -UseDelegatedPermissions, -UseMSI"
        }
       
        #Switch statement to extract the input parameters being used, follow by additional param validation before extracting bearer token
        switch ($PSCmdlet.MyInvocation.BoundParameters.Keys) {
 
            "UseMSI" {
                if ($PSCmdlet.MyInvocation.BoundParameters.Keys.Contains("LocalTest") -or
                   ($PSCmdlet.MyInvocation.BoundParameters.Keys.Contains("RunbookUsername") -or
                   ($PSCmdlet.MyInvocation.BoundParameters.Keys.Contains("UseDelegatedPermissions") -or
                   ($PSCmdlet.MyInvocation.BoundParameters.Keys.Contains("AccessToken") -or
                   ($PSCmdlet.MyInvocation.BoundParameters.Keys.Contains("ClientID") -or
                   ($PSCmdlet.MyInvocation.BoundParameters.Keys.Contains("TenantName"))))))) {
                    throw "You must ONLY use the -UseMSI, -GraphURL, -Method Parameters when using the -UseMSI Parameter"
                }
                else {
                    [string](Get-BearerToken -UseMSI) #This is a nested function that runs from the 'AzureSecrets' Module (required module in this modules Manifest file)
                }
            }
 
            "LocalTest" {
                if ($PSCmdlet.MyInvocation.BoundParameters.ContainsKey("RunbookUsername") -or
                   ($PSCmdlet.MyInvocation.BoundParameters.ContainsKey("AccessToken") -or
                   ($PSCmdlet.MyInvocation.BoundParameters.ContainsKey("UseDelegatedPermissions")))) {
         
                    throw "You must not include the -AccessToken, -RunbookUsername, -UseDelegatedPermissions Parameters when using the -LocalTest Parameter"
                }
                elseif ($PSCmdlet.MyInvocation.BoundParameters.ContainsKey("ClientID") -and
                    $PSCmdlet.MyInvocation.BoundParameters.ContainsKey("TenantName")) {
         
                    $BearerToken = Get-BearerToken -ClientID $ClientID -TenantName $TenantName -LocalTest
                }
                else {
                    throw "You must include the -ClientID and -TenantName Parameters when using the -LocalTest Parameter"
                }
            }
           
            "RunbookUsername" {
                if ($PSCmdlet.MyInvocation.BoundParameters.ContainsKey("LocalTest") -or
                ($PSCmdlet.MyInvocation.BoundParameters.ContainsKey("AccessToken") -or
                ($PSCmdlet.MyInvocation.BoundParameters.ContainsKey("UseDelegatedPermissions")))) {
         
                    throw "You must not include the -AccessToken, -LocalTest, -UseDelegatedPermissions Parameters when using the -RunbookUsername Parameter"
                }
                elseif ($PSCmdlet.MyInvocation.BoundParameters.ContainsKey("ClientID") -and
                    $PSCmdlet.MyInvocation.BoundParameters.ContainsKey("TenantName")) {
         
                    $BearerToken = Get-BearerToken -ClientID $ClientID -TenantName $TenantName -RunbookUsername $RunbookUsername
                }
                else {
                    throw "You must include the -ClientID and -TenantName Parameters when using the -RunbookUsername Parameter"
                }
               
            }
            "AccessToken" {
                if (-not $PSCmdlet.MyInvocation.BoundParameters.ContainsKey("LocalTest") -and
                   (-not $PSCmdlet.MyInvocation.BoundParameters.ContainsKey("RunbookUserName") -and
                   (-not $PSCmdlet.MyInvocation.BoundParameters.ContainsKey("ClientID") -and
                   (-not $PSCmdlet.MyInvocation.BoundParameters.ContainsKey("TenantName") -and
                   (-not $PSCmdlet.MyInvocation.BoundParameters.ContainsKey("TenantName")))))) {
                   
                    $BearerToken = $AccessToken
                }
                else {
                    throw "You must not include the -LocalTest or -RunbookUserName or -ClientID or -UseDelegatedPermissions Parameters when using the -AccessToken Parameter"
                }
            }
            "UseDelegatedPermissions" {
 
                if ($PSCmdlet.MyInvocation.BoundParameters.ContainsKey("RunbookUsername") -or
                ($PSCmdlet.MyInvocation.BoundParameters.ContainsKey("AccessToken") -or
                ($PSCmdlet.MyInvocation.BoundParameters.ContainsKey("LocalTest")))) {
         
                    throw "You must not include the -AccessToken, -RunbookUsername, -LocalTest Parameters when using the -UseDelegatedPermissions Parameter"
                }
                elseif ($PSCmdlet.MyInvocation.BoundParameters.ContainsKey("ClientID") -and
                    $PSCmdlet.MyInvocation.BoundParameters.ContainsKey("TenantName")) {
         
                    $BearerToken = Get-BearerToken -ClientID $ClientID -TenantName $TenantName -UseDelegatedPermissions
                }
                else {
                    throw "You must include the -ClientID and -TenantName Parameters when using the -UseDelegatedPermissions Parameter"
                }
            }
        }
    }
    process {
 
        #Depending on the Input string object passed to the -Method parameter, we will perform different logic for different API Requests
        switch ($PSCmdlet.MyInvocation.BoundParameters["Method"]) {
 
            "DELETE" {
 
                [hashtable]$SplatArgs = [System.Collections.Specialized.OrderedDictionary]::new()
                [hashtable]$ChildHash = [System.Collections.Specialized.OrderedDictionary]::new()
 
                $ChildHash.Add('Authorization', "Bearer $($BearerToken)")
                $SplatArgs.Add('Uri', [string]$GraphURL)
                $SplatArgs.Add('Headers', $ChildHash)
                $SplatArgs.Add('Method', [string]$Method)
 
                try {
                    Invoke-RestMethod @SplatArgs
                }
                catch [System.Exception] {
                    return [PSCustomObject]@{
                        CommandException = $($Global:Error[0])
                    }
                }
            }
            "GET" {
                   
                [hashtable]$SplatArgs = [System.Collections.Specialized.OrderedDictionary]::new()
                [hashtable]$ChildHash = [System.Collections.Specialized.OrderedDictionary]::new()
 
                [hashtable]$ChildHash.Add('Authorization', "Bearer $($BearerToken)")
                [hashtable]$SplatArgs.Add('Uri', [string]$GraphURL)
                [hashtable]$SplatArgs.Add('Headers', $ChildHash)
                [hashtable]$SplatArgs.Add('Method', [string]$Method)
 
                try {
                    do {
                        [array]$GraphResponse = Invoke-RestMethod @SplatArgs
                        foreach ($Response in $GraphResponse.Value) {
                            [void]$Results.Add($Response)
                        }
                        $SplatArgs["Uri"] = $GraphResponse."@odata.nextLink"
                    } while ($SplatArgs["Uri"])
                    #Can't do a return statement here, or the end block will NOT return
                    $global:Results
             
                }
                catch [System.Exception] {
                    return [PSCustomObject]@{
                        CommandException = $($Global:Error[0])
                    }
                }
            }
            "POST" {
                if (-not ($PSCmdlet.MyInvocation.BoundParameters.ContainsKey("JsonBody"))) {
                    throw "You must include the -JSON body parameter when using the POST Method in the -Method Parameter"
                }
 
                [hashtable]$SplatArgs = [System.Collections.Specialized.OrderedDictionary]::new()
                [hashtable]$ChildHash = [System.Collections.Specialized.OrderedDictionary]::new()
 
                [hashtable]$ChildHash.Add('Authorization', "Bearer $($BearerToken)")
                [hashtable]$SplatArgs.Add('Uri', [string]$GraphURL)
                [hashtable]$SplatArgs.Add('Headers', $ChildHash)
                [hashtable]$SplatArgs.Add('Method', [string]$Method)
                [hashtable]$SplatArgs.Add('ContentType', [string]'application/json')
                [hashtable]$SplatArgs.Add('Body', $JsonBody)
 
                try {
                    Invoke-RestMethod @SplatArgs
                }
                catch [System.Exception] {
                    return [PSCustomObject]@{
                        CommandException = $($Global:Error[0] | fl)
                    }
                }  
            }
            "PUT" {
                if (-not ($PSCmdlet.MyInvocation.BoundParameters.ContainsKey("JsonBody"))) {
                    throw "You must include the -JSON body parameter when using the PUT Method in the -Method Parameter"
                }
 
                [hashtable]$SplatArgs = [System.Collections.Specialized.OrderedDictionary]::new()
                [hashtable]$ChildHash = [System.Collections.Specialized.OrderedDictionary]::new()
 
                [hashtable]$ChildHash.Add('Authorization', "Bearer $($BearerToken)")
                [hashtable]$SplatArgs.Add('Uri', [string]$GraphURL)
                [hashtable]$SplatArgs.Add('Headers', $ChildHash)
                [hashtable]$SplatArgs.Add('Method', [string]$Method)
                [hashtable]$SplatArgs.Add('ContentType', [string]'application/json')
                [hashtable]$SplatArgs.Add('Body', $JsonBody)
 
                try {
                    Invoke-RestMethod @SplatArgs
                }
                catch [System.Exception] {
                    return [PSCustomObject]@{
                        CommandException = $($Global:Error[0])
                    }
                }
            }
            "PATCH" {
                if (-not ($PSCmdlet.MyInvocation.BoundParameters.ContainsKey("JsonBody"))) {
                    throw "You must include the -JSON body parameter when using the PATCH Method in the -Method Parameter"
                }
 
                [hashtable]$SplatArgs = [System.Collections.Specialized.OrderedDictionary]::new()
                [hashtable]$ChildHash = [System.Collections.Specialized.OrderedDictionary]::new()
 
                [hashtable]$ChildHash.Add('Authorization', "Bearer $($BearerToken)")
                [hashtable]$SplatArgs.Add('Uri', [string]$GraphURL)
                [hashtable]$SplatArgs.Add('Headers', $ChildHash)
                [hashtable]$SplatArgs.Add('Method', [string]$Method)
                [hashtable]$SplatArgs.Add('ContentType', [string]'application/json')
                [hashtable]$SplatArgs.Add('Body', $JsonBody)
 
                try {
                    Invoke-RestMethod @SplatArgs
                }
                catch [System.Exception] {
                    return [PSCustomObject]@{
                        CommandException = $($Global:Error[0])
                    }
                }
            }
        }
    }
    end {
        #Purge the dictionary (dispose), this will ONLY purge is CTRL + C was not entered during the API Calls within the switch statement
        $ChildHash.Clear()
        $SplatArgs.Clear()
    }
}
 
function New-AutopilotDeploymentProfile {
    [CmdletBinding()]
    param (
        [parameter(Mandatory = $True)][ValidateLength('1' , '6')]
        [string]$DevicePrefixName,
        [parameter(Mandatory = $True)][ValidateNotNullOrEmpty()]
        [array]$CloudImageName
    )
 
    foreach ($Image in $CloudImageName) {
 
        $JsonPayload = @"
{
    "@odata.type": "#microsoft.graph.azureADWindowsAutopilotDeploymentProfile",
    "displayName": "Autopilot: $($image)",
    "description": "",
    "language": "os-default",
    "locale": "os-default",
    "enrollmentStatusScreenSettings": null,
    "extractHardwareHash": true,
    "hardwareHashExtractionEnabled": true,
    "deviceNameTemplate": "Test-%SERIAL%",
    "deviceType": "windowsPc",
    "enableWhiteGlove": true,
    "preprovisioningAllowed": true,
    "roleScopeTagIds": [
        "0"
    ],
    "managementServiceAppId": null,
    "outOfBoxExperienceSettings": {
        "hidePrivacySettings": true,
        "hideEULA": true,
        "userType": "standard",
        "deviceUsageType": "singleUser",
        "skipKeyboardSelectionPage": true,
        "hideEscapeLink": true
    },
    "outOfBoxExperienceSetting": {
        "privacySettingsHidden": true,
        "eulaHidden": true,
        "userType": "standard",
        "deviceUsageType": "singleUser",
        "keyboardSelectionPageSkipped": true,
        "escapeLinkHidden": true
    }
}
"@
        Invoke-GraphAPIRequest -GraphURL 'https://graph.microsoft.com/beta/deviceManagement/windowsAutopilotDeploymentProfiles' -Method 'POST' -AccessToken $token -JsonBody $JsonPayload
    }
}
 
function New-AutopilotDynamicImagingGroups {
    param (
        [parameter(Mandatory = $true)][ValidateNotNullOrEmpty()]
        [array]$AutopilotTagNames,
        [parameter(Mandatory = $true)][ValidateNotNullOrEmpty()]
        [string]$GroupPrefixName
    )
 
    foreach ($Tag in $AutopilotTagNames) {
 
        $JsonPayload = @"
 
{
    "description": null,
    "displayName": "CompanyABC-MEM-Autopilot-$($Tag)",
    "expirationDateTime": null,
    "groupTypes": [
        "DynamicMembership"
    ],
    "infoCatalogs": [],
    "isAssignableToRole": null,
    "isManagementRestricted": null,
    "mail": null,
    "mailEnabled": false,
    "mailNickname": "$($GroupPrefixName)-MEM-Autopilot-$($Tag)",
    "membershipRule": "(device.devicePhysicalIds -any _ -eq \"[OrderID]:$($Tag)\")",
    "membershipRuleProcessingState": "On",
    "onPremisesDomainName": null,
    "onPremisesLastSyncDateTime": null,
    "onPremisesNetBiosName": null,
    "onPremisesObjectIdentifier": null,
    "onPremisesSamAccountName": null,
    "onPremisesSecurityIdentifier": null,
    "onPremisesSyncEnabled": null,
    "preferredDataLocation": null,
    "preferredLanguage": null,
    "proxyAddresses": [],
    "resourceBehaviorOptions": [],
    "resourceProvisioningOptions": [],
    "securityEnabled": true,
    "theme": null,
    "visibility": null,
    "uniqueName": null,
    "onPremisesProvisioningErrors": [],
    "serviceProvisioningErrors": [],
    "writebackConfiguration": {
        "isEnabled": null,
        "onPremisesGroupType": null
    }
}
"@
        Invoke-GraphAPIRequest -GraphURL 'https://graph.microsoft.com/beta/groups' -Method 'POST' -JsonBody $JsonPayload -AccessToken $token
    }
}

function New-PlatFormScript {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$LocalAdminAccountName,
        [Parameter(Mandatory = $true)]
        [string]$BaseImagePwd,
        [Parameter(Mandatory = $true)]
        [string]$CompanyName
    )

    $PlatformScript = @"

function New-LocalAccount {
    [CmdletBinding()]
    param (
      [parameter(mandatory = $true)][ValidateNotNullOrEmpty()]
      [string]$LocalAccountName,
      [parameter(mandatory = $true)][ValidateNotNullOrEmpty()]
      [string]$LocalPWD, 
      [parameter(mandatory = $true)][ValidateNotNullOrEmpty()]
      [string]$ClientName
      
    )
    
    $LogDate = Get-Date -Format "MM_HH_MM_ss"
  
    $LogDir = "C:\Windows\Setup\$($ClientName)\Logs"
    if (! (Test-Path -Path $LogDir)) {
      New-Item $LogDir -ItemType Directory -ErrorAction SilentlyContinue
    }
    $LocalUser = Get-LocalUser -Name $LocalAccountName -ErrorAction SilentlyContinue
  
    If (!($LocalUser.Name)) {
  
      Start-Transcript -Path "$($LogDir)\$($LogDate)_Administrator_Account.log" -Append
  
      [hashtable]$global:LocalAccountArgs = @{
  
        Password             = ConvertTo-SecureString $LocalPWD -AsPlainText -Force
        FullName             = [string]$LocalAccountName
        Name                 = [string]$LocalAccountName
        PasswordNeverExpires = [boolean]$true
        AccountNeverExpires  = [boolean]$true
      }
  
      New-LocalUser @LocalAccountArgs
      Write-Host "Creating Local Account $($LocalAccountName)"
  
      try {
  
        Add-LocalGroupMember -Member $LocalAccountName -Group "Administrators" 
        Write-Host "Adding Local Account $($LocalAccountName) to Administrators Local Group"
  
      }
      Catch {
        Write-Warning $global:Error[0].Exception.Message
  
      }
    }
    Else { 
  
      Write-Host "The Local account already exists" -ForegroundColor Green
    }
  }
  
  [hashtable]$LocalAccountSplat = @{
  
    LocalAccountName = $($LocalAccountName)
    LocalPWD         = $($BaseImagePwd)
    ClientName       = $($CompanyName)
  }
  New-LocalAccount @LocalAccountSplat

"@  

    $Base64EncodedScript = [Convert]::ToBase64String($([System.Text.Encoding]::Unicode.GetBytes($PlatformScript)))

    $JsonPayload = @"
{

    "enforceSignatureCheck": false,
    "runAs32Bit": false,
    "displayName": "Windows - Local Administrator Account",
    "description": "",
    "scriptContent": "$($Base64EncodedScript)",
    "runAsAccount": "system",
    "fileName": "Localadmin.ps1",
    "roleScopeTagIds": [
        "0"
    ]
}
"@

    Invoke-GraphAPIRequest -GraphURL 'https://graph.microsoft.com/beta/deviceManagement/deviceManagementScripts' -Method 'POST' -JsonBody $JsonPayload -AccessToken $token

}

function Get-DODPolicies {

    $months = @('January', 'February', 'March', 'April', 'May', 'June', 'July', 'August', 'September', 'October', 'November', 'December')
    foreach ($month in $months) {
        try {
            Invoke-RestMethod -uri "https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_STIG_GPO_Package_$($month)_2024.zip" -OutFile 'C:\STIG.zip'
            return [boolean]$true  
        }
        catch {
            Write-Host "url is not on month: $($month)"
        }
    }
}
Function Expand-DoDPolicies { 

    Expand-Archive -Path 'C:\STIG.zip' -DestinationPath C:\ -Force
    Expand-Archive -Path 'C:\Intune STIG Policy Baselines 0322.zip' -DestinationPath C:\ -Force
    Set-Location 'C:\Intune STIG Policy Baselines 0322\Intune Policies\Device Configurations'
}
function Import-DoDBaselines {
    [CmdletBinding()]
     
    $JSONFiles = Get-ChildItem -Filter "*.json" | Where-Object { $_.name -notlike "*mac*" -and $_.Name -notlike "*USB*" }
    if (-not ($JSONFiles)) { 
        throw "Json Files (Intune security baselines) may of not been downloaded yet"
    }
    foreach ($JsonFile in $JSONFiles) {
        try {
            $JsonString = Get-Content -Path $JsonFile.FullName -Raw
            $JsonString = [regex]::Replace($JsonString, '"(createdDateTime|lastModifiedDateTime)":\s*"\\/Date\(\d+\)\\/",?\s*', '')
            $JsonString = [regex]::Replace($JsonString, '"secretReferenceValueId":\s*null,?\s*', '')
            $JsonString = [regex]::Replace($JsonString, '"isEncrypted":\s*false,?\s*', '')
            Set-Content -Path $JsonFile.FullName -Value $JsonString
         
            Invoke-GraphAPIRequest  `
                -GraphURL "https://graph.microsoft.com/v1.0/deviceManagement/deviceConfigurations" `
                -Method 'POST' -JsonBody (Get-Content $JsonFile -Raw) -AccessToken $token  
        }
        catch {
            Write-Warning "Could not import policy into MEM: $($JsonFile.FullName)"
        }
    }
}

function New-LAPSPolicy {
    param (
        [parameter(Mandatory = $true)]
        [string]$LocalAdminAccountName
    )  

    $JsonPayload = @"
{
    "name": "Windows - LAPS",
    "description": "",
    "platforms": "windows10",
    "technologies": "mdm",
    "roleScopeTagIds": [
        "0"
    ],
    "settings": [
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_laps_policies_backupdirectory",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_laps_policies_backupdirectory_1",
                    "children": [
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_laps_policies_passwordagedays_aad",
                            "simpleSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationIntegerSettingValue",
                                "value": 30
                            }
                        }
                    ],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "4d90f03d-e14c-43c4-86da-681da96a2f92"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "a3270f64-e493-499d-8900-90290f61ed8a"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance",
                "settingDefinitionId": "device_vendor_msft_laps_policies_administratoraccountname",
                "simpleSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationStringSettingValue",
                    "value": "$($LocalAdminAccountName)",
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "992c7fce-f9e4-46ab-ac11-e167398859ea"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "d3d7d492-0019-4f56-96f8-1967f7deabeb"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_laps_policies_passwordcomplexity",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_laps_policies_passwordcomplexity_4",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "aa883ab5-625e-4e3b-b830-a37a4bb8ce01"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "8a7459e8-1d1c-458a-8906-7b27d216de52"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance",
                "settingDefinitionId": "device_vendor_msft_laps_policies_passwordlength",
                "simpleSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationIntegerSettingValue",
                    "value": 32,
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "d08f1266-5345-4f53-8ae1-4c20e6cb5ec9"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "da7a1dbd-caf7-4341-ab63-ece6f994ff02"
                }
            }
        }
    ],
    "templateReference": {
        "templateId": "adc46e5a-f4aa-4ff6-aeff-4f27bc525796_1"
    }
}
"@

    Invoke-GraphAPIRequest -GraphURL 'https://graph.microsoft.com/beta/deviceManagement/configurationPolicies' -Method 'POST' -JsonBody $JsonPayload -AccessToken $token

}

function Import-GPOs {
    [CmdletBinding()]

    [array]$GPOs = Get-GPO -All
    foreach ($GPO in $GPOs) {
        Get-GPOReport -Name $GPO.displayname -ReportType xml "C:\$($GPO.DisplayName).xml"
    }

    [array]$Reports = Get-ChildItem -Path 'C:\' -Filter "*.xml"
    foreach ($GPOReport in $Reports) {
        $Base64GPO = ([Convert]::ToBase64String($([System.Text.Encoding]::Unicode.GetBytes($(Get-Content -Path $GPOReport.FullName -Raw)))))

        $JsonPayload = @"
{
    "groupPolicyObjectFile": {
        "ouDistinguishedName": "$($env:USERDNSDOMAIN)",
        "roleScopeTagIds": [
            "0"
        ],
        "content": "$($Base64GPO)"
    }
}
"@
        Invoke-GraphAPIRequest -GraphURL 'https://graph.microsoft.com/beta/deviceManagement/groupPolicyMigrationReports/createMigrationReport?' -Method 'POST' -JsonBody $JsonPayload -AccessToken $Token
    } 
}
function Import-SecurityBaselines {
    [CmdletBinding()]

    $JsonPayload = @"
{
    "name": "Windows - Security Baselines",
    "description": "",
    "platforms": "windows10",
    "technologies": "mdm",
    "roleScopeTagIds": [
        "0"
    ],
    "settings": [
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_devicelock_preventenablinglockscreencamera",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_devicelock_preventenablinglockscreencamera_1",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "85f42e96-fbc8-44f7-8cdf-83d645e215e0"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "7c7dc01b-fbad-4476-bbd9-97d6fdd6f557"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_devicelock_preventlockscreenslideshow",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_devicelock_preventlockscreenslideshow_1",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "d26fde39-5e4d-4f2f-8c49-641033edbd60"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "d4af93ed-8a54-4ce3-8468-e53486d58657"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_mssecurityguide_applyuacrestrictionstolocalaccountsonnetworklogon",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_mssecurityguide_applyuacrestrictionstolocalaccountsonnetworklogon_1",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "443c4209-0973-41b3-bccb-bbbc3d5a81a3"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "a6c2cdd6-2c52-4548-b9c7-a1921fcf4717"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_mssecurityguide_configuresmbv1clientdriver",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_mssecurityguide_configuresmbv1clientdriver_1",
                    "children": [
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_config_mssecurityguide_configuresmbv1clientdriver_pol_secguide_smb1clientdriver",
                            "choiceSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                "value": "device_vendor_msft_policy_config_mssecurityguide_configuresmbv1clientdriver_pol_secguide_smb1clientdriver_4",
                                "children": [],
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "7b3823db-9ce0-4c46-8282-da2de3396551"
                                }
                            },
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "5d3a1cbc-ce3e-4937-899b-81a7615b4982"
                            }
                        }
                    ],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "56202f91-eee8-4c14-b3e9-c4b7e72c28d8"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "4edbc00f-ea59-4c76-83db-be2f300d1c00"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_mssecurityguide_configuresmbv1server",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_mssecurityguide_configuresmbv1server_0",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "860c2e23-7eaa-4735-97fb-058eae5b8719"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "3582c437-7f7d-41da-be48-f6cc875d74dc"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_mssecurityguide_enablestructuredexceptionhandlingoverwriteprotection",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_mssecurityguide_enablestructuredexceptionhandlingoverwriteprotection_1",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "3f96c091-58d3-456f-9e4b-9fd18e950f9e"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "861c39fc-9eef-4070-982d-6c062a28ca11"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_mssecurityguide_wdigestauthentication",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_mssecurityguide_wdigestauthentication_0",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "bbe0fb65-31ca-4f87-9d2d-cdc95ade5b48"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "96885e58-34ab-468d-8444-d0f91fbf10d0"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_msslegacy_ipv6sourceroutingprotectionlevel",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_msslegacy_ipv6sourceroutingprotectionlevel_1",
                    "children": [
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_config_msslegacy_ipv6sourceroutingprotectionlevel_disableipsourceroutingipv6",
                            "choiceSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                "value": "device_vendor_msft_policy_config_msslegacy_ipv6sourceroutingprotectionlevel_disableipsourceroutingipv6_2",
                                "children": [],
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "f4e884b8-1fb3-4352-a72d-0866307b9dbe"
                                }
                            },
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "087f2d64-b645-45ff-b820-8b071e321cde"
                            }
                        }
                    ],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "a2ff7ae1-ed74-4c1c-89a0-e22febeb44cd"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "d26001a0-5e2d-4f45-94f6-a8fb15b016d8"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_msslegacy_ipsourceroutingprotectionlevel",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_msslegacy_ipsourceroutingprotectionlevel_1",
                    "children": [
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_config_msslegacy_ipsourceroutingprotectionlevel_disableipsourcerouting",
                            "choiceSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                "value": "device_vendor_msft_policy_config_msslegacy_ipsourceroutingprotectionlevel_disableipsourcerouting_2",
                                "children": [],
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "3df42274-1de8-47a4-9943-bc94e0222758"
                                }
                            },
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "fc9ef55d-dd87-432e-9ab5-8cb709e3beee"
                            }
                        }
                    ],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "a01e5ce1-378d-4a51-97ee-54568cb4b157"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "3e5238aa-9ccc-45ed-8d94-a5a13c9ead63"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_msslegacy_allowicmpredirectstooverrideospfgeneratedroutes",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_msslegacy_allowicmpredirectstooverrideospfgeneratedroutes_0",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "c621460a-7722-47da-9a92-3abb93fab0be"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "e8b666cf-ae2f-48d8-bb52-0003244da18a"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_msslegacy_allowthecomputertoignorenetbiosnamereleaserequestsexceptfromwinsservers",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_msslegacy_allowthecomputertoignorenetbiosnamereleaserequestsexceptfromwinsservers_1",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "1a9b1e9b-b9ab-485a-b5dd-93377b1b5ee8"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "ec6ff1d8-f6f0-4476-b2ba-a300402ca625"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_admx_dnsclient_turn_off_multicast",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_admx_dnsclient_turn_off_multicast_1",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "dca2e64b-118f-48f5-af56-1e5f26e4e496"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "c2beaa88-fa59-4f55-99bf-a87e83d0e40e"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_admx_networkconnections_nc_showsharedaccessui",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_admx_networkconnections_nc_showsharedaccessui_1",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "658d04ad-6c76-440d-b30c-0c3304f421ec"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "fd9e16e7-3362-4849-bdd9-347f0eb2f013"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_connectivity_hardeneduncpaths",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_connectivity_hardeneduncpaths_1",
                    "children": [
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationGroupSettingCollectionInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_config_connectivity_hardeneduncpaths_pol_hardenedpaths",
                            "groupSettingCollectionValue": [
                                {
                                    "children": [
                                        {
                                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance",
                                            "settingDefinitionId": "device_vendor_msft_policy_config_connectivity_hardeneduncpaths_pol_hardenedpaths_key",
                                            "simpleSettingValue": {
                                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationStringSettingValue",
                                                "value": "\\\\*\\SYSVOL",
                                                "settingValueTemplateReference": {
                                                    "settingValueTemplateId": "931398fa-cf2a-4e3d-bf8c-36fda21a1925"
                                                }
                                            },
                                            "settingInstanceTemplateReference": {
                                                "settingInstanceTemplateId": "26f010c1-bc61-42af-9b97-e77fc4181512"
                                            }
                                        },
                                        {
                                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance",
                                            "settingDefinitionId": "device_vendor_msft_policy_config_connectivity_hardeneduncpaths_pol_hardenedpaths_value",
                                            "simpleSettingValue": {
                                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationStringSettingValue",
                                                "value": "RequireMutualAuthentication=1,RequireIntegrity=1",
                                                "settingValueTemplateReference": {
                                                    "settingValueTemplateId": "aa4e239c-f452-4020-a01c-f705b5ba9a40"
                                                }
                                            },
                                            "settingInstanceTemplateReference": {
                                                "settingInstanceTemplateId": "1b15b254-b280-4b38-b22e-fe3ca5af7c70"
                                            }
                                        }
                                    ]
                                },
                                {
                                    "children": [
                                        {
                                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance",
                                            "settingDefinitionId": "device_vendor_msft_policy_config_connectivity_hardeneduncpaths_pol_hardenedpaths_key",
                                            "simpleSettingValue": {
                                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationStringSettingValue",
                                                "value": "\\\\*\\NETLOGON",
                                                "settingValueTemplateReference": {
                                                    "settingValueTemplateId": "b1997627-00d3-46b0-9ac1-533b16cee206"
                                                }
                                            },
                                            "settingInstanceTemplateReference": {
                                                "settingInstanceTemplateId": "1cbb4781-392f-44d1-8660-eb05d5b18b0e"
                                            }
                                        },
                                        {
                                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance",
                                            "settingDefinitionId": "device_vendor_msft_policy_config_connectivity_hardeneduncpaths_pol_hardenedpaths_value",
                                            "simpleSettingValue": {
                                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationStringSettingValue",
                                                "value": "RequireMutualAuthentication=1,RequireIntegrity=1",
                                                "settingValueTemplateReference": {
                                                    "settingValueTemplateId": "90233d64-60b6-4c8a-8c6c-555604f94b55"
                                                }
                                            },
                                            "settingInstanceTemplateReference": {
                                                "settingInstanceTemplateId": "2aa5902e-bc4f-4e98-9deb-582f226cd64c"
                                            }
                                        }
                                    ]
                                }
                            ],
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "c7a421c5-c3e1-4dfd-838b-4d13cd0a2a08"
                            }
                        }
                    ],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "579dd0e4-ad38-417d-9685-d7dd1b467811"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "6bc0d23e-0338-45a7-a7a1-26c91052e3e0"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_windowsconnectionmanager_prohitconnectiontonondomainnetworkswhenconnectedtodomainauthenticatednetwork",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_windowsconnectionmanager_prohitconnectiontonondomainnetworkswhenconnectedtodomainauthenticatednetwork_1",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "eef724ca-465a-43bf-9b7e-fa18e3ec128a"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "787c60ff-a23f-4843-985f-5a537c0508cf"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_printers_configureredirectionguardpolicy",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_printers_configureredirectionguardpolicy_1",
                    "children": [
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_config_printers_configureredirectionguardpolicy_redirectionguardpolicy_enum",
                            "choiceSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                "value": "device_vendor_msft_policy_config_printers_configureredirectionguardpolicy_redirectionguardpolicy_enum_1",
                                "children": [],
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "a055ad15-a86a-4c10-91a3-bf4e5cf9aefe"
                                }
                            },
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "ec55a527-ce66-42eb-a449-9966e63b822f"
                            }
                        }
                    ],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "84dcb49d-06e7-469a-9119-2b2d8c82d9f3"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "8203e137-23e9-4060-92e8-ecd45dd6e63e"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_printers_configurerpcconnectionpolicy",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_printers_configurerpcconnectionpolicy_1",
                    "children": [
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_config_printers_configurerpcconnectionpolicy_rpcconnectionprotocol_enum",
                            "choiceSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                "value": "device_vendor_msft_policy_config_printers_configurerpcconnectionpolicy_rpcconnectionprotocol_enum_0",
                                "children": [],
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "a64aba40-2334-4e0e-ba5e-c2568be53204"
                                }
                            },
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "6bb9775f-7b64-414d-93ad-d612270ef817"
                            }
                        },
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_config_printers_configurerpcconnectionpolicy_rpcconnectionauthentication_enum",
                            "choiceSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                "value": "device_vendor_msft_policy_config_printers_configurerpcconnectionpolicy_rpcconnectionauthentication_enum_0",
                                "children": [],
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "9b2bd846-f46b-4c88-941f-7e835e98ec97"
                                }
                            },
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "f06e3c57-3493-4b72-ac34-71ac856eb52a"
                            }
                        }
                    ],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "911bc668-aca7-40f8-920e-f70b35e052b2"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "83bda0a1-db1b-4fcb-ad7a-ab5b1635bb80"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_printers_configurerpclistenerpolicy",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_printers_configurerpclistenerpolicy_1",
                    "children": [
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_config_printers_configurerpclistenerpolicy_rpcauthenticationprotocol_enum",
                            "choiceSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                "value": "device_vendor_msft_policy_config_printers_configurerpclistenerpolicy_rpcauthenticationprotocol_enum_0",
                                "children": [],
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "394ffdbf-1a51-4e2e-988d-5b187344dbc4"
                                }
                            },
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "79479349-3107-47ac-942e-0153ee655a2e"
                            }
                        },
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_config_printers_configurerpclistenerpolicy_rpclistenerprotocols_enum",
                            "choiceSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                "value": "device_vendor_msft_policy_config_printers_configurerpclistenerpolicy_rpclistenerprotocols_enum_5",
                                "children": [],
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "09bd0f47-8b2d-4518-8328-785345a22221"
                                }
                            },
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "0c505b3a-b1f3-4963-948a-e45ec4e04ee7"
                            }
                        }
                    ],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "7d8ffd7f-4abc-4e2d-9ae9-5f47103fda44"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "49a5e54e-685c-4c33-898d-d06db872bc67"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_printers_configurerpctcpport",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_printers_configurerpctcpport_1",
                    "children": [
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_config_printers_configurerpctcpport_rpctcpport",
                            "simpleSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationIntegerSettingValue",
                                "value": 0,
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "51da7e44-cf39-4880-b3b2-8b40a4e4bb5e"
                                }
                            },
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "c579c06a-37c2-41e8-989d-ee7645fbb4c8"
                            }
                        }
                    ],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "1cde5600-1862-41f4-90c5-d1f5b5bdbac3"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "ae93831c-e0a2-4481-a5a0-35ac7ca5d582"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_printers_restrictdriverinstallationtoadministrators",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_printers_restrictdriverinstallationtoadministrators_1",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "843603d7-5624-45d4-8990-81da10cb97a6"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "66b2729a-5232-4bb3-9106-7cf17f29df14"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_printers_configurecopyfilespolicy",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_printers_configurecopyfilespolicy_1",
                    "children": [
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_config_printers_configurecopyfilespolicy_copyfilespolicy_enum",
                            "choiceSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                "value": "device_vendor_msft_policy_config_printers_configurecopyfilespolicy_copyfilespolicy_enum_1",
                                "children": [],
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "e6b871f6-75c1-43ba-85f0-d3f25b68f3d1"
                                }
                            },
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "89cb9227-10a6-49b5-9fb6-b6c03996feac"
                            }
                        }
                    ],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "8052e4ca-bb3e-42f3-aeff-bedccd112567"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "333f196c-6067-46a0-84a8-e343f297ce24"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "user_vendor_msft_policy_config_admx_wpn_nolockscreentoastnotification",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "user_vendor_msft_policy_config_admx_wpn_nolockscreentoastnotification_1",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "69133b32-d460-4f1e-a573-ca09aef142c9"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "8fa65f3d-a89a-4a03-a4e8-af26f55cd8bf"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_admx_credssp_allowencryptionoracle",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_admx_credssp_allowencryptionoracle_1",
                    "children": [
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_config_admx_credssp_allowencryptionoracle_allowencryptionoracledrop",
                            "choiceSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                "value": "device_vendor_msft_policy_config_admx_credssp_allowencryptionoracle_allowencryptionoracledrop_0",
                                "children": [],
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "66a96d0c-3a4f-4e25-b443-423c0aa42788"
                                }
                            },
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "d9e03c33-c6c1-4644-982f-41046fd4fc5d"
                            }
                        }
                    ],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "a4e0fbd3-202c-4874-9a8b-d4b56050ad99"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "952d951e-92af-4eda-9424-26c06308dda3"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_credentialsdelegation_remotehostallowsdelegationofnonexportablecredentials",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_credentialsdelegation_remotehostallowsdelegationofnonexportablecredentials_1",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "63588f93-c0ec-4561-af47-f6437b12f843"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "1159aa66-0335-4f49-b6ca-29a3453f0d64"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_deviceinstallation_preventinstallationofmatchingdevicesetupclasses",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_deviceinstallation_preventinstallationofmatchingdevicesetupclasses_1",
                    "children": [
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSimpleSettingCollectionInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_config_deviceinstallation_preventinstallationofmatchingdevicesetupclasses_deviceinstall_classes_deny_list",
                            "simpleSettingCollectionValue": [
                                {
                                    "value": "{d48179be-ec20-11d1-b6b8-00c04fa372a7}",
                                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationStringSettingValue"
                                }
                            ],
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "e1922cc8-c5ac-4c12-b03f-91c6269ac072"
                            }
                        },
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_config_deviceinstallation_preventinstallationofmatchingdevicesetupclasses_deviceinstall_classes_deny_retroactive",
                            "choiceSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                "value": "device_vendor_msft_policy_config_deviceinstallation_preventinstallationofmatchingdevicesetupclasses_deviceinstall_classes_deny_retroactive_1",
                                "children": [],
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "025b4cb6-64e8-4347-91c8-58d0a7e483fe"
                                }
                            },
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "949fd962-f769-4f76-93b0-bd1f5b01348d"
                            }
                        }
                    ],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "5df53c06-432c-4284-9596-59e1c6ddea2c"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "f4255e50-3ae1-4973-873a-2c7cf325a306"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_system_bootstartdriverinitialization",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_system_bootstartdriverinitialization_1",
                    "children": [
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_config_system_bootstartdriverinitialization_selectdriverloadpolicy",
                            "choiceSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                "value": "device_vendor_msft_policy_config_system_bootstartdriverinitialization_selectdriverloadpolicy_3",
                                "children": [],
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "87dc517d-962a-4a3c-b2c4-1ae62cc0a1f3"
                                }
                            },
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "3cb3af79-0fb0-4502-b7bc-bb6f8e64512c"
                            }
                        }
                    ],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "6abbd0b9-89ca-4370-a56d-a276ca1223c5"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "e92a938f-2152-4ca4-bae4-bc51ff1901fe"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_admx_grouppolicy_cse_registry",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_admx_grouppolicy_cse_registry_1",
                    "children": [
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_config_admx_grouppolicy_cse_registry_cse_nobackground10",
                            "choiceSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                "value": "device_vendor_msft_policy_config_admx_grouppolicy_cse_registry_cse_nobackground10_0",
                                "children": [],
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "054d3037-4453-4b5e-9ff4-df14e0e0d9e8"
                                }
                            },
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "125b38b9-28db-4504-94db-93e8df2ce458"
                            }
                        },
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_config_admx_grouppolicy_cse_registry_cse_nochanges10",
                            "choiceSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                "value": "device_vendor_msft_policy_config_admx_grouppolicy_cse_registry_cse_nochanges10_1",
                                "children": [],
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "bf3ac28e-cdde-4d28-8ab6-e309fe50cb48"
                                }
                            },
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "f88923bd-3c73-4af6-b6eb-b7175587454e"
                            }
                        }
                    ],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "7fdb5bc9-1885-40ce-84af-a9e2d9a1f31f"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "97e260c3-1b68-4bac-8103-88f7254766bc"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_connectivity_disabledownloadingofprintdriversoverhttp",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_connectivity_disabledownloadingofprintdriversoverhttp_1",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "dce564b3-dc1e-443c-8691-13f79ee8da6d"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "198f553e-44c0-4bbd-8e70-63988284c63b"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_connectivity_disableinternetdownloadforwebpublishingandonlineorderingwizards",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_connectivity_disableinternetdownloadforwebpublishingandonlineorderingwizards_1",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "2406d8a3-b02a-474b-8e6e-c860ccbb06e7"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "c3f1d038-0d63-4f17-bc59-16b8dad092a1"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_localsecurityauthority_allowcustomsspsaps",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_localsecurityauthority_allowcustomsspsaps_0",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "e36a4034-4355-4ec6-b45c-c9cb49730bc2"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "fb1c0fdf-250a-4aa2-999e-066b3bee7f02"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_power_allowstandbystateswhensleepingonbattery",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_power_allowstandbystateswhensleepingonbattery_0",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "5daa5658-5e48-4d10-a9a5-d35e22d769e2"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "0e1d6304-83e8-47b5-8cd2-8d40cc88e48c"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_power_allowstandbywhensleepingpluggedin",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_power_allowstandbywhensleepingpluggedin_0",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "6904d36c-a0b7-40d5-a52d-189f75edf716"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "77e56e66-27e4-4218-81cf-a1d4f90f8b52"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_power_requirepasswordwhencomputerwakesonbattery",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_power_requirepasswordwhencomputerwakesonbattery_1",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "5c65ba39-635f-4c54-813a-9fc104f559c1"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "245d8497-6014-4a16-a6d4-64732b56eac7"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_power_requirepasswordwhencomputerwakespluggedin",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_power_requirepasswordwhencomputerwakespluggedin_1",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "6a551346-13ad-45d6-8841-50f77f2f7265"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "266b7149-095b-4ae2-b13a-d47bc581d4dc"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_remoteassistance_solicitedremoteassistance",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_remoteassistance_solicitedremoteassistance_0",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "ad2dce5e-9555-473c-9052-1567fae10387"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "fac14fa0-103a-4ac3-8e78-0eba8559ffb9"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_remoteprocedurecall_restrictunauthenticatedrpcclients",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_remoteprocedurecall_restrictunauthenticatedrpcclients_1",
                    "children": [
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_config_remoteprocedurecall_restrictunauthenticatedrpcclients_rpcrestrictremoteclientslist",
                            "choiceSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                "value": "device_vendor_msft_policy_config_remoteprocedurecall_restrictunauthenticatedrpcclients_rpcrestrictremoteclientslist_1",
                                "children": [],
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "a7211876-0e46-44df-8b35-9cccf902617e"
                                }
                            },
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "ef7fe777-bad6-4cb9-98ff-b2ee40141f47"
                            }
                        }
                    ],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "67061c0f-16dc-44fe-8c71-afdb9aede19c"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "556583b0-f6db-4cd3-b66f-2282141a0a24"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_appruntime_allowmicrosoftaccountstobeoptional",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_appruntime_allowmicrosoftaccountstobeoptional_1",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "0baf3b8b-2d74-4d5b-8b68-bdeb2dad0c9d"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "648d002e-2881-443b-9456-7b130057afa1"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_autoplay_disallowautoplayfornonvolumedevices",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_autoplay_disallowautoplayfornonvolumedevices_1",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "f7b27b50-11e5-4af5-b46b-5df979746881"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "efbfe7ed-ee10-4b85-8425-41e303a28f9d"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_autoplay_setdefaultautorunbehavior",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_autoplay_setdefaultautorunbehavior_1",
                    "children": [
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_config_autoplay_setdefaultautorunbehavior_noautorun_dropdown",
                            "choiceSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                "value": "device_vendor_msft_policy_config_autoplay_setdefaultautorunbehavior_noautorun_dropdown_1",
                                "children": [],
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "cc7f585d-7c0b-4a43-bb65-8e2e68d392d3"
                                }
                            },
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "90dedabe-7632-4239-954f-0930cf9829dc"
                            }
                        }
                    ],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "8d3d8a9c-98c3-480f-94f8-3ff56f5439b5"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "40d3aaba-a55b-4aaf-b45b-2632b337ac98"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_autoplay_turnoffautoplay",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_autoplay_turnoffautoplay_1",
                    "children": [
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_config_autoplay_turnoffautoplay_autorun_box",
                            "choiceSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                "value": "device_vendor_msft_policy_config_autoplay_turnoffautoplay_autorun_box_255",
                                "children": [],
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "455f1e10-b6ef-4099-8970-79d12e01a444"
                                }
                            },
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "0884a2bc-e6a4-4199-b403-79957c3012f8"
                            }
                        }
                    ],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "8bd1f894-315a-49cb-90a4-c5071e3a8160"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "ed920709-7063-4b8e-94cc-591f0c7de67a"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_bitlocker_fixeddrivesrequireencryption",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_bitlocker_fixeddrivesrequireencryption_0",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "169be857-bf3f-4731-91cb-691650717fc9"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "a9811db0-8881-4422-baa4-df016a507284"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_bitlocker_removabledrivesrequireencryption",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_bitlocker_removabledrivesrequireencryption_1",
                    "children": [
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_bitlocker_removabledrivesrequireencryption_rdvcrossorg",
                            "choiceSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                "value": "device_vendor_msft_bitlocker_removabledrivesrequireencryption_rdvcrossorg_0",
                                "children": [],
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "d5c30693-e1be-47a7-9495-23d5fbfc841d"
                                }
                            },
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "4b58ddd6-5d02-42b0-ab35-8aa8f4477a99"
                            }
                        }
                    ],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "45973ed9-4c0e-4fce-b5a0-09c8892f23db"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "4f1f73d5-7336-4672-8c9c-8043f18ee1fe"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_credentialsui_enumerateadministrators",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_credentialsui_enumerateadministrators_0",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "7cc94336-6190-4baa-9cd1-b1c95ff9ef0e"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "bec232a1-f08c-4f0a-94b4-019561750e12"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_eventlogservice_specifymaximumfilesizeapplicationlog",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_eventlogservice_specifymaximumfilesizeapplicationlog_1",
                    "children": [
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_config_eventlogservice_specifymaximumfilesizeapplicationlog_channel_logmaxsize",
                            "simpleSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationIntegerSettingValue",
                                "value": 32768,
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "5c7a92a6-2ee6-4975-8142-0327a54544ee"
                                }
                            },
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "a23defc7-6cb2-4446-af51-7099793d8c30"
                            }
                        }
                    ],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "c8edb773-f011-4e60-8d85-a5b41f804e87"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "5806b92c-2b16-4fdf-a11b-9026842d248f"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_eventlogservice_specifymaximumfilesizesecuritylog",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_eventlogservice_specifymaximumfilesizesecuritylog_1",
                    "children": [
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_config_eventlogservice_specifymaximumfilesizesecuritylog_channel_logmaxsize",
                            "simpleSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationIntegerSettingValue",
                                "value": 196608,
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "80734545-f819-4571-86a3-0a6ee7b51f50"
                                }
                            },
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "bfebf5bb-ba37-4d5c-9ddc-e40ecfd43394"
                            }
                        }
                    ],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "ca7cb744-3ed3-4311-91ac-6031004ff7ee"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "7238dcbd-da84-4438-aa4c-cd5ba0bfa093"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_eventlogservice_specifymaximumfilesizesystemlog",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_eventlogservice_specifymaximumfilesizesystemlog_1",
                    "children": [
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_config_eventlogservice_specifymaximumfilesizesystemlog_channel_logmaxsize",
                            "simpleSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationIntegerSettingValue",
                                "value": 32768,
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "b997bf11-27de-4600-975e-ba9d57ad2a8c"
                                }
                            },
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "3aef35a2-c469-459f-af03-b57e0b2fa45f"
                            }
                        }
                    ],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "91136e57-3d79-4ab6-b402-cbd9c4339586"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "3aff0cd5-d8b5-48d3-9af1-137f0ec313e2"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_admx_windowsexplorer_enablesmartscreen",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_admx_windowsexplorer_enablesmartscreen_1",
                    "children": [
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_config_admx_windowsexplorer_enablesmartscreen_enablesmartscreendropdown",
                            "choiceSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                "value": "device_vendor_msft_policy_config_admx_windowsexplorer_enablesmartscreen_enablesmartscreendropdown_block",
                                "children": [],
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "c22f6198-8333-4266-8154-b2dbc26884ef"
                                }
                            },
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "67226836-e0e1-4a56-bc4b-939abe5c77c1"
                            }
                        }
                    ],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "6756fdf5-ea8c-4413-894d-a7bd63ef2470"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "4de272f0-1776-4c55-87f3-7fec1614a512"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_fileexplorer_turnoffdataexecutionpreventionforexplorer",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_fileexplorer_turnoffdataexecutionpreventionforexplorer_0",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "8d94c445-724f-4b99-a69d-82890d1a8b06"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "885e38ff-1d91-46d3-a89e-5137b8f0697c"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_fileexplorer_turnoffheapterminationoncorruption",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_fileexplorer_turnoffheapterminationoncorruption_0",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "8b382fb6-1d53-4024-914d-7a6fe0607b4d"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "d9d2278a-f585-496f-b23f-63b7089b242f"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_allowsoftwarewhensignatureisinvalid",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_internetexplorer_allowsoftwarewhensignatureisinvalid_0",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "7fe32b7a-ab5a-486f-be8a-56ba2fd2185b"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "d0b9190a-5327-4b20-a300-2cb541c7f230"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_checkservercertificaterevocation",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_internetexplorer_checkservercertificaterevocation_1",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "039ba3e4-2022-418e-95a5-830a49349783"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "e34785c4-1ba6-4bc3-88dd-b046a2252196"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_checksignaturesondownloadedprograms",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_internetexplorer_checksignaturesondownloadedprograms_1",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "35d2582a-85d8-43c9-aa54-42391e9814d9"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "e38ed687-3528-4838-889f-69e911851a45"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_donotallowactivexcontrolsinprotectedmode",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_internetexplorer_donotallowactivexcontrolsinprotectedmode_1",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "b0262585-c286-4bb4-8944-eb2c0e708a68"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "739e98f9-d569-46d9-8198-8da2e39106b2"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_disableencryptionsupport",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_internetexplorer_disableencryptionsupport_1",
                    "children": [
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_disableencryptionsupport_advanced_wininetprotocoloptions",
                            "choiceSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                "value": "device_vendor_msft_policy_config_internetexplorer_disableencryptionsupport_advanced_wininetprotocoloptions_2560",
                                "children": [],
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "48ac1015-e007-4a29-b620-20651699c76d"
                                }
                            },
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "71ea2cc9-2f65-4d8a-981b-13036bc1c8da"
                            }
                        }
                    ],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "3e133440-3881-48f5-8734-823bcd216bda"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "e81ea4c8-aa61-4db6-8e61-a0424dcae124"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_disableprocessesinenhancedprotectedmode",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_internetexplorer_disableprocessesinenhancedprotectedmode_1",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "3f69b8b9-8308-4976-8d64-1e1f7de8e155"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "809ed266-09b4-46b0-bf66-e36b6999a781"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_allowenhancedprotectedmode",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_internetexplorer_allowenhancedprotectedmode_1",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "83410c6a-7c24-49b6-a25b-7a4da7a5c9f7"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "31a0047a-aa14-4889-90d1-5d5947fcbb4c"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_internetzoneallowaccesstodatasources",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_internetexplorer_internetzoneallowaccesstodatasources_1",
                    "children": [
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_internetzoneallowaccesstodatasources_iz_partname1406",
                            "choiceSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                "value": "device_vendor_msft_policy_config_internetexplorer_internetzoneallowaccesstodatasources_iz_partname1406_3",
                                "children": [],
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "d1da06d7-da3d-4c24-81c9-f40a62469c0d"
                                }
                            },
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "59b86f96-bcdd-4fd8-aa73-1077a1c24fd3"
                            }
                        }
                    ],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "c2db104a-02c3-478f-bc39-d4e8c4677f46"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "c6b1f0a1-ce57-4635-a469-7c129fbad863"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_internetzoneallowcopypasteviascript",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_internetexplorer_internetzoneallowcopypasteviascript_1",
                    "children": [
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_internetzoneallowcopypasteviascript_iz_partname1407",
                            "choiceSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                "value": "device_vendor_msft_policy_config_internetexplorer_internetzoneallowcopypasteviascript_iz_partname1407_3",
                                "children": [],
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "52bad3e0-3aa4-4dc1-8f95-0ca76643f6d6"
                                }
                            },
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "12a94c7f-f345-4eea-aefc-f176f1576b8a"
                            }
                        }
                    ],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "b9466cf2-acd9-4650-b2d8-350ac55704ec"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "8dc80818-0328-46ee-aac2-d5f9add4f05a"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_internetzoneallowdraganddropcopyandpastefiles",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_internetexplorer_internetzoneallowdraganddropcopyandpastefiles_1",
                    "children": [
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_internetzoneallowdraganddropcopyandpastefiles_iz_partname1802",
                            "choiceSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                "value": "device_vendor_msft_policy_config_internetexplorer_internetzoneallowdraganddropcopyandpastefiles_iz_partname1802_3",
                                "children": [],
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "547a19be-0b80-400e-862c-3a500cfca60f"
                                }
                            },
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "ec2aa58b-640b-4d83-b81d-d93b069e20e9"
                            }
                        }
                    ],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "c5d5e31a-c9a4-4dd5-aa12-c73b7d12b117"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "7f6be888-4368-48e1-a81c-bfba283f5159"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_internetzoneallowloadingofxamlfiles",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_internetexplorer_internetzoneallowloadingofxamlfiles_1",
                    "children": [
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_internetzoneallowloadingofxamlfiles_iz_partname2402",
                            "choiceSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                "value": "device_vendor_msft_policy_config_internetexplorer_internetzoneallowloadingofxamlfiles_iz_partname2402_3",
                                "children": [],
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "8cff938b-bfd1-432a-865a-a3480d3c8cc2"
                                }
                            },
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "e508521d-a837-4a9f-ba6a-5632dc30763a"
                            }
                        }
                    ],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "a1a063f6-655b-4ad2-b54e-ec66f65e8e28"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "91b1f6cf-e265-40f0-a31f-81fdeec11ea0"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_internetzoneallowonlyapproveddomainstouseactivexcontrols",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_internetexplorer_internetzoneallowonlyapproveddomainstouseactivexcontrols_1",
                    "children": [
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_internetzoneallowonlyapproveddomainstouseactivexcontrols_iz_partname120b",
                            "choiceSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                "value": "device_vendor_msft_policy_config_internetexplorer_internetzoneallowonlyapproveddomainstouseactivexcontrols_iz_partname120b_3",
                                "children": [],
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "120060f5-4646-4c9f-9600-6713f559be87"
                                }
                            },
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "5a50d633-f2e3-4408-af07-cb4fd7e8da69"
                            }
                        }
                    ],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "711d3883-c522-4ff1-8a5c-bd7fbc91c736"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "04aa177c-def8-4a90-aa5e-213a5f74b6a4"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_internetzoneallowonlyapproveddomainstousetdcactivexcontrol",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_internetexplorer_internetzoneallowonlyapproveddomainstousetdcactivexcontrol_1",
                    "children": [
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_internetzoneallowonlyapproveddomainstousetdcactivexcontrol_iz_partname120c",
                            "choiceSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                "value": "device_vendor_msft_policy_config_internetexplorer_internetzoneallowonlyapproveddomainstousetdcactivexcontrol_iz_partname120c_3",
                                "children": [],
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "d6f1cdcd-1ba8-45bb-8103-34167cc19e3a"
                                }
                            },
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "dc4f83a4-d0f3-459f-b6f6-319908793199"
                            }
                        }
                    ],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "47615484-9039-49bc-9e29-96e428080e11"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "aa226371-0e5f-4b98-8817-823ab183e645"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_internetzoneallowscriptinitiatedwindows",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_internetexplorer_internetzoneallowscriptinitiatedwindows_1",
                    "children": [
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_internetzoneallowscriptinitiatedwindows_iz_partname2102",
                            "choiceSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                "value": "device_vendor_msft_policy_config_internetexplorer_internetzoneallowscriptinitiatedwindows_iz_partname2102_3",
                                "children": [],
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "91f35b27-99da-4689-9046-910247bc3d0f"
                                }
                            },
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "908f06f9-4cef-4889-a726-778a3819f31b"
                            }
                        }
                    ],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "2c34fec4-8fd9-4745-8b5b-0d2168acb778"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "ad6f576b-5ced-4979-877b-7c5a3ee0e74b"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_internetzoneallowscriptingofinternetexplorerwebbrowsercontrols",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_internetexplorer_internetzoneallowscriptingofinternetexplorerwebbrowsercontrols_1",
                    "children": [
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_internetzoneallowscriptingofinternetexplorerwebbrowsercontrols_iz_partname1206",
                            "choiceSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                "value": "device_vendor_msft_policy_config_internetexplorer_internetzoneallowscriptingofinternetexplorerwebbrowsercontrols_iz_partname1206_3",
                                "children": [],
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "81ddb101-6ab5-44f2-b6b4-c71aaae5f172"
                                }
                            },
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "7e4da519-137a-4643-b216-a585a6672604"
                            }
                        }
                    ],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "0567cafe-c9f4-4c1e-bbbb-4c727f1e49f4"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "1e6590ea-e35c-4331-a53b-8f775c05f154"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_internetzoneallowscriptlets",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_internetexplorer_internetzoneallowscriptlets_1",
                    "children": [
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_internetzoneallowscriptlets_iz_partname1209",
                            "choiceSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                "value": "device_vendor_msft_policy_config_internetexplorer_internetzoneallowscriptlets_iz_partname1209_3",
                                "children": [],
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "c0dedee9-31e6-4e34-8423-5ea3f011dfb7"
                                }
                            },
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "8738d71f-5c2d-43b7-bc53-e73b02114f04"
                            }
                        }
                    ],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "a415b0b5-9806-4fdf-8a8c-73e098b3265f"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "f251b0c9-3936-491d-a654-f529249965ed"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_internetzoneallowupdatestostatusbarviascript",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_internetexplorer_internetzoneallowupdatestostatusbarviascript_1",
                    "children": [
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_internetzoneallowupdatestostatusbarviascript_iz_partname2103",
                            "choiceSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                "value": "device_vendor_msft_policy_config_internetexplorer_internetzoneallowupdatestostatusbarviascript_iz_partname2103_3",
                                "children": [],
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "f8cc1fe5-4663-459f-8932-b08d700c3040"
                                }
                            },
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "c6367acc-4406-46bf-9bce-292184d95f0a"
                            }
                        }
                    ],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "b73e36e2-9f42-4174-b15b-e83cbe023a0b"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "091809e5-92a8-4b25-8b3a-f03ad1d0a87c"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_internetzoneallowvbscripttorunininternetexplorer",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_internetexplorer_internetzoneallowvbscripttorunininternetexplorer_1",
                    "children": [
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_internetzoneallowvbscripttorunininternetexplorer_iz_partname140c",
                            "choiceSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                "value": "device_vendor_msft_policy_config_internetexplorer_internetzoneallowvbscripttorunininternetexplorer_iz_partname140c_3",
                                "children": [],
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "67ab9121-6656-4b90-9d69-2831589a0070"
                                }
                            },
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "71ddb41b-feb1-440a-8e5c-0129bb596e85"
                            }
                        }
                    ],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "fb5c43ef-5e11-45c0-9274-e7308c757a77"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "4421ce4b-8b3e-4ac3-ac6b-63f2a0b8c768"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_internetzoneallowautomaticpromptingforfiledownloads",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_internetexplorer_internetzoneallowautomaticpromptingforfiledownloads_1",
                    "children": [
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_internetzoneallowautomaticpromptingforfiledownloads_iz_partname2200",
                            "choiceSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                "value": "device_vendor_msft_policy_config_internetexplorer_internetzoneallowautomaticpromptingforfiledownloads_iz_partname2200_3",
                                "children": [],
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "6836b580-7956-4602-810f-527f2cdb0b24"
                                }
                            },
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "88c834ea-925e-4013-bc1d-67b49498317a"
                            }
                        }
                    ],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "65adb8ec-0181-43f1-88e4-4eecb702a39a"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "a8031520-8439-489b-b59f-55a302939069"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_internetzonedonotrunantimalwareagainstactivexcontrols",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_internetexplorer_internetzonedonotrunantimalwareagainstactivexcontrols_1",
                    "children": [
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_internetzonedonotrunantimalwareagainstactivexcontrols_iz_partname270c",
                            "choiceSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                "value": "device_vendor_msft_policy_config_internetexplorer_internetzonedonotrunantimalwareagainstactivexcontrols_iz_partname270c_0",
                                "children": [],
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "5ad7bda3-a2f0-48a5-be7f-56568aaaac16"
                                }
                            },
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "a77be816-a14b-4649-abf1-7087fe594aa8"
                            }
                        }
                    ],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "c9bad151-d482-4440-bbb0-8d53f4360ded"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "be011321-a19b-495a-bcad-43b8b09d7f8b"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_internetzonedownloadsignedactivexcontrols",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_internetexplorer_internetzonedownloadsignedactivexcontrols_1",
                    "children": [
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_internetzonedownloadsignedactivexcontrols_iz_partname1001",
                            "choiceSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                "value": "device_vendor_msft_policy_config_internetexplorer_internetzonedownloadsignedactivexcontrols_iz_partname1001_3",
                                "children": [],
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "6aea53c3-fd24-46b1-9326-677d32db0176"
                                }
                            },
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "29f00797-3a94-435b-a99d-3a6917669d77"
                            }
                        }
                    ],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "cb2dc912-814c-4cc3-a13c-cdf223997ed4"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "bbc60f19-cf2c-4d2d-8bf6-babec3e168be"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_internetzonedownloadunsignedactivexcontrols",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_internetexplorer_internetzonedownloadunsignedactivexcontrols_1",
                    "children": [
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_internetzonedownloadunsignedactivexcontrols_iz_partname1004",
                            "choiceSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                "value": "device_vendor_msft_policy_config_internetexplorer_internetzonedownloadunsignedactivexcontrols_iz_partname1004_3",
                                "children": [],
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "c5fd96ca-9d7c-4039-814a-d02efec66c93"
                                }
                            },
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "06276ff1-74c6-4c10-9d7a-0378d479873a"
                            }
                        }
                    ],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "48ac368b-b8cd-4293-bc1a-5657f73b5164"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "c038671e-7af4-468d-b24a-a42d4b91e600"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_internetzoneenabledraggingofcontentfromdifferentdomainsacrosswindows",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_internetexplorer_internetzoneenabledraggingofcontentfromdifferentdomainsacrosswindows_1",
                    "children": [
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_internetzoneenabledraggingofcontentfromdifferentdomainsacrosswindows_iz_partname2709",
                            "choiceSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                "value": "device_vendor_msft_policy_config_internetexplorer_internetzoneenabledraggingofcontentfromdifferentdomainsacrosswindows_iz_partname2709_3",
                                "children": [],
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "810ebed5-0102-4bc2-a37c-24f3e4306412"
                                }
                            },
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "7fbd9d52-aa71-4c78-834c-05d8fc274522"
                            }
                        }
                    ],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "57ab1599-33dc-49a2-9a04-8326a5e50dba"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "9e47de7a-af27-4a34-8f17-274b24e1de2e"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_internetzoneenabledraggingofcontentfromdifferentdomainswithinwindows",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_internetexplorer_internetzoneenabledraggingofcontentfromdifferentdomainswithinwindows_1",
                    "children": [
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_internetzoneenabledraggingofcontentfromdifferentdomainswithinwindows_iz_partname2708",
                            "choiceSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                "value": "device_vendor_msft_policy_config_internetexplorer_internetzoneenabledraggingofcontentfromdifferentdomainswithinwindows_iz_partname2708_3",
                                "children": [],
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "0d1ed23c-cf89-4467-b65e-2b035a670ca0"
                                }
                            },
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "0faa395b-e9d7-45f7-9a0d-9f82b233fefb"
                            }
                        }
                    ],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "1ebd8964-7859-4f33-b3d1-98f9bb4b7d90"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "676d54cf-a876-4fb5-9884-769f9eefe503"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_internetzoneincludelocalpathwhenuploadingfilestoserver",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_internetexplorer_internetzoneincludelocalpathwhenuploadingfilestoserver_1",
                    "children": [
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_internetzoneincludelocalpathwhenuploadingfilestoserver_iz_partname160a",
                            "choiceSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                "value": "device_vendor_msft_policy_config_internetexplorer_internetzoneincludelocalpathwhenuploadingfilestoserver_iz_partname160a_3",
                                "children": [],
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "c3310fee-4848-442b-80e2-f9a19669ddd3"
                                }
                            },
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "dd2e5b34-c2f6-46c6-8c51-4b9aec69efb1"
                            }
                        }
                    ],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "4780274c-6ff2-4085-9cb1-656ef35663ac"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "56c24b5b-8961-42cf-9a60-da556bbb4f70"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_internetzoneinitializeandscriptactivexcontrols",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_internetexplorer_internetzoneinitializeandscriptactivexcontrols_1",
                    "children": [
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_internetzoneinitializeandscriptactivexcontrols_iz_partname1201",
                            "choiceSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                "value": "device_vendor_msft_policy_config_internetexplorer_internetzoneinitializeandscriptactivexcontrols_iz_partname1201_3",
                                "children": [],
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "7370acd9-0b38-453f-b76f-2f5fffd93026"
                                }
                            },
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "53734adf-a34a-4836-9f06-f0beaa63e18a"
                            }
                        }
                    ],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "2d277658-8856-465d-a522-533d22c2f3f2"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "c32b4069-ef87-4afb-b7a0-635360659726"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_internetzonejavapermissions",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_internetexplorer_internetzonejavapermissions_1",
                    "children": [
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_internetzonejavapermissions_iz_partname1c00",
                            "choiceSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                "value": "device_vendor_msft_policy_config_internetexplorer_internetzonejavapermissions_iz_partname1c00_0",
                                "children": [],
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "d9d258e9-e8f0-4668-b184-2572e77a065e"
                                }
                            },
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "002aaffa-e83e-4fe1-90a1-f08146e21c3f"
                            }
                        }
                    ],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "49390a1a-0c78-41fe-9c42-2bd33187e770"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "70d20b6f-9771-487f-a89b-d23efcfd65cf"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_internetzonelaunchingapplicationsandfilesiniframe",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_internetexplorer_internetzonelaunchingapplicationsandfilesiniframe_1",
                    "children": [
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_internetzonelaunchingapplicationsandfilesiniframe_iz_partname1804",
                            "choiceSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                "value": "device_vendor_msft_policy_config_internetexplorer_internetzonelaunchingapplicationsandfilesiniframe_iz_partname1804_3",
                                "children": [],
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "410a2838-f766-4bd3-960a-6486431c37bc"
                                }
                            },
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "41ad518b-4826-4853-87cf-4d3776929169"
                            }
                        }
                    ],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "5203ab41-4307-4fa0-a382-dfc948e5dd45"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "9f1bf0f5-b2fd-44a5-b65a-16fa65cb821f"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_internetzonelogonoptions",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_internetexplorer_internetzonelogonoptions_1",
                    "children": [
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_internetzonelogonoptions_iz_partname1a00",
                            "choiceSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                "value": "device_vendor_msft_policy_config_internetexplorer_internetzonelogonoptions_iz_partname1a00_65536",
                                "children": [],
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "9ada1109-3bb2-4ff6-86ed-0421bb3be807"
                                }
                            },
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "58331549-d7b9-4f60-99b4-ae209e2e610e"
                            }
                        }
                    ],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "b32fe460-1e34-4e85-bcfc-8d67c980d318"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "311bc017-5814-48c5-a18c-c6fef4af856f"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_internetzonenavigatewindowsandframes",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_internetexplorer_internetzonenavigatewindowsandframes_1",
                    "children": [
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_internetzonenavigatewindowsandframes_iz_partname1607",
                            "choiceSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                "value": "device_vendor_msft_policy_config_internetexplorer_internetzonenavigatewindowsandframes_iz_partname1607_3",
                                "children": [],
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "edfa7403-345e-4c12-a0c4-5d2502954576"
                                }
                            },
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "f36476b7-2ebd-4627-8b94-8c35569336bf"
                            }
                        }
                    ],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "7215158d-7031-44b9-ab4b-b9f79cfe4056"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "bb4d0d65-bcfb-4add-b18e-249ee1eec80f"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_internetzoneallownetframeworkreliantcomponents",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_internetexplorer_internetzoneallownetframeworkreliantcomponents_1",
                    "children": [
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_internetzoneallownetframeworkreliantcomponents_iz_partname2004",
                            "choiceSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                "value": "device_vendor_msft_policy_config_internetexplorer_internetzoneallownetframeworkreliantcomponents_iz_partname2004_3",
                                "children": [],
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "9a03335e-7702-4742-91fe-feabfecddbb1"
                                }
                            },
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "99e8ee0a-0929-45ee-a5b3-712924d83b0a"
                            }
                        }
                    ],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "269af8d1-4b15-4c10-b8ee-1804846e371e"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "a827f535-a9df-415b-a519-280986d8492a"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_internetzonerunnetframeworkreliantcomponentssignedwithauthenticode",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_internetexplorer_internetzonerunnetframeworkreliantcomponentssignedwithauthenticode_1",
                    "children": [
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_internetzonerunnetframeworkreliantcomponentssignedwithauthenticode_iz_partname2001",
                            "choiceSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                "value": "device_vendor_msft_policy_config_internetexplorer_internetzonerunnetframeworkreliantcomponentssignedwithauthenticode_iz_partname2001_3",
                                "children": [],
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "2d3340d0-9030-4069-99a1-682e7ecd2836"
                                }
                            },
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "5b4dc9cf-2edc-4c22-9000-b3d6aad7a6b6"
                            }
                        }
                    ],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "0d9ba0aa-b207-4057-962e-2bfb5c2a11bf"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "dac78f54-2d36-43e7-909c-76dcc4d809b7"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_internetzoneshowsecuritywarningforpotentiallyunsafefiles",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_internetexplorer_internetzoneshowsecuritywarningforpotentiallyunsafefiles_1",
                    "children": [
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_internetzoneshowsecuritywarningforpotentiallyunsafefiles_iz_partname1806",
                            "choiceSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                "value": "device_vendor_msft_policy_config_internetexplorer_internetzoneshowsecuritywarningforpotentiallyunsafefiles_iz_partname1806_1",
                                "children": [],
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "13281e96-eac1-4ee3-a637-05df5d84ad78"
                                }
                            },
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "aba8a9c1-ae36-46ab-99de-13ab130b9103"
                            }
                        }
                    ],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "147681cd-370d-4529-b48d-e335de643288"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "59ceceb4-f666-4c9d-a635-0fa0e5f7de23"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_internetzoneenablecrosssitescriptingfilter",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_internetexplorer_internetzoneenablecrosssitescriptingfilter_1",
                    "children": [
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_internetzoneenablecrosssitescriptingfilter_iz_partname1409",
                            "choiceSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                "value": "device_vendor_msft_policy_config_internetexplorer_internetzoneenablecrosssitescriptingfilter_iz_partname1409_0",
                                "children": [],
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "e4d562c4-b02c-40ad-9441-0341ffd714fc"
                                }
                            },
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "437a9087-58ac-4199-9c1f-23dffdbeae0a"
                            }
                        }
                    ],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "3d694d7d-83f2-4137-a3ee-c31bea163a50"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "69116d59-944e-4ac1-b531-047f615cf42a"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_internetzoneenableprotectedmode",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_internetexplorer_internetzoneenableprotectedmode_1",
                    "children": [
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_internetzoneenableprotectedmode_iz_partname2500",
                            "choiceSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                "value": "device_vendor_msft_policy_config_internetexplorer_internetzoneenableprotectedmode_iz_partname2500_0",
                                "children": [],
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "4f276201-0203-4705-9076-b0dd28e5eb76"
                                }
                            },
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "8162d57d-797d-4dce-888d-05efd3573b88"
                            }
                        }
                    ],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "54f3d270-abf7-4319-b5f0-d20688dab3fd"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "929221b4-90f9-4da6-9942-fa8ce8f0c062"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_internetzoneallowsmartscreenie",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_internetexplorer_internetzoneallowsmartscreenie_1",
                    "children": [
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_internetzoneallowsmartscreenie_iz_partname2301",
                            "choiceSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                "value": "device_vendor_msft_policy_config_internetexplorer_internetzoneallowsmartscreenie_iz_partname2301_0",
                                "children": [],
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "ea0641f1-488b-4b92-bcd3-61c0277c0059"
                                }
                            },
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "733425f8-5dad-493d-83cf-0d504eebaf21"
                            }
                        }
                    ],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "5566b159-7423-4a4f-9ece-97fe890cf17b"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "ede75ec7-1ccb-44c0-8839-3d7767bf2efa"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_internetzoneusepopupblocker",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_internetexplorer_internetzoneusepopupblocker_1",
                    "children": [
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_internetzoneusepopupblocker_iz_partname1809",
                            "choiceSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                "value": "device_vendor_msft_policy_config_internetexplorer_internetzoneusepopupblocker_iz_partname1809_0",
                                "children": [],
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "c0a21c62-3c5c-4463-812c-71f1f6525ffc"
                                }
                            },
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "bdaef8a0-e974-4e15-8738-b523dfa071de"
                            }
                        }
                    ],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "d2e2c64c-b4d1-4013-9a53-02c2e8b8689f"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "ca77b6ca-4c2a-49d7-88cf-f1fb755b7952"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_internetzoneallowuserdatapersistence",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_internetexplorer_internetzoneallowuserdatapersistence_1",
                    "children": [
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_internetzoneallowuserdatapersistence_iz_partname1606",
                            "choiceSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                "value": "device_vendor_msft_policy_config_internetexplorer_internetzoneallowuserdatapersistence_iz_partname1606_3",
                                "children": [],
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "87462eca-0071-494a-af30-8282552b113b"
                                }
                            },
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "0d53efeb-421a-43c7-bf1f-c26cf5ae4e15"
                            }
                        }
                    ],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "5de3d7cf-96f0-483a-a30a-9ecd545864d2"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "37684896-d0be-4175-a1ba-b129be49f982"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_internetzoneallowlessprivilegedsites",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_internetexplorer_internetzoneallowlessprivilegedsites_1",
                    "children": [
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_internetzoneallowlessprivilegedsites_iz_partname2101",
                            "choiceSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                "value": "device_vendor_msft_policy_config_internetexplorer_internetzoneallowlessprivilegedsites_iz_partname2101_3",
                                "children": [],
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "9521428f-3ecb-4c29-bd96-e777807bd57b"
                                }
                            },
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "e9c38257-e7c3-4258-ad19-a709f5d5e0a5"
                            }
                        }
                    ],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "c85f17be-79d1-463e-8f33-2f0942df31d7"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "0032304c-7943-48f0-8fbc-c3dc9a2b18ae"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_intranetzonedonotrunantimalwareagainstactivexcontrols",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_internetexplorer_intranetzonedonotrunantimalwareagainstactivexcontrols_1",
                    "children": [
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_intranetzonedonotrunantimalwareagainstactivexcontrols_iz_partname270c",
                            "choiceSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                "value": "device_vendor_msft_policy_config_internetexplorer_intranetzonedonotrunantimalwareagainstactivexcontrols_iz_partname270c_0",
                                "children": [],
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "58644e4a-0136-43ed-a974-e6b9a30ea111"
                                }
                            },
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "944d7592-bbd2-4ea7-8984-30a9b6fbb8d6"
                            }
                        }
                    ],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "a429b1e3-5fec-4f9f-ae80-2344e1aec40f"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "5fd4e6bc-399d-4fd7-abe2-5801f1a97ade"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_intranetzoneinitializeandscriptactivexcontrols",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_internetexplorer_intranetzoneinitializeandscriptactivexcontrols_1",
                    "children": [
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_intranetzoneinitializeandscriptactivexcontrols_iz_partname1201",
                            "choiceSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                "value": "device_vendor_msft_policy_config_internetexplorer_intranetzoneinitializeandscriptactivexcontrols_iz_partname1201_3",
                                "children": [],
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "02c9b9eb-9727-43c4-94f1-7fcbb4f8ac98"
                                }
                            },
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "9a0bc393-6569-4fad-a0f5-fa2db6351946"
                            }
                        }
                    ],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "15b3f944-8ea7-4a91-9e81-5a085eee639a"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "5536f9cb-5357-42bf-b210-4216f3a12510"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_intranetzonejavapermissions",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_internetexplorer_intranetzonejavapermissions_1",
                    "children": [
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_intranetzonejavapermissions_iz_partname1c00",
                            "choiceSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                "value": "device_vendor_msft_policy_config_internetexplorer_intranetzonejavapermissions_iz_partname1c00_65536",
                                "children": [],
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "c79f70b9-1f52-47f2-9f83-41cb91819e40"
                                }
                            },
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "cc44f5cf-62e0-4a96-82ee-c54c7ded3c6c"
                            }
                        }
                    ],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "ad96cdfb-4e5a-41d3-a8c6-7ce978bddbc4"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "a5376071-8f90-4e19-b9f2-d706fd7a9a78"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_localmachinezonedonotrunantimalwareagainstactivexcontrols",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_internetexplorer_localmachinezonedonotrunantimalwareagainstactivexcontrols_1",
                    "children": [
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_localmachinezonedonotrunantimalwareagainstactivexcontrols_iz_partname270c",
                            "choiceSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                "value": "device_vendor_msft_policy_config_internetexplorer_localmachinezonedonotrunantimalwareagainstactivexcontrols_iz_partname270c_0",
                                "children": [],
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "4f04d520-7219-4a79-863b-aa617c3540d7"
                                }
                            },
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "df4962d1-aa51-4068-89bc-c903cc75dfcc"
                            }
                        }
                    ],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "f57345be-ec3a-4dce-9242-63d803819411"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "2e8f4997-df75-4e06-9689-08285954a0f1"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_localmachinezonejavapermissions",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_internetexplorer_localmachinezonejavapermissions_1",
                    "children": [
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_localmachinezonejavapermissions_iz_partname1c00",
                            "choiceSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                "value": "device_vendor_msft_policy_config_internetexplorer_localmachinezonejavapermissions_iz_partname1c00_0",
                                "children": [],
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "612b8d8b-c258-449a-bc1a-21d36d0564e2"
                                }
                            },
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "bfb830d9-dea5-4500-9f37-7e688c76d4b4"
                            }
                        }
                    ],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "965862f1-33b7-4984-91aa-fbb239151f74"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "b94eaaa4-8fa1-4b36-afbd-634e5181a370"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_lockeddowninternetzoneallowsmartscreenie",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_internetexplorer_lockeddowninternetzoneallowsmartscreenie_1",
                    "children": [
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_lockeddowninternetzoneallowsmartscreenie_iz_partname2301",
                            "choiceSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                "value": "device_vendor_msft_policy_config_internetexplorer_lockeddowninternetzoneallowsmartscreenie_iz_partname2301_0",
                                "children": [],
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "55941ab7-39b7-4fd6-b332-3c47cfd14fe1"
                                }
                            },
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "826fd16f-b6fb-4d70-a60a-342e32c53894"
                            }
                        }
                    ],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "b4b62305-14c1-48bc-a17e-06616cea4890"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "bdccfd04-faca-4ede-be52-d35bb657019a"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_lockeddownintranetjavapermissions",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_internetexplorer_lockeddownintranetjavapermissions_1",
                    "children": [
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_lockeddownintranetjavapermissions_iz_partname1c00",
                            "choiceSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                "value": "device_vendor_msft_policy_config_internetexplorer_lockeddownintranetjavapermissions_iz_partname1c00_0",
                                "children": [],
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "2b4181a0-f52f-4b89-ba4b-2d55809f76da"
                                }
                            },
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "a2735a91-baa4-47fb-896c-7312d8f9f5d5"
                            }
                        }
                    ],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "98678104-6cbe-45a1-b343-4a376c2fad76"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "a92395d0-bb80-4039-91f9-bb44740ae884"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_lockeddownlocalmachinezonejavapermissions",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_internetexplorer_lockeddownlocalmachinezonejavapermissions_1",
                    "children": [
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_lockeddownlocalmachinezonejavapermissions_iz_partname1c00",
                            "choiceSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                "value": "device_vendor_msft_policy_config_internetexplorer_lockeddownlocalmachinezonejavapermissions_iz_partname1c00_0",
                                "children": [],
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "32892824-8139-4ced-9b29-c528d5a9fafd"
                                }
                            },
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "c9996b31-8f52-413d-941b-4e8a5f181754"
                            }
                        }
                    ],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "7bd13187-8bd1-40f4-b587-849c83788782"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "8b713db8-b4c7-4f74-bb31-fdbab2d2adc5"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_lockeddownrestrictedsiteszonejavapermissions",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_internetexplorer_lockeddownrestrictedsiteszonejavapermissions_1",
                    "children": [
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_lockeddownrestrictedsiteszonejavapermissions_iz_partname1c00",
                            "choiceSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                "value": "device_vendor_msft_policy_config_internetexplorer_lockeddownrestrictedsiteszonejavapermissions_iz_partname1c00_0",
                                "children": [],
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "0fa970e5-e867-42f5-a5c3-bead7dff3e28"
                                }
                            },
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "b8d8f6ca-66dc-422d-a364-10cb99cfe114"
                            }
                        }
                    ],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "bfe81b50-13f0-4527-a919-ba2bb7566d9a"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "19dab1ba-57c4-489f-86ec-382ed28d42c1"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_lockeddownrestrictedsiteszoneallowsmartscreenie",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_internetexplorer_lockeddownrestrictedsiteszoneallowsmartscreenie_1",
                    "children": [
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_lockeddownrestrictedsiteszoneallowsmartscreenie_iz_partname2301",
                            "choiceSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                "value": "device_vendor_msft_policy_config_internetexplorer_lockeddownrestrictedsiteszoneallowsmartscreenie_iz_partname2301_0",
                                "children": [],
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "213326b3-5261-4c19-882a-a3f67f77d3a8"
                                }
                            },
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "890e2205-b3b9-4335-8568-fc982d09f418"
                            }
                        }
                    ],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "5bced3dd-7ae8-49eb-a016-68afdecf2fc1"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "68a07bc2-2264-410c-ac8a-0469cfe482a5"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_lockeddowntrustedsiteszonejavapermissions",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_internetexplorer_lockeddowntrustedsiteszonejavapermissions_1",
                    "children": [
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_lockeddowntrustedsiteszonejavapermissions_iz_partname1c00",
                            "choiceSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                "value": "device_vendor_msft_policy_config_internetexplorer_lockeddowntrustedsiteszonejavapermissions_iz_partname1c00_0",
                                "children": [],
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "91e92cf2-daa4-47ae-ac34-3e1ea10b119d"
                                }
                            },
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "53bb83a6-085a-4f0b-b836-2b81caded53b"
                            }
                        }
                    ],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "fd8ac3aa-b848-43d6-af0f-b463e099ac75"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "f53ad448-47ad-4ca2-8d9e-aabb48945abe"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszoneallowaccesstodatasources",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszoneallowaccesstodatasources_1",
                    "children": [
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszoneallowaccesstodatasources_iz_partname1406",
                            "choiceSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                "value": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszoneallowaccesstodatasources_iz_partname1406_3",
                                "children": [],
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "b76ac21f-7463-4db4-b811-e7c7f8bc7be9"
                                }
                            },
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "a19d7e52-59fc-48e4-aba5-3c138f9bf2f2"
                            }
                        }
                    ],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "262b755a-779e-4148-a08b-ca17265234de"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "9b6ccc84-885e-4780-9c5d-7c16cda02e6a"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszoneallowactivescripting",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszoneallowactivescripting_1",
                    "children": [
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszoneallowactivescripting_iz_partname1400",
                            "choiceSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                "value": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszoneallowactivescripting_iz_partname1400_3",
                                "children": [],
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "765db41c-63ff-4a07-b1f9-075147d99b0b"
                                }
                            },
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "e598fa77-758c-40b5-a4f1-a878252d86f2"
                            }
                        }
                    ],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "5479325c-4a9f-42af-8d77-41586a7c3d27"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "7aebae7a-8c1f-4515-aafb-7e41b2c8c9f0"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszoneallowbinaryandscriptbehaviors",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszoneallowbinaryandscriptbehaviors_1",
                    "children": [
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszoneallowbinaryandscriptbehaviors_iz_partname2000",
                            "choiceSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                "value": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszoneallowbinaryandscriptbehaviors_iz_partname2000_3",
                                "children": [],
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "cb7600b8-8428-49f7-a44f-0d20c726792b"
                                }
                            },
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "6854249c-7cae-4be8-a6f1-7712b4b8907c"
                            }
                        }
                    ],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "68d2f053-948e-40b5-943a-9960772d7f9c"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "c719f1ec-221c-4076-b5df-294f7b85c436"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszoneallowcopypasteviascript",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszoneallowcopypasteviascript_1",
                    "children": [
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszoneallowcopypasteviascript_iz_partname1407",
                            "choiceSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                "value": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszoneallowcopypasteviascript_iz_partname1407_3",
                                "children": [],
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "8a7d1140-971f-410b-9db2-695a674545b2"
                                }
                            },
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "132040d2-3151-450d-8b4e-dd39ab164668"
                            }
                        }
                    ],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "70bc3c9a-21d6-4821-9ae0-a5aa5391d002"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "09d5e2b3-1a71-4b7f-90e0-e9d4b3267696"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszoneallowdraganddropcopyandpastefiles",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszoneallowdraganddropcopyandpastefiles_1",
                    "children": [
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszoneallowdraganddropcopyandpastefiles_iz_partname1802",
                            "choiceSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                "value": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszoneallowdraganddropcopyandpastefiles_iz_partname1802_3",
                                "children": [],
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "e3a47052-3fbc-458c-8aef-ce4d66ef1f6d"
                                }
                            },
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "09d7e1b1-7fa3-4869-9051-56aceba5977a"
                            }
                        }
                    ],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "3cedb909-b22d-4fb4-b686-12a25d5af05f"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "963218e6-077b-4faa-a2fc-54522b2dea2c"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszoneallowfiledownloads",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszoneallowfiledownloads_1",
                    "children": [
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszoneallowfiledownloads_iz_partname1803",
                            "choiceSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                "value": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszoneallowfiledownloads_iz_partname1803_3",
                                "children": [],
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "097edf65-dac6-4f2e-98bb-2fe28c00118d"
                                }
                            },
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "548fcd3f-8c26-49ec-8b52-bc23794a6f6e"
                            }
                        }
                    ],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "6731bba7-a542-4294-b126-822d6a930814"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "b14aa58f-0afd-4c1b-8e7a-d1b2062986d1"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszoneallowloadingofxamlfiles",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszoneallowloadingofxamlfiles_1",
                    "children": [
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszoneallowloadingofxamlfiles_iz_partname2402",
                            "choiceSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                "value": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszoneallowloadingofxamlfiles_iz_partname2402_3",
                                "children": [],
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "cf5ba088-1354-41a8-8ef5-76f47dd2acca"
                                }
                            },
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "82666f14-4f26-4313-902d-d26483883428"
                            }
                        }
                    ],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "b88a01ff-cc4e-4443-a0c5-614752b6cf26"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "bbe6d765-2897-4c3e-a835-806cd28083d4"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszoneallowmetarefresh",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszoneallowmetarefresh_1",
                    "children": [
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszoneallowmetarefresh_iz_partname1608",
                            "choiceSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                "value": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszoneallowmetarefresh_iz_partname1608_3",
                                "children": [],
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "4b925ad1-9eda-43e0-8acc-7a6f590924b6"
                                }
                            },
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "3401186f-56d2-4f4c-a2fa-46d12e507655"
                            }
                        }
                    ],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "8c7eca32-fd5a-4160-98de-4e9d44fa9cc9"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "e35d4493-f226-4cdd-b84e-4e7e9025c7a0"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszoneallowonlyapproveddomainstouseactivexcontrols",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszoneallowonlyapproveddomainstouseactivexcontrols_1",
                    "children": [
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszoneallowonlyapproveddomainstouseactivexcontrols_iz_partname120b",
                            "choiceSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                "value": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszoneallowonlyapproveddomainstouseactivexcontrols_iz_partname120b_3",
                                "children": [],
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "1b442d16-b9df-4eba-abbe-2d8d4ba4be5f"
                                }
                            },
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "c5288979-1038-49d5-bd75-5a76790599c4"
                            }
                        }
                    ],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "4de25904-da66-4034-877a-ff89b70cd8ae"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "6e4c63e9-43a4-43e2-805c-ae1ddc203019"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszoneallowonlyapproveddomainstousetdcactivexcontrol",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszoneallowonlyapproveddomainstousetdcactivexcontrol_1",
                    "children": [
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszoneallowonlyapproveddomainstousetdcactivexcontrol_iz_partname120c",
                            "choiceSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                "value": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszoneallowonlyapproveddomainstousetdcactivexcontrol_iz_partname120c_3",
                                "children": [],
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "83cc898d-b73d-4a23-99e4-22f4ec6b9ee7"
                                }
                            },
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "e689f1b2-9f98-4694-ab77-df5883a0f2fb"
                            }
                        }
                    ],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "745259c0-31ae-41dd-8045-162722fc2733"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "aab332c1-d04f-4a31-a31c-25f76e39b1fa"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszoneallowscriptinitiatedwindows",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszoneallowscriptinitiatedwindows_1",
                    "children": [
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszoneallowscriptinitiatedwindows_iz_partname2102",
                            "choiceSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                "value": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszoneallowscriptinitiatedwindows_iz_partname2102_3",
                                "children": [],
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "a1399f75-c0a8-4bd1-904d-4e8e1e2c3e81"
                                }
                            },
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "e751bb6e-0d47-4132-9cb5-b4f86f8d6d9e"
                            }
                        }
                    ],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "8284fa71-87fb-4a25-8381-5ffe82767e6a"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "39b4b896-17ce-42be-93bd-a06e8d7b7959"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszoneallowscriptingofinternetexplorerwebbrowsercontrols",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszoneallowscriptingofinternetexplorerwebbrowsercontrols_1",
                    "children": [
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszoneallowscriptingofinternetexplorerwebbrowsercontrols_iz_partname1206",
                            "choiceSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                "value": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszoneallowscriptingofinternetexplorerwebbrowsercontrols_iz_partname1206_3",
                                "children": [],
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "d000cebf-2589-43af-8e93-73a5766b77c5"
                                }
                            },
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "0d0653f8-03c9-41f7-9d9b-81d261102d90"
                            }
                        }
                    ],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "12244b61-79ac-4550-b595-6d6e45888897"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "68fdd4d5-a580-40bb-9bff-379d2efddf81"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszoneallowscriptlets",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszoneallowscriptlets_1",
                    "children": [
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszoneallowscriptlets_iz_partname1209",
                            "choiceSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                "value": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszoneallowscriptlets_iz_partname1209_3",
                                "children": [],
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "9b6baf2c-dd0a-4715-bb8b-8c219ea463ca"
                                }
                            },
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "6fd157c4-80d6-49a2-ad98-7f397781191d"
                            }
                        }
                    ],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "3c3248a8-3200-4b91-9c3a-dad3b9ee250f"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "0390be1a-0e76-4d74-b253-f6ffc52b1ce0"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszoneallowupdatestostatusbarviascript",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszoneallowupdatestostatusbarviascript_1",
                    "children": [
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszoneallowupdatestostatusbarviascript_iz_partname2103",
                            "choiceSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                "value": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszoneallowupdatestostatusbarviascript_iz_partname2103_3",
                                "children": [],
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "fa091853-68bc-45c9-bf78-37edc4bb11b0"
                                }
                            },
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "3be78f1f-97ea-4137-b5fb-109dd02050ff"
                            }
                        }
                    ],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "6e04de9b-0e2b-47d1-92bc-79623bd917f7"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "436e5374-50f5-4c1a-a6b7-f2bb8cf33ac4"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszoneallowvbscripttorunininternetexplorer",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszoneallowvbscripttorunininternetexplorer_1",
                    "children": [
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszoneallowvbscripttorunininternetexplorer_iz_partname140c",
                            "choiceSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                "value": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszoneallowvbscripttorunininternetexplorer_iz_partname140c_3",
                                "children": [],
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "5ab7d09f-6d53-4f2a-9f05-7b61995606c4"
                                }
                            },
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "8acdec26-60f0-4d2a-abf1-75d4c4babd81"
                            }
                        }
                    ],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "f3317757-2c12-4cdc-841e-73dbde4d4440"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "53eb2c56-16cc-4b1f-bdcc-4e4050e6b21b"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszoneallowautomaticpromptingforfiledownloads",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszoneallowautomaticpromptingforfiledownloads_1",
                    "children": [
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszoneallowautomaticpromptingforfiledownloads_iz_partname2200",
                            "choiceSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                "value": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszoneallowautomaticpromptingforfiledownloads_iz_partname2200_3",
                                "children": [],
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "a1dace27-4bcc-4830-92b3-bf5dd8424dc6"
                                }
                            },
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "d7649346-ff10-4c2b-8247-cec23e6e8840"
                            }
                        }
                    ],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "371af241-e12d-45cc-88f9-b75e71f1a2ff"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "0ca72068-0e51-4ad5-bb2f-a60313a27209"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszonedonotrunantimalwareagainstactivexcontrols",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszonedonotrunantimalwareagainstactivexcontrols_1",
                    "children": [
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszonedonotrunantimalwareagainstactivexcontrols_iz_partname270c",
                            "choiceSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                "value": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszonedonotrunantimalwareagainstactivexcontrols_iz_partname270c_0",
                                "children": [],
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "0369a044-5207-4a09-a873-11be52f62f02"
                                }
                            },
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "c5cbd77b-11bf-4496-8a07-6662c0e675ce"
                            }
                        }
                    ],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "e48fe752-6160-47eb-ad0c-ec9000bb95a0"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "a9224fe1-b058-44bc-b0d5-b23c23d6d215"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszonedownloadsignedactivexcontrols",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszonedownloadsignedactivexcontrols_1",
                    "children": [
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszonedownloadsignedactivexcontrols_iz_partname1001",
                            "choiceSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                "value": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszonedownloadsignedactivexcontrols_iz_partname1001_3",
                                "children": [],
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "a9c3bc30-9b92-41c4-b596-2279c49e8882"
                                }
                            },
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "6423e3b2-873a-4f65-8626-4f6a561977a7"
                            }
                        }
                    ],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "e6c70358-5898-4438-9fce-e82cebc390dd"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "7495da73-4392-4983-a98d-bfb2539275a3"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszonedownloadunsignedactivexcontrols",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszonedownloadunsignedactivexcontrols_1",
                    "children": [
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszonedownloadunsignedactivexcontrols_iz_partname1004",
                            "choiceSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                "value": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszonedownloadunsignedactivexcontrols_iz_partname1004_3",
                                "children": [],
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "399ecdf3-eb0e-4272-936d-8f12cfc74d9b"
                                }
                            },
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "b804c6fd-f817-44bd-adac-0a41601b97b8"
                            }
                        }
                    ],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "9b79a0af-4ebc-432b-8765-0049084e8a74"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "a7e1e9a0-63a7-4f66-914e-8a704f7f7912"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszoneenabledraggingofcontentfromdifferentdomainsacrosswindows",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszoneenabledraggingofcontentfromdifferentdomainsacrosswindows_1",
                    "children": [
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszoneenabledraggingofcontentfromdifferentdomainsacrosswindows_iz_partname2709",
                            "choiceSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                "value": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszoneenabledraggingofcontentfromdifferentdomainsacrosswindows_iz_partname2709_3",
                                "children": [],
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "39af09f7-1b99-44ce-8173-3cdd1bc96197"
                                }
                            },
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "5d93c570-1448-4a02-ae43-f662af49a815"
                            }
                        }
                    ],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "2581f05f-6907-42a9-9c73-005dea804fba"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "3a853807-2fdc-4716-a575-91719db0326b"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszoneenabledraggingofcontentfromdifferentdomainswithinwindows",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszoneenabledraggingofcontentfromdifferentdomainswithinwindows_1",
                    "children": [
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszoneenabledraggingofcontentfromdifferentdomainswithinwindows_iz_partname2708",
                            "choiceSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                "value": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszoneenabledraggingofcontentfromdifferentdomainswithinwindows_iz_partname2708_3",
                                "children": [],
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "71949821-b2cd-494e-b2cb-b021ca455254"
                                }
                            },
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "d3ad60fd-135c-4ca3-8cac-d9b94b25aa18"
                            }
                        }
                    ],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "75adda9a-9d8d-4fce-b250-1d729d354a44"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "eaf2f4f7-e1f6-4f0c-ad14-06e47f317532"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszoneincludelocalpathwhenuploadingfilestoserver",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszoneincludelocalpathwhenuploadingfilestoserver_1",
                    "children": [
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszoneincludelocalpathwhenuploadingfilestoserver_iz_partname160a",
                            "choiceSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                "value": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszoneincludelocalpathwhenuploadingfilestoserver_iz_partname160a_3",
                                "children": [],
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "88ca478f-a8fc-4ade-a306-0b519063d36d"
                                }
                            },
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "6cbd1d20-27c0-458a-955a-e374da09f0b2"
                            }
                        }
                    ],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "821ae1d2-f621-493c-bda4-57def81ca18d"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "93948498-b331-4a0f-b405-05abb8e3db34"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszoneinitializeandscriptactivexcontrols",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszoneinitializeandscriptactivexcontrols_1",
                    "children": [
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszoneinitializeandscriptactivexcontrols_iz_partname1201",
                            "choiceSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                "value": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszoneinitializeandscriptactivexcontrols_iz_partname1201_3",
                                "children": [],
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "e4097c63-ab59-4be0-8806-31efd5bd468a"
                                }
                            },
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "1a8679e5-5913-4917-9337-6fb51290251b"
                            }
                        }
                    ],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "73d7aafe-78fe-4711-9cc7-04b357aa05f3"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "8ed0c074-a56d-4ad3-88e5-0f37907a8cba"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszonejavapermissions",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszonejavapermissions_1",
                    "children": [
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszonejavapermissions_iz_partname1c00",
                            "choiceSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                "value": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszonejavapermissions_iz_partname1c00_0",
                                "children": [],
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "7067ab10-d618-4793-8e4f-dc13272def9f"
                                }
                            },
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "f705a832-f9a7-4159-9570-38eae9df3f54"
                            }
                        }
                    ],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "e846b109-0d0c-4b23-baf4-260fa888cfe7"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "309be167-14f6-408d-b48b-433721a04f89"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszonelaunchingapplicationsandfilesiniframe",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszonelaunchingapplicationsandfilesiniframe_1",
                    "children": [
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszonelaunchingapplicationsandfilesiniframe_iz_partname1804",
                            "choiceSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                "value": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszonelaunchingapplicationsandfilesiniframe_iz_partname1804_3",
                                "children": [],
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "47fe919d-2bde-4185-934b-4036e301c914"
                                }
                            },
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "28eca1f4-f1a3-43e5-b89d-1caa90c442f1"
                            }
                        }
                    ],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "2a6a230a-c68d-4152-8958-a59b1cf2dd19"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "10275972-63d9-4130-9879-e2b0436d6064"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszonelogonoptions",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszonelogonoptions_1",
                    "children": [
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszonelogonoptions_iz_partname1a00",
                            "choiceSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                "value": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszonelogonoptions_iz_partname1a00_196608",
                                "children": [],
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "b8b9e74b-b47c-40aa-bf77-b9c6c4c1c00d"
                                }
                            },
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "82f0bce3-d595-4c71-ade7-1ef1985d0fe8"
                            }
                        }
                    ],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "d750b7c6-db93-49c1-b6cd-1d22f2774e80"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "c4def5f4-8569-4928-bdba-a08066539474"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszonenavigatewindowsandframes",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszonenavigatewindowsandframes_1",
                    "children": [
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszonenavigatewindowsandframes_iz_partname1607",
                            "choiceSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                "value": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszonenavigatewindowsandframes_iz_partname1607_3",
                                "children": [],
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "ca9ccb7f-a19c-4add-af33-8a2ef81f2918"
                                }
                            },
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "7fb0fbcc-1e58-440f-91ca-c1b03d288206"
                            }
                        }
                    ],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "6c697855-be4c-44e3-95c4-7cc73059a6b8"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "af28aee7-df91-418e-9982-e1180ed0c407"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszoneallownetframeworkreliantcomponents",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszoneallownetframeworkreliantcomponents_1",
                    "children": [
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszoneallownetframeworkreliantcomponents_iz_partname2004",
                            "choiceSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                "value": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszoneallownetframeworkreliantcomponents_iz_partname2004_3",
                                "children": [],
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "bf2fc6e8-c818-4190-a4ea-07cd8f02944f"
                                }
                            },
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "dae08163-c39f-4a57-8dcd-c691f20e57b3"
                            }
                        }
                    ],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "4c3ab6f7-a3b0-4d9d-a6f1-c643e5014f72"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "1fcc183c-b504-47f6-b1ae-5966e508dd48"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszonerunnetframeworkreliantcomponentssignedwithauthenticode",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszonerunnetframeworkreliantcomponentssignedwithauthenticode_1",
                    "children": [
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszonerunnetframeworkreliantcomponentssignedwithauthenticode_iz_partname2001",
                            "choiceSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                "value": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszonerunnetframeworkreliantcomponentssignedwithauthenticode_iz_partname2001_3",
                                "children": [],
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "c56706e0-57c9-4b21-96ba-10f49cdbd540"
                                }
                            },
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "f07e428b-73f6-42b8-b1d6-b6d9101c2b2d"
                            }
                        }
                    ],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "9f7bc83c-26a2-49d3-a5be-f399ff422708"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "8a8864a5-ff59-4733-b3e4-9326ecc3c4d1"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszonerunactivexcontrolsandplugins",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszonerunactivexcontrolsandplugins_1",
                    "children": [
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszonerunactivexcontrolsandplugins_iz_partname1200",
                            "choiceSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                "value": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszonerunactivexcontrolsandplugins_iz_partname1200_3",
                                "children": [],
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "95963388-dfe9-4543-bdff-786dfbda8a58"
                                }
                            },
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "694e187a-2917-4780-908b-06d1b9815243"
                            }
                        }
                    ],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "8f53543f-f9a2-46f3-a8b8-b97dfdd61912"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "f088c7d0-35f8-4bf7-82d1-530d421aa5fe"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszonescriptactivexcontrolsmarkedsafeforscripting",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszonescriptactivexcontrolsmarkedsafeforscripting_1",
                    "children": [
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszonescriptactivexcontrolsmarkedsafeforscripting_iz_partname1405",
                            "choiceSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                "value": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszonescriptactivexcontrolsmarkedsafeforscripting_iz_partname1405_3",
                                "children": [],
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "708f7841-66f3-4140-b0fc-741c26a9df20"
                                }
                            },
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "fb531896-2084-4b9a-af3e-59a2fbba5673"
                            }
                        }
                    ],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "1c8b7dea-d3d2-4580-a490-6ef62b743e05"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "af76dbb5-c8cc-4277-a74a-8d71901cfe0b"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszonescriptingofjavaapplets",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszonescriptingofjavaapplets_1",
                    "children": [
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszonescriptingofjavaapplets_iz_partname1402",
                            "choiceSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                "value": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszonescriptingofjavaapplets_iz_partname1402_3",
                                "children": [],
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "aac69b8c-ff12-4e36-8608-78281f59e434"
                                }
                            },
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "d2c8ff40-d9d8-4c61-876e-0d33006ba3b3"
                            }
                        }
                    ],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "52f1e115-8c4c-4b46-bb80-0d8bb25a40f3"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "73b958a7-df60-41bb-8ce5-1b0ef135f803"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszoneshowsecuritywarningforpotentiallyunsafefiles",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszoneshowsecuritywarningforpotentiallyunsafefiles_1",
                    "children": [
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszoneshowsecuritywarningforpotentiallyunsafefiles_iz_partname1806",
                            "choiceSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                "value": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszoneshowsecuritywarningforpotentiallyunsafefiles_iz_partname1806_3",
                                "children": [],
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "6bb372ea-531e-40cb-b38d-9c6cc2ad2803"
                                }
                            },
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "463e58ce-5ffd-486b-bd64-20315d860d3d"
                            }
                        }
                    ],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "80a8ce02-cc45-4fc1-9ab0-b4af9b0249f6"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "fa4b5f3f-ea66-4e47-afae-3ae88d2515fc"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszoneenablecrosssitescriptingfilter",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszoneenablecrosssitescriptingfilter_1",
                    "children": [
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszoneenablecrosssitescriptingfilter_iz_partname1409",
                            "choiceSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                "value": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszoneenablecrosssitescriptingfilter_iz_partname1409_0",
                                "children": [],
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "7cad257a-221f-4da5-b3c4-b02d0f33f7e8"
                                }
                            },
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "3c9f52ea-c434-4015-92ee-447291a1d7eb"
                            }
                        }
                    ],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "3d4cd6a3-5e90-4802-8ef3-b1ffd6198bca"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "2629e187-7cc4-4545-b243-a367b0d62ce8"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszoneturnonprotectedmode",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszoneturnonprotectedmode_1",
                    "children": [
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszoneturnonprotectedmode_iz_partname2500",
                            "choiceSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                "value": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszoneturnonprotectedmode_iz_partname2500_0",
                                "children": [],
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "5932392c-6abc-44e1-ad1f-e099a988ac29"
                                }
                            },
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "90eeadd1-fdef-4285-8f9c-5862e5eaee0a"
                            }
                        }
                    ],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "34661614-9d0e-4a9e-bfb1-e26ee4e7e7a0"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "8b37038d-16b1-4f36-a2b2-e8a4dd7aadab"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszoneallowsmartscreenie",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszoneallowsmartscreenie_1",
                    "children": [
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszoneallowsmartscreenie_iz_partname2301",
                            "choiceSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                "value": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszoneallowsmartscreenie_iz_partname2301_0",
                                "children": [],
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "dfd03a1d-179e-419b-927a-77fc06c5ca43"
                                }
                            },
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "fa303478-4c36-4a32-8379-3011c936a271"
                            }
                        }
                    ],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "d70c46a8-9db1-412d-9555-dca4f65b9b33"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "d7cce09c-8013-4bdc-904e-f9b64170a692"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszoneusepopupblocker",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszoneusepopupblocker_1",
                    "children": [
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszoneusepopupblocker_iz_partname1809",
                            "choiceSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                "value": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszoneusepopupblocker_iz_partname1809_0",
                                "children": [],
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "71fb3287-3287-4ed4-8bb2-6cbb7f22cf09"
                                }
                            },
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "3c1bb95f-3080-44ad-b726-50050641c852"
                            }
                        }
                    ],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "0459e083-5bb0-41e9-a670-65e4377ece40"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "e34db23b-544b-428c-816f-174dfab6fbf5"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszoneallowuserdatapersistence",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszoneallowuserdatapersistence_1",
                    "children": [
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszoneallowuserdatapersistence_iz_partname1606",
                            "choiceSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                "value": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszoneallowuserdatapersistence_iz_partname1606_3",
                                "children": [],
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "2176bd03-8567-4e85-bb7a-615e150fdcf3"
                                }
                            },
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "5ca857ef-b380-4b19-b80c-9e65f28acb55"
                            }
                        }
                    ],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "189d21c1-f375-470f-9389-488031fb279d"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "3b886701-de22-4a79-92c5-d76a761cc890"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszoneallowlessprivilegedsites",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszoneallowlessprivilegedsites_1",
                    "children": [
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszoneallowlessprivilegedsites_iz_partname2101",
                            "choiceSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                "value": "device_vendor_msft_policy_config_internetexplorer_restrictedsiteszoneallowlessprivilegedsites_iz_partname2101_3",
                                "children": [],
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "f119831c-e5f9-4400-9b32-ec6d50753278"
                                }
                            },
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "62dce577-3b62-4613-b7b5-2383286e4a78"
                            }
                        }
                    ],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "f2663f5d-9bce-490d-b78b-67744773a2f2"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "4f5355da-3a54-4c33-b75e-a6a82d0899c4"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_trustedsiteszonedonotrunantimalwareagainstactivexcontrols",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_internetexplorer_trustedsiteszonedonotrunantimalwareagainstactivexcontrols_1",
                    "children": [
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_trustedsiteszonedonotrunantimalwareagainstactivexcontrols_iz_partname270c",
                            "choiceSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                "value": "device_vendor_msft_policy_config_internetexplorer_trustedsiteszonedonotrunantimalwareagainstactivexcontrols_iz_partname270c_0",
                                "children": [],
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "a5c30789-4d9e-4aa9-9ec9-9577c7756b61"
                                }
                            },
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "04091c20-1a96-4f2d-903b-e3a7bb8665db"
                            }
                        }
                    ],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "3c9f1eb5-6f20-4676-b494-80e843303eb0"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "2b34cfca-bc11-4e3d-b6cd-5b784c6bf243"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_trustedsiteszoneinitializeandscriptactivexcontrols",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_internetexplorer_trustedsiteszoneinitializeandscriptactivexcontrols_1",
                    "children": [
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_trustedsiteszoneinitializeandscriptactivexcontrols_iz_partname1201",
                            "choiceSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                "value": "device_vendor_msft_policy_config_internetexplorer_trustedsiteszoneinitializeandscriptactivexcontrols_iz_partname1201_3",
                                "children": [],
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "ba4803ed-3c10-49d6-a3de-16b14190e10c"
                                }
                            },
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "f1e8e261-b9cb-4bc5-bea2-c86ec0cb83ef"
                            }
                        }
                    ],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "f6a0d5e2-5646-4bec-a042-e0a275def3b8"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "08804c0e-c275-47dd-b83e-98c792645c27"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_trustedsiteszonejavapermissions",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_internetexplorer_trustedsiteszonejavapermissions_1",
                    "children": [
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_trustedsiteszonejavapermissions_iz_partname1c00",
                            "choiceSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                "value": "device_vendor_msft_policy_config_internetexplorer_trustedsiteszonejavapermissions_iz_partname1c00_65536",
                                "children": [],
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "0fb45999-72c8-4e1f-9b62-724c9a15eb57"
                                }
                            },
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "c78fe183-5412-4bba-b353-0387354f4812"
                            }
                        }
                    ],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "eea707a1-68a9-4d3a-a9bb-f00647d6938d"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "63cea4c5-8324-4bfe-94a0-b6872af4f8b3"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_includeallnetworkpaths",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_internetexplorer_includeallnetworkpaths_0",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "e262d738-3267-4028-9abf-9d0f97e3c42e"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "c163c8af-c747-4dd8-a649-6bc40e10ebed"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_allowcertificateaddressmismatchwarning",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_internetexplorer_allowcertificateaddressmismatchwarning_1",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "e5174eff-04c1-4292-8b3e-cc20e2d9c6e5"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "16802e3e-0dbf-4a5a-b57e-aaf9bf8656fc"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_disableignoringcertificateerrors",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_internetexplorer_disableignoringcertificateerrors_1",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "5fbd9783-077a-4898-9fcc-7b48e9829b73"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "73e1e690-3fa1-4d3a-ac93-7bbcccf28bb1"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_removerunthistimebuttonforoutdatedactivexcontrols",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_internetexplorer_removerunthistimebuttonforoutdatedactivexcontrols_1",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "f9e7126e-70d3-43d5-8a5b-9f15ba09dc14"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "596bb1b1-8b72-48c3-b1b2-bff757c410af"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_donotblockoutdatedactivexcontrols",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_internetexplorer_donotblockoutdatedactivexcontrols_0",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "daec2c1d-c93e-484f-9458-9b63a4eef5b5"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "b090600b-5375-48fe-98a0-24c89287336b"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_consistentmimehandlinginternetexplorerprocesses",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_internetexplorer_consistentmimehandlinginternetexplorerprocesses_1",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "a74036d3-be24-4273-8aa4-8c99c71b4d1e"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "e57fc662-e951-4b5b-b70d-1280044fb454"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_mimesniffingsafetyfeatureinternetexplorerprocesses",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_internetexplorer_mimesniffingsafetyfeatureinternetexplorerprocesses_1",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "2394d7bc-52c9-4ce7-aab7-d3795cfd5861"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "b9291719-ba52-4fba-857a-07d06cbef4fe"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_mkprotocolsecurityrestrictioninternetexplorerprocesses",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_internetexplorer_mkprotocolsecurityrestrictioninternetexplorerprocesses_1",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "d3892737-9972-46c8-b41f-64de3bf4af56"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "71722130-7b6a-471d-9240-7dfe8bb6cfb6"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_notificationbarinternetexplorerprocesses",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_internetexplorer_notificationbarinternetexplorerprocesses_1",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "fa05de82-de67-4bff-9a11-fe45f1fa73d3"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "2073355c-ab74-4311-8d6c-0a5312fb95af"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_protectionfromzoneelevationinternetexplorerprocesses",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_internetexplorer_protectionfromzoneelevationinternetexplorerprocesses_1",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "98194b78-041a-44ad-9b6f-b38a61d4f113"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "6cf6555c-abb9-45d3-a622-e22b03f53d8b"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_restrictactivexinstallinternetexplorerprocesses",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_internetexplorer_restrictactivexinstallinternetexplorerprocesses_1",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "0be41807-26c8-452a-b91c-39b6f3a1b66d"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "83038d03-0599-474a-abef-bd6366407a14"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_restrictfiledownloadinternetexplorerprocesses",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_internetexplorer_restrictfiledownloadinternetexplorerprocesses_1",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "a38ba1e3-e4ba-4216-9987-8ff506069f92"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "9b2b8a5d-dcd6-42ab-b0a0-565d5126ad20"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_scriptedwindowsecurityrestrictionsinternetexplorerprocesses",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_internetexplorer_scriptedwindowsecurityrestrictionsinternetexplorerprocesses_1",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "92915bcd-a58b-4864-aeb6-759cd477635c"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "22821ee1-a859-4017-97e5-1443d1ebb066"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_allowfallbacktossl3",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_internetexplorer_allowfallbacktossl3_1",
                    "children": [
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_allowfallbacktossl3_advanced_enablessl3fallbackoptions",
                            "choiceSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                "value": "device_vendor_msft_policy_config_internetexplorer_allowfallbacktossl3_advanced_enablessl3fallbackoptions_0",
                                "children": [],
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "5ccbb7e2-16fb-450a-b675-6bc29aca2099"
                                }
                            },
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "6d500aad-d40b-4157-bed9-5f4606a9ce1d"
                            }
                        }
                    ],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "a862747b-5da6-4dc1-9d80-ff4cf72fae4b"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "65fceea0-2e6d-4a8e-b264-86005ee05e17"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_disablebypassofsmartscreenwarnings",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_internetexplorer_disablebypassofsmartscreenwarnings_1",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "c97c541b-ede6-4cc2-9f65-93fe5e6fb72a"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "7f070617-9e7d-43ac-8e9d-3b81a0633ba6"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_disablebypassofsmartscreenwarningsaboutuncommonfiles",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_internetexplorer_disablebypassofsmartscreenwarningsaboutuncommonfiles_1",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "3213fc39-d48e-427e-a9ce-ebe9c4197eed"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "89fb78bb-1587-46df-bfc0-73a0461ab091"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_preventmanagingsmartscreenfilter",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_internetexplorer_preventmanagingsmartscreenfilter_1",
                    "children": [
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_preventmanagingsmartscreenfilter_ie9safetyfilteroptions",
                            "choiceSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                "value": "device_vendor_msft_policy_config_internetexplorer_preventmanagingsmartscreenfilter_ie9safetyfilteroptions_1",
                                "children": [],
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "2e793442-86eb-4fc0-9635-6750e098ed00"
                                }
                            },
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "efa03991-6324-46a2-a03e-9bc0741e1327"
                            }
                        }
                    ],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "84f9ec32-01ef-4c69-ad6d-5ccdfdda39c4"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "4247f266-ca83-48cb-9f02-8c3f57d5ec13"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_preventperuserinstallationofactivexcontrols",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_internetexplorer_preventperuserinstallationofactivexcontrols_1",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "2cb158ce-c2c4-490d-94f2-38362746a919"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "20ac809a-d5d1-4f54-a47d-882e5f20b6dc"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_donotallowuserstoaddsites",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_internetexplorer_donotallowuserstoaddsites_1",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "2d5ac56a-6b63-463d-9092-0a374fd76eed"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "548969ab-4493-4267-9038-9e5b9cfa86b7"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_donotallowuserstochangepolicies",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_internetexplorer_donotallowuserstochangepolicies_1",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "7101d91f-57b5-491c-bca2-80c4644fe122"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "38d3f791-c451-4680-9aa5-b17ce7cbbb88"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_securityzonesuseonlymachinesettings",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_internetexplorer_securityzonesuseonlymachinesettings_1",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "64edca64-ddb8-4b11-b9f8-78256dccbfd0"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "7b214d48-622f-45eb-9199-0024499f07d8"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_specifyuseofactivexinstallerservice",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_internetexplorer_specifyuseofactivexinstallerservice_1",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "baf0d1b0-b761-458e-866f-059818abf827"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "66c45224-8e3c-45ed-a3bd-dcaaa5a4d951"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_disablecrashdetection",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_internetexplorer_disablecrashdetection_1",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "8cde1bab-d2bf-433c-a862-313fc6748665"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "687adce3-3978-4bcb-bc4b-d81c69d4e9f9"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_disablesecuritysettingscheck",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_internetexplorer_disablesecuritysettingscheck_0",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "02d04991-d5da-428d-8896-0231902b7efe"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "bd34f766-d988-489e-b606-0630d84fbb0c"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "user_vendor_msft_policy_config_internetexplorer_allowautocomplete",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "user_vendor_msft_policy_config_internetexplorer_allowautocomplete_0",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "7ee03af0-88f3-4c1a-a936-dc56792d0c69"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "8a72456c-17dd-4791-bb90-0a0d9c131b75"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_admx_microsoftdefenderantivirus_disableblockatfirstseen",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_admx_microsoftdefenderantivirus_disableblockatfirstseen_1",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "5a33385a-9bda-4cc5-8fd3-5dd2a28d2af5"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "fc87eb74-b6b8-4732-9ad8-d47b3a6492d1"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_admx_microsoftdefenderantivirus_realtimeprotection_disablescanonrealtimeenable",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_admx_microsoftdefenderantivirus_realtimeprotection_disablescanonrealtimeenable_1",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "95343ebc-4808-43d4-b131-221f1c314757"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "25280726-7d2c-42fc-a01b-544fc5149302"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_admx_microsoftdefenderantivirus_scan_disablepackedexescanning",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_admx_microsoftdefenderantivirus_scan_disablepackedexescanning_1",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "59f5f1ec-a6eb-4686-b798-d9bc2b5c42ce"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "2be5c530-92c6-4b79-97a2-1fbce9535d0b"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_admx_microsoftdefenderantivirus_disableroutinelytakingaction",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_admx_microsoftdefenderantivirus_disableroutinelytakingaction_0",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "985e3126-ff93-414d-8fc0-db63deb10eb5"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "6deba92c-1066-4f53-971d-58543b0911c6"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_remotedesktopservices_donotallowpasswordsaving",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_remotedesktopservices_donotallowpasswordsaving_1",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "90e3214f-8279-4eff-b62a-31bbda83ed73"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "eda46bc6-1380-413f-9901-87cfc7d7a551"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_remotedesktopservices_donotallowdriveredirection",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_remotedesktopservices_donotallowdriveredirection_1",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "d83e0604-6098-4738-9c1e-3761af108acf"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "52f31423-9103-4c09-ad37-ace83400dda5"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_remotedesktopservices_promptforpassworduponconnection",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_remotedesktopservices_promptforpassworduponconnection_1",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "3810b97b-b9ca-4781-b175-4c2d5df58abd"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "8d0927d1-6c9a-4538-9153-02f6b5ce13be"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_remotedesktopservices_requiresecurerpccommunication",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_remotedesktopservices_requiresecurerpccommunication_1",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "686d2d0b-017d-4382-8425-2dd1aeb75ed8"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "5004e80c-44c0-408b-b5f7-38220c5a0813"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_remotedesktopservices_clientconnectionencryptionlevel",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_remotedesktopservices_clientconnectionencryptionlevel_1",
                    "children": [
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_config_remotedesktopservices_clientconnectionencryptionlevel_ts_encryption_level",
                            "choiceSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                "value": "device_vendor_msft_policy_config_remotedesktopservices_clientconnectionencryptionlevel_ts_encryption_level_3",
                                "children": [],
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "c762aaae-7ee2-413c-bd15-32881aefd894"
                                }
                            },
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "7af7dc9e-399a-42d6-8bed-8433c638baa9"
                            }
                        }
                    ],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "553be5f0-b7f4-4a27-98a5-d64e4da809cc"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "d5c15cda-08d9-4f5c-bd90-839637072811"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_internetexplorer_disableenclosuredownloading",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_internetexplorer_disableenclosuredownloading_1",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "615264e2-0d23-4e59-960b-36c1c583f287"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "57446061-8492-404c-990f-e9feac9e7d6d"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_windowslogon_enablemprnotifications",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_windowslogon_enablemprnotifications_0",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "05132456-58ca-4286-bdee-d91690ea0b52"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "e058c985-52de-451e-b9a3-5ddbd1bbe928"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_windowslogon_allowautomaticrestartsignon",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_windowslogon_allowautomaticrestartsignon_0",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "6fc2ec8f-c78f-4fe2-828a-a4efc4ea7439"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "dbaf35c4-57a8-4fbf-8b27-ef018da9c3c3"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_windowspowershell_turnonpowershellscriptblocklogging",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_windowspowershell_turnonpowershellscriptblocklogging_1",
                    "children": [
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_config_windowspowershell_turnonpowershellscriptblocklogging_enablescriptblockinvocationlogging",
                            "choiceSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                "value": "device_vendor_msft_policy_config_windowspowershell_turnonpowershellscriptblocklogging_enablescriptblockinvocationlogging_0",
                                "children": [],
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "28e501f8-b6e4-4329-92c3-bc1d35bb6837"
                                }
                            },
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "a9740d73-a2f0-4833-aa90-99d27f765d15"
                            }
                        }
                    ],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "f12c5491-af5b-4f2e-8b4c-2dc6189f80bc"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "497a4950-f928-47d4-b775-3ecb8320857c"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_remotemanagement_allowbasicauthentication_client",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_remotemanagement_allowbasicauthentication_client_0",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "42109ef0-0789-442d-b2fc-c8662f61d87b"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "85687185-476b-4c04-8016-e37a015f3c1c"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_remotemanagement_allowunencryptedtraffic_client",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_remotemanagement_allowunencryptedtraffic_client_0",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "7afbbf93-8750-4f44-85f5-cb4ac9ee1ea2"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "9d4cbd9f-7b3c-4a20-90df-e7230404bf2e"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_remotemanagement_disallowdigestauthentication",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_remotemanagement_disallowdigestauthentication_1",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "a750d6ec-6834-4751-82f4-413bbcd9cded"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "9722555a-e415-44ba-8b73-79bf10fbd593"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_remotemanagement_allowbasicauthentication_service",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_remotemanagement_allowbasicauthentication_service_0",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "ace993b8-d41d-4dbb-94dc-aece7bcddcd2"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "c5e81f9c-8480-4a17-8d27-efc0da463060"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_remotemanagement_allowunencryptedtraffic_service",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_remotemanagement_allowunencryptedtraffic_service_0",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "4d0a125c-0ec7-4b8f-9395-10fd158387ea"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "d7988f48-757a-4740-a90c-ca363945629f"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_remotemanagement_disallowstoringofrunascredentials",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_remotemanagement_disallowstoringofrunascredentials_1",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "721b0f94-cc8d-4481-8987-8b68361ec12d"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "44ffc847-3686-4e09-9058-4f8c28c7f739"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_audit_accountlogon_auditcredentialvalidation",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_audit_accountlogon_auditcredentialvalidation_3",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "619fa42d-a4f5-4aab-8918-16fe787f4a8f"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "32b3de29-b99f-4afb-a6cd-ee582df0cb7e"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_audit_accountlogonlogoff_auditaccountlockout",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_audit_accountlogonlogoff_auditaccountlockout_2",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "b07ffcbc-125a-4ebc-a93b-ebf640278b88"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "9b369aa9-fec8-4b08-b189-16ec1b34e773"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_audit_accountlogonlogoff_auditgroupmembership",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_audit_accountlogonlogoff_auditgroupmembership_1",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "a5b6d386-b4dd-4e01-ab13-1ebce3c3109c"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "3a0f15a0-2ed7-418c-a79b-8a898235312e"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_audit_accountlogonlogoff_auditlogon",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_audit_accountlogonlogoff_auditlogon_3",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "9b62ab4c-9b5c-4d73-8433-a5be073f8e34"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "1d721324-c445-4c14-94bf-0875d9053951"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_audit_policychange_auditauthenticationpolicychange",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_audit_policychange_auditauthenticationpolicychange_1",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "07941b97-c730-4d01-af0a-01266cbb8770"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "543b3def-6f0a-4cf6-8241-95c34d6cf20d"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_audit_policychange_auditpolicychange",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_audit_policychange_auditpolicychange_1",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "8bfee613-27d2-4bb7-9dd3-042b9f360761"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "8a74951b-ee66-42c9-8534-e3f06d51122a"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_audit_objectaccess_auditfileshare",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_audit_objectaccess_auditfileshare_3",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "a95fbf07-2e6f-4548-a55e-0948315552a5"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "64a2a8ef-6031-49a2-8e3b-0e01415f98f6"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_audit_accountlogonlogoff_auditotherlogonlogoffevents",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_audit_accountlogonlogoff_auditotherlogonlogoffevents_3",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "49454f07-262e-499d-b771-0a6c374d6579"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "b23df640-0e12-4e95-b154-ad848f49af02"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_audit_accountmanagement_auditsecuritygroupmanagement",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_audit_accountmanagement_auditsecuritygroupmanagement_1",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "587cf162-4bc1-4df3-a0b3-b04b34720427"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "16dfd341-ad92-4309-80ba-2839445fc84e"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_audit_system_auditsecuritysystemextension",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_audit_system_auditsecuritysystemextension_1",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "49b680d4-e72a-46d5-bd1e-ec4dbdffa4e6"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "eead22e9-5113-4e90-9aab-6db21c181cd6"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_audit_accountlogonlogoff_auditspeciallogon",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_audit_accountlogonlogoff_auditspeciallogon_1",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "61145c6c-7611-4272-997d-6e29a8501bde"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "cfbb5d70-fc92-4af3-b32c-b16671b038db"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_audit_accountmanagement_audituseraccountmanagement",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_audit_accountmanagement_audituseraccountmanagement_3",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "05429a09-84a2-404a-96a8-867f8712f01b"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "db9e922f-8955-4f6e-a2bc-28a9d56edfd8"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_audit_detailedtracking_auditpnpactivity",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_audit_detailedtracking_auditpnpactivity_1",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "08bb32e6-d609-444c-a827-51ad88665bf1"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "4190d95f-8532-4ac5-b96c-a87e521a59c7"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_audit_detailedtracking_auditprocesscreation",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_audit_detailedtracking_auditprocesscreation_1",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "7286e4e4-915d-47ac-807c-36dd2c98afe6"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "a0dfcef6-a1cf-46aa-be7b-25c1bb51e48c"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_audit_objectaccess_auditdetailedfileshare",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_audit_objectaccess_auditdetailedfileshare_2",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "b1f5ef04-5f39-43cf-936b-5a3ec665350a"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "4590aa3d-f558-4d73-9f1f-488de147e635"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_audit_objectaccess_auditotherobjectaccessevents",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_audit_objectaccess_auditotherobjectaccessevents_3",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "d5dad8e7-bc0b-4ef7-8916-21be64079b33"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "765cbb76-faa1-42a8-871d-ab88ce265be2"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_audit_objectaccess_auditremovablestorage",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_audit_objectaccess_auditremovablestorage_3",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "654944a0-153a-4bd8-88c7-ef7e96186926"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "6dff3117-fd67-42b4-89a8-1be64974d7f3"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_audit_policychange_auditmpssvcrulelevelpolicychange",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_audit_policychange_auditmpssvcrulelevelpolicychange_3",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "ab717ec0-50a1-44f6-bdfb-3bebc9c877ec"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "b6effe28-8269-4b6e-8ccc-7e14ddbea377"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_audit_policychange_auditotherpolicychangeevents",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_audit_policychange_auditotherpolicychangeevents_2",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "71c1002a-a1af-4791-badc-abf179dd3f1d"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "2ccb34ec-e7e8-49c6-be8e-976dbac9e04e"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_audit_privilegeuse_auditsensitiveprivilegeuse",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_audit_privilegeuse_auditsensitiveprivilegeuse_1",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "42344f7b-fce5-4dce-bb09-ab51327401d5"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "90ff86cd-ab47-40a5-b852-90d186b62bff"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_audit_system_auditothersystemevents",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_audit_system_auditothersystemevents_3",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "6fe8f20d-3574-4be5-90dd-e12c9de96a30"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "d00c3a27-e8d9-4c9a-8926-793517613340"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_audit_system_auditsecuritystatechange",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_audit_system_auditsecuritystatechange_1",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "a536b402-6905-4a81-8ad0-339b9ecba70f"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "a679718b-c28d-4980-abb1-852743b47b04"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_audit_system_auditsystemintegrity",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_audit_system_auditsystemintegrity_3",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "2ffcd787-b772-4b32-8482-c9ca0ccc56ad"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "8e6efa6d-a8f3-40f1-a2fd-ca8452fffd00"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_browser_allowpasswordmanager",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_browser_allowpasswordmanager_0",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "beeeed01-4dc5-45ed-b8c3-578e1bab95fc"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "4440dfb7-4164-4dcd-a5c5-46c1d0558a12"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_browser_allowsmartscreen",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_browser_allowsmartscreen_1",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "7c32b6e9-9d18-450b-8438-4a95a27339fe"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "6bdb1980-b5dd-4f0d-9663-2a31b37223ba"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_browser_preventcerterroroverrides",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_browser_preventcerterroroverrides_1",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "ded94c65-4861-42fc-8240-92b82838ebe4"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "124c2e50-5a4d-414b-bff9-d686be5bd697"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_browser_preventsmartscreenpromptoverride",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_browser_preventsmartscreenpromptoverride_1",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "9e050626-50ce-41ee-90b5-71424aefd700"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "107a6613-80ae-49f1-8108-ea0046713f06"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_browser_preventsmartscreenpromptoverrideforfiles",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_browser_preventsmartscreenpromptoverrideforfiles_1",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "6a28e48b-ffe5-4a3d-abfd-34a705303864"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "6e03d2df-8d80-4e98-b4e8-9dc9831d6895"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_dataprotection_allowdirectmemoryaccess",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_dataprotection_allowdirectmemoryaccess_0",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "0ade3ab6-33d3-4640-bc0f-44be72250c25"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "3231c529-ed72-486b-bffb-c9bea1b4a2b5"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_defender_allowarchivescanning",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_defender_allowarchivescanning_1",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "5f0ee961-5c31-472e-bea5-d6b793c8b4f4"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "4629bd6c-e93e-4583-ae0b-330c9c28b694"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_defender_allowbehaviormonitoring",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_defender_allowbehaviormonitoring_1",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "a2b155a3-ffd8-4705-8066-687fa762c912"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "8c626130-a3f8-4d09-b44f-48093a9172b8"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_defender_allowcloudprotection",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_defender_allowcloudprotection_1",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "9cb78a55-aca2-4486-b263-eb3b150de7c5"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "e2eb5f82-3e7d-47ff-a2e0-206a817b61ea"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_defender_allowfullscanremovabledrivescanning",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_defender_allowfullscanremovabledrivescanning_1",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "9b4ff59c-2457-4d43-a003-ae901e87202a"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "9cad9a6a-ae7b-43f0-b046-a31a859538f0"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_defender_allowonaccessprotection",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_defender_allowonaccessprotection_1",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "4447be1b-3c0c-4535-a3a1-dd507627f511"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "3b031b98-5d6e-428d-b5bb-44febe5e802a"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_defender_allowrealtimemonitoring",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_defender_allowrealtimemonitoring_1",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "825dca7a-18d3-4917-85a3-a4c3f371ca65"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "2b8d850d-585d-4c82-80b4-4e88b099dc8e"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_defender_allowioavprotection",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_defender_allowioavprotection_1",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "079cff8c-483e-4351-ac0c-345733df6d56"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "49d492db-dd5b-4a10-86d0-3929c05ad743"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_defender_allowscriptscanning",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_defender_allowscriptscanning_1",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "66600aca-be92-4971-93b9-0be888c8156a"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "71dfc97f-39ab-4196-9406-95223b85fb58"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationGroupSettingCollectionInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_defender_attacksurfacereductionrules",
                "groupSettingCollectionValue": [
                    {
                        "children": [
                            {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                                "settingDefinitionId": "device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockadobereaderfromcreatingchildprocesses",
                                "choiceSettingValue": {
                                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                    "value": "device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockadobereaderfromcreatingchildprocesses_block",
                                    "children": []
                                }
                            },
                            {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                                "settingDefinitionId": "device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockexecutionofpotentiallyobfuscatedscripts",
                                "choiceSettingValue": {
                                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                    "value": "device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockexecutionofpotentiallyobfuscatedscripts_block",
                                    "children": []
                                }
                            },
                            {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                                "settingDefinitionId": "device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockwin32apicallsfromofficemacros",
                                "choiceSettingValue": {
                                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                    "value": "device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockwin32apicallsfromofficemacros_block",
                                    "children": []
                                }
                            },
                            {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                                "settingDefinitionId": "device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockofficeapplicationsfromcreatingexecutablecontent",
                                "choiceSettingValue": {
                                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                    "value": "device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockofficeapplicationsfromcreatingexecutablecontent_block",
                                    "children": []
                                }
                            },
                            {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                                "settingDefinitionId": "device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockcredentialstealingfromwindowslocalsecurityauthoritysubsystem",
                                "choiceSettingValue": {
                                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                    "value": "device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockcredentialstealingfromwindowslocalsecurityauthoritysubsystem_block",
                                    "children": []
                                }
                            },
                            {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                                "settingDefinitionId": "device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockjavascriptorvbscriptfromlaunchingdownloadedexecutablecontent",
                                "choiceSettingValue": {
                                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                    "value": "device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockjavascriptorvbscriptfromlaunchingdownloadedexecutablecontent_block",
                                    "children": []
                                }
                            },
                            {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                                "settingDefinitionId": "device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockofficecommunicationappfromcreatingchildprocesses",
                                "choiceSettingValue": {
                                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                    "value": "device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockofficecommunicationappfromcreatingchildprocesses_block",
                                    "children": []
                                }
                            },
                            {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                                "settingDefinitionId": "device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockofficeapplicationsfrominjectingcodeintootherprocesses",
                                "choiceSettingValue": {
                                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                    "value": "device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockofficeapplicationsfrominjectingcodeintootherprocesses_block",
                                    "children": []
                                }
                            },
                            {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                                "settingDefinitionId": "device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockallofficeapplicationsfromcreatingchildprocesses",
                                "choiceSettingValue": {
                                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                    "value": "device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockallofficeapplicationsfromcreatingchildprocesses_block",
                                    "children": []
                                }
                            },
                            {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                                "settingDefinitionId": "device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockuntrustedunsignedprocessesthatrunfromusb",
                                "choiceSettingValue": {
                                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                    "value": "device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockuntrustedunsignedprocessesthatrunfromusb_block",
                                    "children": []
                                }
                            },
                            {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                                "settingDefinitionId": "device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockexecutablecontentfromemailclientandwebmail",
                                "choiceSettingValue": {
                                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                    "value": "device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockexecutablecontentfromemailclientandwebmail_block",
                                    "children": []
                                }
                            }
                        ]
                    }
                ],
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "3d6107c2-c307-4399-8070-6542f1760309"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_defender_cloudblocklevel",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_defender_cloudblocklevel_2",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "a150d2c7-4380-4021-b311-54a4334f67d5"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "b19fcb8d-3052-4d21-8684-b7b5ab54e02a"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_defender_cloudextendedtimeout",
                "simpleSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationIntegerSettingValue",
                    "value": 50,
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "c8decc1e-14ae-4f77-afd6-e89a786231a1"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "3271caaa-ee8d-4e80-bd0b-82561023b318"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_defender_configuration_disablelocaladminmerge",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_defender_configuration_disablelocaladminmerge_1",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "b2a233d6-49c0-458b-87d4-4345aa826a5f"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "0ccc87b6-38cd-4676-8e06-19ba51bbf875"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_defender_configuration_enablefilehashcomputation",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_defender_configuration_enablefilehashcomputation_1",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "04e39dd9-b74c-4d1e-8a89-823c0b1457ce"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "c288354b-ec37-469b-9d13-195d97405e81"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_defender_enablenetworkprotection",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_defender_enablenetworkprotection_1",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "6bc24627-5077-4614-bdaa-51bc3659e153"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "887ee7fa-4a91-4468-b3e1-1b717c2c2618"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_defender_configuration_hideexclusionsfromlocaladmins",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_defender_configuration_hideexclusionsfromlocaladmins_1",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "1a14248f-9a2b-40cc-9d54-861abe4f3640"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "66037ddc-d716-4f50-9842-c669f6ae4d8f"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_defender_puaprotection",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_defender_puaprotection_1",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "fbd53bb4-a04a-4578-9c70-91f866951506"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "d591684c-569e-42d5-87cb-d015bac955ce"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_defender_realtimescandirection",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_defender_realtimescandirection_0",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "cbdeef1a-a651-4d88-a637-2335e9852f88"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "33bd6674-ae18-43e4-9f10-a7785df1df94"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_defender_submitsamplesconsent",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_defender_submitsamplesconsent_3",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "166b1900-ec5d-48c6-9d6c-0db6ecddb6ad"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "e2cc0998-fb53-4d74-81eb-4962dbdc22bb"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_deviceguard_configuresystemguardlaunch",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_deviceguard_configuresystemguardlaunch_1",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "9860e181-0bb4-4496-8821-ad88edd9a437"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "c5d16b5e-b2b2-4a7a-86be-416eb5ff8d02"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_deviceguard_lsacfgflags",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_deviceguard_lsacfgflags_1",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "2518a53d-bc46-476d-9863-bb4893aae7af"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "0558dfe7-4b99-44e1-98d8-31d67307a090"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_deviceguard_enablevirtualizationbasedsecurity",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_deviceguard_enablevirtualizationbasedsecurity_1",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "ac12acc6-5a5f-4285-b32d-2e09a37f315e"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "81251104-89f3-4011-b3f9-6c1197395485"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_deviceguard_requireplatformsecurityfeatures",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_deviceguard_requireplatformsecurityfeatures_1",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "61892cf7-5a44-4590-a8f8-6ff6afb53ab5"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "0dd32130-3939-446a-85ef-80c65a9f204a"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_devicelock_devicepasswordenabled",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_devicelock_devicepasswordenabled_0",
                    "children": [
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_config_devicelock_devicepasswordhistory",
                            "simpleSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationIntegerSettingValue",
                                "value": 24,
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "0d2ac35c-2ed8-41ce-a25d-4279355d6883"
                                }
                            },
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "59f32bc4-83b6-49e6-966d-3a2b651929be"
                            }
                        },
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_config_devicelock_mindevicepasswordlength",
                            "simpleSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationIntegerSettingValue",
                                "value": 14,
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "b193e752-94a2-4d61-97da-2a237d8c1e8c"
                                }
                            },
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "8f28400a-4098-418a-a0c9-df0da259a06c"
                            }
                        }
                    ],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "d6c39a3e-da62-4879-b4be-d3dfca1949f2"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "50b7d26c-6cd6-4305-af23-adf0432c57d2"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_dmaguard_deviceenumerationpolicy",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_dmaguard_deviceenumerationpolicy_0",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "bfff897c-58c7-4c45-8d80-6a0be472e49c"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "3c3dec21-e31b-46af-99eb-2cb61ad12527"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "user_vendor_msft_policy_config_experience_allowwindowsspotlight",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "user_vendor_msft_policy_config_experience_allowwindowsspotlight_1",
                    "children": [
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_config_experience_allowwindowsconsumerfeatures",
                            "choiceSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                "value": "device_vendor_msft_policy_config_experience_allowwindowsconsumerfeatures_0",
                                "children": [],
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "3845cc66-d148-4ca2-a25e-bbb0ee2b001f"
                                }
                            },
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "d4b80e7a-cde6-4939-b736-794a7201bacd"
                            }
                        },
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "settingDefinitionId": "user_vendor_msft_policy_config_experience_allowthirdpartysuggestionsinwindowsspotlight",
                            "choiceSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                "value": "user_vendor_msft_policy_config_experience_allowthirdpartysuggestionsinwindowsspotlight_0",
                                "children": [],
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "5134d45b-74fb-42c3-834d-da11d009f9f3"
                                }
                            },
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "ed36c396-e8a8-4056-a71c-49ba4b4d48e9"
                            }
                        }
                    ],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "3190c9d4-3fba-45f5-b6b3-fbdebf9ef5a2"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "bb79e6fc-a957-476b-b8a1-0a7b1ac81c6a"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "vendor_msft_firewall_mdmstore_domainprofile_enablefirewall",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "vendor_msft_firewall_mdmstore_domainprofile_enablefirewall_true",
                    "children": [
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance",
                            "settingDefinitionId": "vendor_msft_firewall_mdmstore_domainprofile_logmaxfilesize",
                            "simpleSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationIntegerSettingValue",
                                "value": 16384,
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "3bfbe468-0549-4a70-b742-6b40be6a1087"
                                }
                            },
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "d8a1dc04-88ee-4d57-ac7c-4aaaf3cbfa96"
                            }
                        },
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "settingDefinitionId": "vendor_msft_firewall_mdmstore_domainprofile_defaultinboundaction",
                            "choiceSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                "value": "vendor_msft_firewall_mdmstore_domainprofile_defaultinboundaction_1",
                                "children": [],
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "efe1d365-aca0-405b-92f7-4042f74402b0"
                                }
                            },
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "3616568d-831b-4cd8-8143-627468003eb5"
                            }
                        },
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "settingDefinitionId": "vendor_msft_firewall_mdmstore_domainprofile_enablelogdroppedpackets",
                            "choiceSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                "value": "vendor_msft_firewall_mdmstore_domainprofile_enablelogdroppedpackets_true",
                                "children": [],
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "832698e0-b5e2-4130-9c4f-d49b147e88ae"
                                }
                            },
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "d69a5292-98d0-4b39-baad-5933fd881e3e"
                            }
                        },
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "settingDefinitionId": "vendor_msft_firewall_mdmstore_domainprofile_defaultoutboundaction",
                            "choiceSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                "value": "vendor_msft_firewall_mdmstore_domainprofile_defaultoutboundaction_0",
                                "children": [],
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "003f66fa-4bdc-4c60-b6a5-8c5ad86007b2"
                                }
                            },
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "eeac01d3-39bd-4bc2-8b5c-4f17263eff0d"
                            }
                        },
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "settingDefinitionId": "vendor_msft_firewall_mdmstore_domainprofile_disableinboundnotifications",
                            "choiceSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                "value": "vendor_msft_firewall_mdmstore_domainprofile_disableinboundnotifications_true",
                                "children": [],
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "51366ca3-9811-498f-81be-32fdd32fa967"
                                }
                            },
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "ea17ca65-425e-444e-88fb-9c5794addc54"
                            }
                        },
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "settingDefinitionId": "vendor_msft_firewall_mdmstore_domainprofile_enablelogsuccessconnections",
                            "choiceSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                "value": "vendor_msft_firewall_mdmstore_domainprofile_enablelogsuccessconnections_true",
                                "children": [],
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "3edb867e-05dd-4500-aed3-305d4b8e2105"
                                }
                            },
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "4ab98420-a349-4828-8675-135f9fd29a41"
                            }
                        }
                    ],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "9e4bc472-20d4-4fc9-a9a8-05cdeb1c4f59"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "a3c0eb6a-83e5-41d2-8565-0833de9e3b4e"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "vendor_msft_firewall_mdmstore_privateprofile_enablefirewall",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "vendor_msft_firewall_mdmstore_privateprofile_enablefirewall_true",
                    "children": [
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance",
                            "settingDefinitionId": "vendor_msft_firewall_mdmstore_privateprofile_logmaxfilesize",
                            "simpleSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationIntegerSettingValue",
                                "value": 16384,
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "2b0622e3-f044-4f55-ab24-57a3d5e206d2"
                                }
                            },
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "d4cb87be-47e9-49f7-8267-315bde8b7688"
                            }
                        },
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "settingDefinitionId": "vendor_msft_firewall_mdmstore_privateprofile_defaultinboundaction",
                            "choiceSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                "value": "vendor_msft_firewall_mdmstore_privateprofile_defaultinboundaction_1",
                                "children": [],
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "d0a7f940-5afb-4ce5-8f16-9cb7ad4ad2aa"
                                }
                            },
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "3e8890a4-f038-4cd9-838f-3f66ba184bb6"
                            }
                        },
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "settingDefinitionId": "vendor_msft_firewall_mdmstore_privateprofile_enablelogdroppedpackets",
                            "choiceSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                "value": "vendor_msft_firewall_mdmstore_privateprofile_enablelogdroppedpackets_true",
                                "children": [],
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "2d8d3f5d-2e49-411e-ba5e-03905889ed57"
                                }
                            },
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "6959e391-f432-421f-8bcb-67e6a6fddcc1"
                            }
                        },
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "settingDefinitionId": "vendor_msft_firewall_mdmstore_privateprofile_disableinboundnotifications",
                            "choiceSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                "value": "vendor_msft_firewall_mdmstore_privateprofile_disableinboundnotifications_true",
                                "children": [],
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "da9e56a5-a181-425f-a21a-05a4ad7273f6"
                                }
                            },
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "820911be-8b6d-46d0-83e1-b6b54e999624"
                            }
                        },
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "settingDefinitionId": "vendor_msft_firewall_mdmstore_privateprofile_enablelogsuccessconnections",
                            "choiceSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                "value": "vendor_msft_firewall_mdmstore_privateprofile_enablelogsuccessconnections_true",
                                "children": [],
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "92c28280-cbe7-4048-adcb-63494299f4cb"
                                }
                            },
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "7b49474a-4fa8-4a20-8da3-6ca72734aac2"
                            }
                        },
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "settingDefinitionId": "vendor_msft_firewall_mdmstore_privateprofile_defaultoutboundaction",
                            "choiceSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                "value": "vendor_msft_firewall_mdmstore_privateprofile_defaultoutboundaction_0",
                                "children": [],
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "0a00ddb1-ea27-4525-8ac9-333ae1902547"
                                }
                            },
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "0fa42464-4d1a-4c22-9e35-986408022a91"
                            }
                        }
                    ],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "b8007970-bd96-4b71-ba86-d0d551880148"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "efea36fa-004d-4b46-b7d2-c9ed20d6122e"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "vendor_msft_firewall_mdmstore_publicprofile_enablefirewall",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "vendor_msft_firewall_mdmstore_publicprofile_enablefirewall_true",
                    "children": [
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance",
                            "settingDefinitionId": "vendor_msft_firewall_mdmstore_publicprofile_logmaxfilesize",
                            "simpleSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationIntegerSettingValue",
                                "value": 16384,
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "08f471b8-ed62-41e3-bb52-3db158f25834"
                                }
                            },
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "89151949-4d57-4469-80a3-633350a0809c"
                            }
                        },
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "settingDefinitionId": "vendor_msft_firewall_mdmstore_publicprofile_enablelogdroppedpackets",
                            "choiceSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                "value": "vendor_msft_firewall_mdmstore_publicprofile_enablelogdroppedpackets_true",
                                "children": [],
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "c3e248b6-0f28-4611-a873-0ec39281ad10"
                                }
                            },
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "bfdc2273-e5cc-42c7-a97c-fc377a9abf2e"
                            }
                        },
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "settingDefinitionId": "vendor_msft_firewall_mdmstore_publicprofile_defaultinboundaction",
                            "choiceSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                "value": "vendor_msft_firewall_mdmstore_publicprofile_defaultinboundaction_1",
                                "children": [],
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "5e149012-80ff-481d-9629-51d841cbadcd"
                                }
                            },
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "a32e93ba-be2e-4631-9192-18bbebd5990b"
                            }
                        },
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "settingDefinitionId": "vendor_msft_firewall_mdmstore_publicprofile_allowlocalpolicymerge",
                            "choiceSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                "value": "vendor_msft_firewall_mdmstore_publicprofile_allowlocalpolicymerge_false",
                                "children": [],
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "75064e3e-3aec-478b-acf8-2c233a1172c8"
                                }
                            },
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "304cc793-6468-4875-9bf2-9384c0d0f651"
                            }
                        },
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "settingDefinitionId": "vendor_msft_firewall_mdmstore_publicprofile_defaultoutboundaction",
                            "choiceSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                "value": "vendor_msft_firewall_mdmstore_publicprofile_defaultoutboundaction_0",
                                "children": [],
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "fade140b-cdae-4b5a-af11-18b5258752dd"
                                }
                            },
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "a05f0e16-655c-4608-9e00-89b077e57bf4"
                            }
                        },
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "settingDefinitionId": "vendor_msft_firewall_mdmstore_publicprofile_disableinboundnotifications",
                            "choiceSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                "value": "vendor_msft_firewall_mdmstore_publicprofile_disableinboundnotifications_true",
                                "children": [],
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "f37bf55e-5163-4e3d-8069-30d1c3390531"
                                }
                            },
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "b502beeb-78fc-4b92-8447-1aa09b6ef542"
                            }
                        },
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "settingDefinitionId": "vendor_msft_firewall_mdmstore_publicprofile_enablelogsuccessconnections",
                            "choiceSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                "value": "vendor_msft_firewall_mdmstore_publicprofile_enablelogsuccessconnections_true",
                                "children": [],
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "1cbff808-2ed6-4355-9fa5-52764162d3d7"
                                }
                            },
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "7b5032e3-a8a8-4bac-88be-535c10581456"
                            }
                        },
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "settingDefinitionId": "vendor_msft_firewall_mdmstore_publicprofile_allowlocalipsecpolicymerge",
                            "choiceSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                "value": "vendor_msft_firewall_mdmstore_publicprofile_allowlocalipsecpolicymerge_false",
                                "children": [],
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "01a0a9e2-1153-49f5-8ebe-a63329c496b0"
                                }
                            },
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "93839913-a264-4945-aef5-1372c833f87b"
                            }
                        }
                    ],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "90ee6a7a-e58f-4e95-9947-edcff35a1755"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "5a8b6b58-658e-47a7-a20d-addf7bf18533"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_lanmanworkstation_enableinsecureguestlogons",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_lanmanworkstation_enableinsecureguestlogons_0",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "23d34d64-8a7c-403d-b931-3392cdb3d540"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "885f5d03-c4ba-4067-80ed-03151df6a7c8"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_laps_policies_backupdirectory",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_laps_policies_backupdirectory_1",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "9717b1b9-ea8c-4eed-bea3-40565503862e"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "78874924-d4df-420e-baf7-bd6fd26bcf18"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_localpoliciessecurityoptions_accounts_limitlocalaccountuseofblankpasswordstoconsolelogononly",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_localpoliciessecurityoptions_accounts_limitlocalaccountuseofblankpasswordstoconsolelogononly_1",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "b7c18b12-d7a3-44b5-ba91-8b591d1eebe2"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "a6ea9c66-4363-4efb-b82b-7267f57b5ece"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_localpoliciessecurityoptions_interactivelogon_machineinactivitylimit_v2",
                "simpleSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationIntegerSettingValue",
                    "value": 900,
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "0c2d6162-10b5-4f3b-8c54-f41674abf936"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "1cea246e-e450-4993-b4ee-8b4daf8e70cc"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_localpoliciessecurityoptions_interactivelogon_smartcardremovalbehavior",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_localpoliciessecurityoptions_interactivelogon_smartcardremovalbehavior_1",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "dca8c8e4-e03c-4de8-b72c-e02bee8d2a63"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "a611d952-bce4-4ac2-8e94-3fd4ba5d3a16"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_localpoliciessecurityoptions_microsoftnetworkclient_digitallysigncommunicationsalways",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_localpoliciessecurityoptions_microsoftnetworkclient_digitallysigncommunicationsalways_1",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "5fbfab0b-91a9-4c03-b829-a4eb11243492"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "0c01a1f7-af42-4ccb-8a3a-c07567bb0089"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_localpoliciessecurityoptions_microsoftnetworkclient_sendunencryptedpasswordtothirdpartysmbservers",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_localpoliciessecurityoptions_microsoftnetworkclient_sendunencryptedpasswordtothirdpartysmbservers_0",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "ebc86a23-48dc-4c4a-bf81-83e904b06588"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "6c0bd6db-6402-40b3-bc12-bb948dfc43cf"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_localpoliciessecurityoptions_microsoftnetworkserver_digitallysigncommunicationsalways",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_localpoliciessecurityoptions_microsoftnetworkserver_digitallysigncommunicationsalways_1",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "cdad7c95-fa66-476b-a49d-d22865b945ee"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "b282e470-31b1-44ab-9f8e-2f516780a202"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_localpoliciessecurityoptions_networkaccess_donotallowanonymousenumerationofsamaccounts",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_localpoliciessecurityoptions_networkaccess_donotallowanonymousenumerationofsamaccounts_1",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "554e26e8-c1da-4459-b8f0-f3cc6939a274"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "6fabaf9b-36c8-4c40-887e-93ed6aefa8ce"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_localpoliciessecurityoptions_networkaccess_donotallowanonymousenumerationofsamaccountsandshares",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_localpoliciessecurityoptions_networkaccess_donotallowanonymousenumerationofsamaccountsandshares_1",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "0d790310-f6ea-4832-b1d7-2cc5fe5f0af6"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "71e5c427-7201-4b18-a016-c1bacf4054d5"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_localpoliciessecurityoptions_networkaccess_restrictanonymousaccesstonamedpipesandshares",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_localpoliciessecurityoptions_networkaccess_restrictanonymousaccesstonamedpipesandshares_1",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "2f4b3c7c-4bb1-46c1-8af2-220f80ca865f"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "bab6332a-aac0-452d-ab3a-c3781552dc4f"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_localpoliciessecurityoptions_networkaccess_restrictclientsallowedtomakeremotecallstosam",
                "simpleSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationStringSettingValue",
                    "value": "O:BAG:BAD:(A;;RC;;;BA)",
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "540c9109-bc6f-443c-812e-2b09baf8582c"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "cbe14209-7c72-48f4-89d1-cfeeab1d78a1"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_localpoliciessecurityoptions_networksecurity_donotstorelanmanagerhashvalueonnextpasswordchange",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_localpoliciessecurityoptions_networksecurity_donotstorelanmanagerhashvalueonnextpasswordchange_1",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "0ab2915d-59a8-4db9-8e93-82ae7f88ddb1"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "50f5685c-f499-4392-af5b-e42ea2669e88"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_localpoliciessecurityoptions_networksecurity_lanmanagerauthenticationlevel",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_localpoliciessecurityoptions_networksecurity_lanmanagerauthenticationlevel_5",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "a8418b3b-fe60-406c-b627-9c9d6e55beb9"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "45a4688d-e36b-4f58-be4b-ea629d7cfd2c"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_localpoliciessecurityoptions_networksecurity_minimumsessionsecurityforntlmsspbasedclients",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_localpoliciessecurityoptions_networksecurity_minimumsessionsecurityforntlmsspbasedclients_537395200",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "8706c5c6-4601-47f4-8212-0207ce487c97"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "785d0946-e003-4fa4-b517-245d961612d7"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_localpoliciessecurityoptions_networksecurity_minimumsessionsecurityforntlmsspbasedservers",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_localpoliciessecurityoptions_networksecurity_minimumsessionsecurityforntlmsspbasedservers_537395200",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "8680dcb8-584c-4628-b759-f85f69742dc7"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "50a2e509-4d7c-44fe-8c90-9b9ab4e27624"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_localpoliciessecurityoptions_useraccountcontrol_behavioroftheelevationpromptforadministrators",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_localpoliciessecurityoptions_useraccountcontrol_behavioroftheelevationpromptforadministrators_1",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "2b6dc9a4-a5d8-49e3-9cae-9b88f62635e6"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "04100061-4b8c-4f16-9167-63eaa830e2c1"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_localpoliciessecurityoptions_useraccountcontrol_behavioroftheelevationpromptforstandardusers",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_localpoliciessecurityoptions_useraccountcontrol_behavioroftheelevationpromptforstandardusers_1",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "0a85226c-4988-4298-85a3-5a264f0cadf0"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "7fed1de6-6d25-4b3a-87d1-939b59860ed9"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_localpoliciessecurityoptions_useraccountcontrol_detectapplicationinstallationsandpromptforelevation",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_localpoliciessecurityoptions_useraccountcontrol_detectapplicationinstallationsandpromptforelevation_1",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "9f9b2854-b1fd-4ae1-849c-2c2cdf16a743"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "bab74079-a148-4ab7-b71b-0f5998fbb3e7"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_localpoliciessecurityoptions_useraccountcontrol_onlyelevateuiaccessapplicationsthatareinstalledinsecurelocations",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_localpoliciessecurityoptions_useraccountcontrol_onlyelevateuiaccessapplicationsthatareinstalledinsecurelocations_1",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "8b17fcfd-25e4-4a2f-8f56-296cb530a424"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "e05931c5-d507-405a-a5cc-ed0e837fd550"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_localpoliciessecurityoptions_useraccountcontrol_runalladministratorsinadminapprovalmode",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_localpoliciessecurityoptions_useraccountcontrol_runalladministratorsinadminapprovalmode_1",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "5fbf1169-47fa-427c-a622-cbfafb66fbf8"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "77dec054-14b9-405e-b0a3-6fae171ee7dc"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_localpoliciessecurityoptions_useraccountcontrol_useadminapprovalmode",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_localpoliciessecurityoptions_useraccountcontrol_useadminapprovalmode_1",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "2ab704e2-70fe-4b34-b0af-e4853438423d"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "8169d43b-a789-411d-98c1-717070974310"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_localpoliciessecurityoptions_useraccountcontrol_virtualizefileandregistrywritefailurestoperuserlocations",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_localpoliciessecurityoptions_useraccountcontrol_virtualizefileandregistrywritefailurestoperuserlocations_1",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "fadefee1-4de8-455d-85a7-e1afb3e2c32f"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "18af25c1-ad1e-4ab8-9f73-4a44da053d29"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_localsecurityauthority_configurelsaprotectedprocess",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_localsecurityauthority_configurelsaprotectedprocess_1",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "2371b876-3e5b-4c8d-9da7-cde9e385a49c"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "a8c5e695-e184-4581-b6ac-b564b256d64e"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_applicationmanagement_allowgamedvr",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_applicationmanagement_allowgamedvr_0",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "cf8fb349-bd29-453f-9bd5-6a3bdeb9ecd4"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "88e5df2b-44fc-4f96-9a9d-bdc4c3460ff5"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_applicationmanagement_msiallowusercontroloverinstall",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_applicationmanagement_msiallowusercontroloverinstall_0",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "6d0e6d1d-1fc8-4370-90cc-db8b03c39df2"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "dbd9dd3d-f9d9-4fcc-9bb6-094a9c927d68"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_applicationmanagement_msialwaysinstallwithelevatedprivileges",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_applicationmanagement_msialwaysinstallwithelevatedprivileges_0",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "75657c72-5e5e-4f8f-aaaa-e550c365611b"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "fd84af95-3d88-42ef-a369-0d9f68a59e6b"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_microsoft_edge~policy~microsoft_edge~smartscreen_smartscreenenabled",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_microsoft_edge~policy~microsoft_edge~smartscreen_smartscreenenabled_1",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "bc272f43-906c-418f-b113-565a8a1854aa"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "4a12af0a-4c14-46dc-beff-955d00b017ea"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_microsoft_edge~policy~microsoft_edge~smartscreen_preventsmartscreenpromptoverride",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_microsoft_edge~policy~microsoft_edge~smartscreen_preventsmartscreenpromptoverride_1",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "65fb02dd-61c0-43b0-89da-f11d75ca01bf"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "ff40bd07-443d-4988-b95a-342b5ee76f37"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_privacy_letappsactivatewithvoiceabovelock",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_privacy_letappsactivatewithvoiceabovelock_2",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "2a51bc39-376c-4da4-bb84-726f42d2725e"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "1962acab-d990-470c-848c-5d57e6f4e157"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_search_allowindexingencryptedstoresoritems",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_search_allowindexingencryptedstoresoritems_0",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "0054aa10-809c-426c-9438-45ad1fe47e02"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "5292e47c-7be2-414e-a040-6b5ca351013e"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_webthreatdefense_notifymalicious",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_webthreatdefense_notifymalicious_1",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "deec27ef-749a-4eff-90c6-cdad03600e57"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "9b0ceffd-7f83-4db3-a414-3bac67929fcb"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_webthreatdefense_notifypasswordreuse",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_webthreatdefense_notifypasswordreuse_1",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "6ebd3b05-c125-487a-80b5-3a6fd82dc20a"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "cb9c5284-fa09-4b2d-96e8-cec2ad1bf22e"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_webthreatdefense_notifyunsafeapp",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_webthreatdefense_notifyunsafeapp_1",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "a29bfec5-e7ed-4b5a-af30-9a36c70e1991"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "01a8ec94-8900-4f11-aed9-db1f59616830"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_webthreatdefense_serviceenabled",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_webthreatdefense_serviceenabled_1",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "78171361-7b27-4155-80b9-24cf89c089fd"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "f9284608-1728-4384-9ef1-4fe0119c97cb"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_smartscreen_enablesmartscreeninshell",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_smartscreen_enablesmartscreeninshell_1",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "966b00ac-b2ca-4233-9b93-c1cadad10ab7"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "cb363c90-f514-46aa-acaf-760a277b8f7b"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_smartscreen_preventoverrideforfilesinshell",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_smartscreen_preventoverrideforfilesinshell_1",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "e758a87b-fc8a-4fe7-8a24-5125a1173441"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "746bc3a0-d3ed-4a59-a81e-d0cab7b615f7"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_systemservices_configurexboxaccessorymanagementservicestartupmode",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_systemservices_configurexboxaccessorymanagementservicestartupmode_4",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "fea89187-d70e-4857-9a35-c484279208e2"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "96032425-933b-49d3-9bf2-47764e178489"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_systemservices_configurexboxliveauthmanagerservicestartupmode",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_systemservices_configurexboxliveauthmanagerservicestartupmode_4",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "bd8d9630-6358-451a-ab5b-92b31bd849a7"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "1856834d-09f0-4e9d-b83e-d4d87b6fd255"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_systemservices_configurexboxlivegamesaveservicestartupmode",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_systemservices_configurexboxlivegamesaveservicestartupmode_4",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "265acfa6-5af1-4963-9d3a-4d2b2765a4c7"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "77d53451-b875-4bd0-9bb0-9ac9ca99c50d"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_systemservices_configurexboxlivenetworkingservicestartupmode",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_systemservices_configurexboxlivenetworkingservicestartupmode_4",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "1b757ff4-7c75-4350-8d20-bdbef26e6368"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "4cb5ffab-1d59-4c1e-843f-2861d7fceb55"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_taskscheduler_enablexboxgamesavetask",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_taskscheduler_enablexboxgamesavetask_0",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "2f6204ae-5840-4ad6-a39a-89058ba05575"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "81aecabe-eab5-40dc-8d54-6612552be8bc"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationSimpleSettingCollectionInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_userrights_accessfromnetwork",
                "simpleSettingCollectionValue": [
                    {
                        "value": "*S-1-5-32-544",
                        "@odata.type": "#microsoft.graph.deviceManagementConfigurationStringSettingValue"
                    },
                    {
                        "value": "*S-1-5-32-555",
                        "@odata.type": "#microsoft.graph.deviceManagementConfigurationStringSettingValue"
                    }
                ],
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "5b1a36e3-5503-412b-824b-3a1ae63ea2fd"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationSimpleSettingCollectionInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_userrights_allowlocallogon",
                "simpleSettingCollectionValue": [
                    {
                        "value": "*S-1-5-32-544",
                        "@odata.type": "#microsoft.graph.deviceManagementConfigurationStringSettingValue"
                    },
                    {
                        "value": "*S-1-5-32-545",
                        "@odata.type": "#microsoft.graph.deviceManagementConfigurationStringSettingValue"
                    }
                ],
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "aa5107cc-a779-49db-a1ab-f117bad9bf64"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationSimpleSettingCollectionInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_userrights_backupfilesanddirectories",
                "simpleSettingCollectionValue": [
                    {
                        "value": "*S-1-5-32-544",
                        "@odata.type": "#microsoft.graph.deviceManagementConfigurationStringSettingValue"
                    }
                ],
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "e4e51e09-260d-4f2f-8ab5-f589907f457a"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationSimpleSettingCollectionInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_userrights_createglobalobjects",
                "simpleSettingCollectionValue": [
                    {
                        "value": "*S-1-5-32-544",
                        "@odata.type": "#microsoft.graph.deviceManagementConfigurationStringSettingValue"
                    },
                    {
                        "value": "*S-1-5-19",
                        "@odata.type": "#microsoft.graph.deviceManagementConfigurationStringSettingValue"
                    },
                    {
                        "value": "*S-1-5-20",
                        "@odata.type": "#microsoft.graph.deviceManagementConfigurationStringSettingValue"
                    },
                    {
                        "value": "*S-1-5-6",
                        "@odata.type": "#microsoft.graph.deviceManagementConfigurationStringSettingValue"
                    }
                ],
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "ca63b0ee-d22a-4213-b313-a20114759415"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationSimpleSettingCollectionInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_userrights_createpagefile",
                "simpleSettingCollectionValue": [
                    {
                        "value": "*S-1-5-32-544",
                        "@odata.type": "#microsoft.graph.deviceManagementConfigurationStringSettingValue"
                    }
                ],
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "529aedcf-cd5c-4677-b481-c2107a875236"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationSimpleSettingCollectionInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_userrights_debugprograms",
                "simpleSettingCollectionValue": [
                    {
                        "value": "*S-1-5-32-544",
                        "@odata.type": "#microsoft.graph.deviceManagementConfigurationStringSettingValue"
                    }
                ],
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "a27fcf27-c36d-41c0-8cc5-2fcaed5a03d7"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationSimpleSettingCollectionInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_userrights_denyaccessfromnetwork",
                "simpleSettingCollectionValue": [
                    {
                        "value": "*S-1-5-113",
                        "@odata.type": "#microsoft.graph.deviceManagementConfigurationStringSettingValue"
                    }
                ],
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "567afec8-381f-4ff1-aced-e9d59badf17d"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationSimpleSettingCollectionInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_userrights_denyremotedesktopserviceslogon",
                "simpleSettingCollectionValue": [
                    {
                        "value": "*S-1-5-113",
                        "@odata.type": "#microsoft.graph.deviceManagementConfigurationStringSettingValue"
                    }
                ],
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "bc3c735f-1c25-4877-b86d-6d1adff03eee"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationSimpleSettingCollectionInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_userrights_impersonateclient",
                "simpleSettingCollectionValue": [
                    {
                        "value": "*S-1-5-32-544",
                        "@odata.type": "#microsoft.graph.deviceManagementConfigurationStringSettingValue"
                    },
                    {
                        "value": "*S-1-5-6",
                        "@odata.type": "#microsoft.graph.deviceManagementConfigurationStringSettingValue"
                    },
                    {
                        "value": "*S-1-5-19",
                        "@odata.type": "#microsoft.graph.deviceManagementConfigurationStringSettingValue"
                    },
                    {
                        "value": "*S-1-5-20",
                        "@odata.type": "#microsoft.graph.deviceManagementConfigurationStringSettingValue"
                    }
                ],
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "26fe917a-e117-4219-a4eb-7a6e764cedef"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationSimpleSettingCollectionInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_userrights_loadunloaddevicedrivers",
                "simpleSettingCollectionValue": [
                    {
                        "value": "*S-1-5-32-544",
                        "@odata.type": "#microsoft.graph.deviceManagementConfigurationStringSettingValue"
                    }
                ],
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "a9a9e367-5f32-43b1-95d5-e439a7ddb1c3"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationSimpleSettingCollectionInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_userrights_manageauditingandsecuritylog",
                "simpleSettingCollectionValue": [
                    {
                        "value": "*S-1-5-32-544",
                        "@odata.type": "#microsoft.graph.deviceManagementConfigurationStringSettingValue"
                    }
                ],
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "51e3ac65-dc02-4be1-95de-5a37028cedb8"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationSimpleSettingCollectionInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_userrights_managevolume",
                "simpleSettingCollectionValue": [
                    {
                        "value": "*S-1-5-32-544",
                        "@odata.type": "#microsoft.graph.deviceManagementConfigurationStringSettingValue"
                    }
                ],
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "c391db53-dbd6-4e0d-81e4-f1845887098c"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationSimpleSettingCollectionInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_userrights_modifyfirmwareenvironment",
                "simpleSettingCollectionValue": [
                    {
                        "value": "*S-1-5-32-544",
                        "@odata.type": "#microsoft.graph.deviceManagementConfigurationStringSettingValue"
                    }
                ],
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "64599138-78fc-47d8-a24b-665a0a7551d0"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationSimpleSettingCollectionInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_userrights_profilesingleprocess",
                "simpleSettingCollectionValue": [
                    {
                        "value": "*S-1-5-32-544",
                        "@odata.type": "#microsoft.graph.deviceManagementConfigurationStringSettingValue"
                    }
                ],
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "f67ae512-2092-4b22-ae13-ecaa235593e4"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationSimpleSettingCollectionInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_userrights_remoteshutdown",
                "simpleSettingCollectionValue": [
                    {
                        "value": "*S-1-5-32-544",
                        "@odata.type": "#microsoft.graph.deviceManagementConfigurationStringSettingValue"
                    }
                ],
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "f4d48a3f-3bc5-40d1-88a7-043710c40c44"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationSimpleSettingCollectionInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_userrights_restorefilesanddirectories",
                "simpleSettingCollectionValue": [
                    {
                        "value": "*S-1-5-32-544",
                        "@odata.type": "#microsoft.graph.deviceManagementConfigurationStringSettingValue"
                    }
                ],
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "cb80eb31-1b2f-419f-8667-dc6d0505e7f6"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationSimpleSettingCollectionInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_userrights_takeownership",
                "simpleSettingCollectionValue": [
                    {
                        "value": "*S-1-5-32-544",
                        "@odata.type": "#microsoft.graph.deviceManagementConfigurationStringSettingValue"
                    }
                ],
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "9106ffc1-2777-4e6e-a80c-0f23730ca7ad"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_virtualizationbasedtechnology_hypervisorenforcedcodeintegrity",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_virtualizationbasedtechnology_hypervisorenforcedcodeintegrity_1",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "dc0066bb-e721-49f2-bfcd-19971eddf643"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "bf7b6212-1c6e-4669-a517-6653052f509e"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_wifi_allowautoconnecttowifisensehotspots",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_wifi_allowautoconnecttowifisensehotspots_0",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "cd487ee5-09e0-426b-acfc-04f6a542f85d"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "05ca51b4-beac-4c1c-90fa-103dba821f19"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_wifi_allowinternetsharing",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_wifi_allowinternetsharing_0",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "a35978d6-f58a-44b0-b71e-928e43301283"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "b97154f4-817b-496b-b88d-9bfd80dbe9ca"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_passportforwork_biometrics_facialfeaturesuseenhancedantispoofing",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_passportforwork_biometrics_facialfeaturesuseenhancedantispoofing_true",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "50385f1f-529e-4597-9bc3-efc8b09e1b69"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "6906cb56-4cfc-40bc-9df9-3801bb09a939"
                }
            }
        },
        {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_windowsinkworkspace_allowwindowsinkworkspace",
                "choiceSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                    "value": "device_vendor_msft_policy_config_windowsinkworkspace_allowwindowsinkworkspace_1",
                    "children": [],
                    "settingValueTemplateReference": {
                        "settingValueTemplateId": "0615f2aa-0136-46fc-a89d-687a4934ac28"
                    }
                },
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "74afd036-aacf-4005-8ef1-7e6bbd63d777"
                }
            }
        }
    ],
    "templateReference": {
        "templateId": "66df8dce-0166-4b82-92f7-1f74e3ca17a3_1"
    }
}
"@

    Invoke-GraphAPIRequest -GraphURL 'https://graph.microsoft.com/beta/deviceManagement/configurationPolicies' -Method 'POST' -JsonBody $JsonPayload -AccessToken $token

}

Clear-Host
Write-Host "Creating: Autopilot Deployment Profile (s)" -ForegroundColor Green
Write-Host "Creating: Autopilot Dynamic Imaging Group (s)" -ForegroundColor Cyan
Write-Host "Creating: Autopilot Local Administrator Platform Script" -ForegroundColor Magenta
Write-Host "Creating: Autopilot Cloud LAPS Policy" -ForegroundColor Blue
Write-Host "Creating: Autopilot DoD Custom Baselines" -ForegroundColor DarkMagenta
Write-Host "Creating: Autopilot Security Baselines for Windows" -ForegroundColor Red
Write-Host "Migrating: Autopilot GPOs from On-Prem AD" -ForegroundColor Yellow
Start-Sleep -Seconds 10


#Get JWT Token First
Get-OAuthToken -ClientID '' -ClientSecret '' -TenantName 'domain.com'


#Execute REST API Functions
New-AutopilotDeploymentProfile -DevicePrefixName 'Test' -CloudImageName 'IT', 'Marketing', 'Integration', 'Standard' -Verbose
New-AutopilotDynamicImagingGroups -GroupPrefixName 'Companyxyz' -AutopilotTagNames 'Standard', 'Marketing', 'IT' -Verbose
New-PlatFormScript -LocalAdminAccountName 'admin.companyname' -BaseImagePwd 'WelcomeB@SEImage123$!31' -CompanyName 'mycompany' -Verbose
New-LAPSPolicy -LocalAdminAccountName 'admin.companyname' -Verbose
Get-DODPolicies -Verbose
Expand-DoDPolicies -Verbose
Import-DoDBaselines -Verbose
Import-SecurityBaselines -Verbose
Import-GPOs -Verbose