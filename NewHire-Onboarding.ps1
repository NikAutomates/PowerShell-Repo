#parameters to feed from the website, customize to your liking. Ensure to customize splat in third function
param (

    [parameter(Mandatory = $true)]
    [string]$FirstName,
    [parameter(Mandatory = $true)]
    [string]$LastName,
    [parameter(Mandatory = $true)]
    [string]$CompanyName,
    [parameter(Mandatory = $true)]
    [string]$Department,
    [parameter(Mandatory = $true)]
    [string]$JobTitle,
    [parameter(Mandatory = $true)]
    [string]$ManagerUPN,
    [parameter(Mandatory = $true)]
    [string]$StartDate,
    [parameter(Mandatory = $true)]
    [string]$O365License,
    [parameter(Mandatory = $false)]
    [string]$Country,
    [parameter(Mandatory = $false)]
    [string]$State,
    [parameter(Mandatory = $false)]
    [string]$City,
    [parameter(Mandatory = $false)]
    [string]$ZipCode,
    [parameter(Mandatory = $false)]
    [string]$StreetAddress
)

<#
.SYNOPSIS
This function retrieves an access token (bearer) from the Graph API
.DESCRIPTION
This function may be used local to retrieve an access token, or by creating a credential in an Azure Automation Account
.NOTES
Author: Nik Chikersal
Date: 4/12/2024
Version: V1.0.0
Change Log: N/A
.LINK
https://www.powershellgallery.com/packages/Graph/

.EXAMPLE
Get-BearerToken -ClientID "8c193358-c9c9-4255e-acd8c28f4a" -TenantName "Domain.com" -LocalTest
This example will allow you to retrieve a bearer token locally, by providing the Client App Secret from Azure AD

Get-BearerToken -ClientID "8c193358-c9c9-4255e-acd8c28f4a" -TenantName "Domain.com" -RunbookUserName "ClientSecret-Graph"
This example will retrieve a bearer token from the credential in the Automation Account and autmatically set it on the Runbooks canvas

Get-BearerToken -ClientID "8c193358-c9c9-4255e-acd8c28f4a" -TenantName "Domain.com" -UseDelegatedPermissions
This example will retrieve a bearer token from the ClientID using delegated permissions and the configured app registration re-direct URIs for auth

Get-BearerToken -UseMSI
This example will retrieve a bearer token from the MSI being used in the Azure Automation and Runbook
#>
function Get-BearerToken {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false, Position = 0, ValueFromPipeline = [boolean]$true, ValueFromPipelineByPropertyName = [boolean]$true)]
        [ValidateNotNullOrEmpty()][ValidateLength('30', '36')]
        [string]$ClientID,
        [Parameter(Mandatory = $false, Position = 1, ValueFromPipeline = [boolean]$true, ValueFromPipelineByPropertyName = [boolean]$true )]
        [ValidateNotNullOrEmpty()]
        [string]$TenantName,
        [Parameter(Mandatory = $false, Position = 6)]
        [switch]$LocalTest,
        [Parameter(Mandatory = $false, Position = 4, ValueFromPipeline = [boolean]$true, ValueFromPipelineByPropertyName = [boolean]$true)]
        [string]$RunbookUsername,
        [Parameter(Mandatory = $false, Position = 3)]
        [switch]$UseDelegatedPermissions,
        [Parameter(Mandatory = $false, Position = 5)]
        [switch]$UseMSI
    )

    if (-not $PSCmdlet.MyInvocation.BoundParameters["LocalTest"] -and
       (-not $PSCmdlet.MyInvocation.BoundParameters["RunbookUsername"] -and
       (-not $PSCmdlet.MyInvocation.BoundParameters["UseDelegatedPermissions"] -and
       (-not $PSCmdlet.MyInvocation.BoundParameters["UseMSI"])))) {
        throw "You must include at least one of the following parameters: -LocalTest, -RunbookUserName, -UseDelegatedPermissions, -UseMSI"
    }

    switch ($PSCmdlet.MyInvocation.BoundParameters.Keys) {
        "LocalTest" {
            if (-not $PSCmdlet.MyInvocation.BoundParameters.Keys.Equals("RunbookUserName") -and 
               (-not $PSCmdlet.MyInvocation.BoundParameters.Keys.Equals("UseDelegatedPermissions"))) {
                [string]$Secret = Read-Host "Enter Secret from ClientID"
                if (-not [string]::IsNullOrEmpty($Secret)) {
                    if ($Secret.Length -gt "30") {
                        #[System.Security.SecureString](ConvertTo-SecureString -String $Secret -Force -AsPlainText)
       
                        [hashtable]$Body = [System.Collections.Specialized.OrderedDictionary]::new()
                        [hashtable]$TokenSplat = [System.Collections.Specialized.OrderedDictionary]::new()

                        [hashtable]$Body.Add("Grant_Type", [string]"client_credentials")
                        [hashtable]$Body.Add("Scope", [string]"https://graph.microsoft.com/.default")
                        [hashtable]$Body.Add("client_Id ", [string]$clientID)
                        [hashtable]$Body.Add("Client_Secret", [string]$Secret)
                        [hashtable]$TokenSplat.Add("Uri", [string]"https://login.microsoftonline.com/$TenantName/oauth2/v2.0/token")
                        [hashtable]$TokenSplat.Add("Method", [string]"POST")
                        [hashtable]$TokenSplat.Add("Body", [hashtable]$Body)

                        try {
                            $global:Token = (Invoke-RestMethod @TokenSplat).access_token
                            return $global:Token   
                        }
                        catch [System.Exception] {
                            throw $global:Error[0].Exception.Message
                        }
                    }
                    else {
                        throw "Secret must be 36 characters"
                    }
                }
                else {
                    throw "Secret must not be null or empty"
                }
            }
        }
        "RunbookUsername" {
            if (-not $PSCmdlet.MyInvocation.BoundParameters.Keys.Equals("LocalTest") -and
               (-not $PSCmdlet.MyInvocation.BoundParameters.Keys.Equals("UseDelegatedPermissions"))) {

                if (-not (Get-Command -Name 'Get-AutomationPSCredential' -ErrorAction SilentlyContinue)) {
                    throw "Please ensure this command is being used in an Azure Runbook"
                }

                [hashtable]$Body = [System.Collections.Specialized.OrderedDictionary]::new()
                [hashtable]$TokenSplat = [System.Collections.Specialized.OrderedDictionary]::new()

                [hashtable]$Body.Add("Grant_Type", [string]"client_credentials")
                [hashtable]$Body.Add("Scope", [string]"https://graph.microsoft.com/.default")
                [hashtable]$Body.Add("client_Id ", [string]$clientID)
                [hashtable]$Body.Add("Client_Secret", (Get-AutomationPSCredential -Name $RunbookUsername).GetNetworkCredential().Password)
                [hashtable]$TokenSplat.Add("Uri", [string]"https://login.microsoftonline.com/$TenantName/oauth2/v2.0/token")
                [hashtable]$TokenSplat.Add("Method", [string]"POST")
                [hashtable]$TokenSplat.Add("Body", [hashtable]$Body)

                try {
                  (Invoke-RestMethod @TokenSplat).access_token  
                }
                catch [System.Exception] {
                    throw $global:Error[0].Exception.Message
                }
            }
        }
        "UseDelegatedPermissions" {
            if (-not $PSCmdlet.MyInvocation.BoundParameters.ContainsKey("LocalTest") -and 
               (-not $PSCmdlet.MyInvocation.BoundParameters.ContainsKey("RunbookUsername"))) {
                if (-not (Get-Command Get-MsalToken)) {
                    throw "Ensure you have MSAL.PS Installed. Graph may of not fully installed and loaded the required modules"
                }
                [hashtable]$DelegatedAuthSplat = [System.Collections.Specialized.OrderedDictionary]::new()
                [hashtable]$DelegatedAuthSplat.Add("ClientId", [string]$ClientID)
                [hashtable]$DelegatedAuthSplat.Add("TenantId", [string]$TenantName)
                [hashtable]$DelegatedAuthSplat.Add("Interactive", [boolean]$True)
                try {
                    [string](Get-MsalToken @DelegatedAuthSplat).AccessToken
                }
                catch [System.Exception] {
                    throw $global:Error[0].Exception.Message
                }
            }
        }
        "UseMSI" {
            if ($PSCmdlet.MyInvocation.BoundParameters.Keys.Contains("ClientID") -or
               ($PSCmdlet.MyInvocation.BoundParameters.Keys.Contains("TenantName") -or
               ($PSCmdlet.MyInvocation.BoundParameters.Keys.Contains("LocalTest") -or
               ($PSCmdlet.MyInvocation.BoundParameters.Keys.Contains("RunbookUsername") -or
               ($PSCmdlet.MyInvocation.BoundParameters.Keys.Contains("UseDelegatedPermissions")))))) {
                throw 'You must only use the -UseMSI Parameter while using an MSI in a Runbook'

            }
            else {
                try {
                    [string](Get-GraphAccessToken -UseMSI) #This cmlet runs from Azure Secrets Module
                }
                catch [System.Exception] {
                    return $global:Error[0].Exception.Message
                }
            }
        }
    }
}

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
                        CommandException = $($Global:Error[0])
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

###########################################################REST API Module End##################################################################################

<#
.SYNOPSIS
This function works in conjunction with the graph module to automatically provision AD Identities. This is intended for runbook use.
.DESCRIPTION
This function can be used in conunction with the Graph Module to create an On-Prem AD User and create a graph alert via REST API through email
The alert will send to the manager, a custom user, and will also alert the support team in the event of a failure

Feel free to customize the code according to your orginzations needs. The intention is NOT to create a remote mailbox, therefore, only AD logic is present
Perform Exchange remoting, specify the DAG and create your on-prem/remote mailbox based off your conditions/enviornment. 

.NOTES
Author: Nik Chikersal
Date: 4/30/2024
Version: V1.0.0

Change Log: N/A

.LINK
N/A

.EXAMPLE

New-OnPremIdentity -ClientID "8c193358-c9c9-4255e-acd8c28f4a" -TenantName "Domain.com" -RunbookUserName "ClientID" -AlertCustomUser "john.doe@domain.com"
This example will send onboarding information to a custom mailbox address

New-OnPremIdentity -ClientID "8c193358-c9c9-4255e-acd8c28f4a" -TenantName "Domain.com" -RunbookUserName "ClientID" -AlertManager 
This example will send onboarding information to the user's manager automatically.

Both examples should be used with other mandatory/non-mandatory parameters, depending on attribute needs per orginzation
#>


function New-OnPremIdentity {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $True)]
        [string]$FailureAlertingEmailAddress,
        [Parameter(Mandatory = $True)]
        [string]$NoReplyMailboxSender,
        [Parameter(Mandatory = $false)]
        [switch]$AlertManager,
        [Parameter(Mandatory = $false)]
        [string]$AlertCustomUser,
        [Parameter(Mandatory = $true)]
        [string]$UPNSuffix,
        [Parameter(Mandatory = $true)]
        [string]$TenantName,
        [Parameter(Mandatory = $true)]
        [string]$RunbookUsername,
        [Parameter(Mandatory = $true)]
        [string]$ClientID

    )

    begin {
        ipmo activedirectory

        [string]$token = $(Get-BearerToken -ClientID $ClientID -TenantName $TenantName -RunbookUsername $RunbookUsername)

        if (-not $PSCmdlet.MyInvocation.BoundParameters["AlertCustomUser"] -and
     (-not $PSCmdlet.MyInvocation.BoundParameters["AlertManager"])) {
            throw "You must include at least one of the following parameters: -AlertCustomUser or -AlertManager"
        }

        #If AlertManager param is passed, we will find the managers smtp/email address and send an onboarding email, otherwise it is specified within input string object
        switch ($PSCmdlet.MyInvocation.BoundParameters.Keys) {

            "AlertCustomUser" { $MailboxRecipient = [string]$AlertCustomUser }
            "AlertManager" { $global:MailboxRecipient = [string](Get-ADUser -Properties * -Filter { UserPrincipalName -eq $ManagerUPN }).EmailAddress }
        }

        #Required, must filter UPN into DN Path to set manager attribute within .NET dictionary below
        if (-not ([string]::IsNullOrEmpty($ManagerUPN))) {
            [string]$ManagerDN = [string]$ManagerDN = (Get-ADUser -Properties * -Filter { UserPrincipalName -eq $ManagerUPN }).DistinguishedName
        }
        elseif ([string]::IsNullOrEmpty) {
            [string]$ManagerDN = $null
        }

        [string]$ADTempPass = "@&@WelcometoVS!!$#@" + ( -join ((44..126 | ForEach-Object { [char]$_ }) | Get-Random -Count ((1..8 | Get-Random) + 1)))

        #Ordered dictionary to ensure the values stay in the correct order.
        [hashtable]$global:ADUserSplat = [System.Collections.Specialized.OrderedDictionary]::new()
        $ADUserSplat['Path']                  = [string]"OU=Test,OU=Users,OU=Tst,DC=test,DC=vs,DC=com" #change OU, or dictate of a switch statement
        $ADUserSplat['UserPrincipalName']     = [string]"$FirstName.$LastName@$($UPNSuffix)"
        $ADUserSplat['SamAccountName']        = [string]$FirstName + "." + [string]$LastName
        $ADUserSplat['DisplayName']           = [string]$FirstName + " " + [string]$LastName
        $ADUserSplat['GivenName']             = [string]$FirstName
        $ADUserSplat['Surname']               = [string]$LastName
        $ADUserSplat['Name']                  = [string]$FirstName + "." + [string]$LastName
        $ADUserSplat['Department']            = [string]$Department
        $ADUserSplat['Company']               = [string]$CompanyName
        $ADUserSplat['Title']                 = [string]$JobTitle
        $ADUserSplat['Manager']               = $ManagerDN
        $ADUserSplat['Enabled']               = [boolean]$true
        $ADUserSplat['AccountPassword']       = ConvertTo-SecureString -String $ADTempPass -Force -AsPlainText
        $ADUserSplat['ChangePasswordAtLogon'] = [boolean]$true

        if ([string]::IsNullOrEmpty($ADUserSplat.Manager)) {
            $ADUserSplat.Remove("Manager")
        } 
    }
    process {
        try {
            New-ADUser @ADUserSplat <#-Server $env:USERDNSDOMAIN#>
            $global:ValidateCreation = Get-ADUser -Identity $ADUserSplat.SamAccountName
            if (-not ([string]::IsNullOrEmpty($ValidateCreation))) {
                #Custonize the output of the object "o365license to your liking/needs"
                switch ($O365License) {
                    "E3" { 
                        try {     
                            Add-ADGroupMember -Identity "M365-E3" -Members $ADUserSplat.SamAccountName
                        }
                        catch [system.exception] {
                            Write-Warning $Error[0].Exception.Message
                        }
                    }
                    "F3" { 
                        try {     
                            Add-ADGroupMember -Identity "M365-F3" -Members $ADUserSplat.SamAccountName
                        }
                        catch [system.exception] {
                            Write-Warning $Error[0].Exception.Message
                        }
                    }
                    $null {
                        [boolean]$null 

                    }
                }

                $NewIdentityObj = [PScustomobject]@{
                    EmailAddress = $ADUserSplat.UserPrincipalName
                    StartDate    = [string]$StartDate
                    Title        = [string]$JobTitle
                    Dept         = $ADUserSplat.Department
                    TempPassword = [string]$ADTempPass
                }
            }
            else {
                throw "Account cannot be null or empty"
            }

            $CSS = @"
<style>
body {
font-family: 'Arial', sans-serif;
}
table {
width: 100%;
border-collapse: collapse;
}
th, td {
border: 1px solid #ddd;
padding: 8px;
text-align: left;
}
th {
background-color: #f2f2f2;
}
tr:hover {background-color: #ddd;}
</style>
"@

            $HTMLIdentityObject = $NewIdentityObj | ConvertTo-Html -Fragment | Out-String
            $HTMLIdentityObject = $CSS + $HTMLIdentityObject
            $JsonBodyCreationEmail = @"
  {
      "message": {
        "subject": "New Hire Onboarding: New Hire was onboarded $($ADUserSplat.UserPrincipalname)",
        "body": {
          "contentType": "HTML",
          "content": "Your new associate has been onboarded. Please review the onboarding information below.<br>
            <br>
          
          $HTMLIdentityObject <br>
          
          "
        },
        "toRecipients": [
          {
            "emailAddress": {
              "address": "$($MailboxRecipient)"
            }
          }
        ]
      },
      "saveToSentItems": "false"
    }
"@          #Sending onboarding email via REST API using Graph
            try {
                Invoke-GraphAPIRequest `
                    -GraphURL "https://graph.microsoft.com/v1.0/users/$($NoReplyMailboxSender)/sendMail" `
                    -Method 'POST' `
                    -JsonBody $JsonBodyCreationEmail `
                    -AccessToken $token   
            }
            catch {
                throw $global:Error[0].Exception.Message
            }
        }
        catch [System.Exception] {
            $FailureObj = [PSCustomObject]@{
                Account       = $($FirstName) + "." + $($LastName)
                FailureReason = $Error[0].Exception.Message
            }

            $HTMLFailureObject = $FailureObj | ConvertTo-Html -Fragment | Out-String
            $HTMLFailureObject = $CSS + $HTMLFailureObject
            $JsonBodyFailureEmail = @"
  {
      "message": {
        "subject": "Failure: Account could not be provisioned successfully",
        "body": {
          "contentType": "HTML",
          "content": "The Runbook and Automation workflow failed. Please review the errors below<br>
            <br>
          
          $($HTMLFailureObject) <br>
          
          "
        },
        "toRecipients": [
          {
            "emailAddress": {
              "address": "$($MailboxRecipient)"
            }
          }
        ]
      },
      "saveToSentItems": "false"
    }
"@          #Sending failure email via REST API using graph, in the event the account does not provision properly
            try {
                Invoke-GraphAPIRequest `
                    -GraphURL "https://graph.microsoft.com/v1.0/users/$($NoReplyMailboxSender)/sendMail" `
                    -Method 'POST' `
                    -JsonBody $JsonBodyFailureEmail `
                    -AccessToken $token
            }
            catch {
                throw $global:Error[0].Exception.Message
            }
        } 
    }
    end {
        #Perform dictionary purge to ensure hashtable is not written again before re-executing
        $ADUserSplat.Clear()
    }
}

#Customize to your tenant/AD values in function 

[hashtable]$IdentitySplat = @{
    FailureAlertingEmailAddress = [string]"someone@domain.com"
    NoReplyMailboxSender        = [string]"Sender@domain.com"
    UPNSuffix                   = [string]"" 
    TenantName                  = [string]"yourdomain.com"
    ClientID                    = [string]''
    RunbookUsername             = [string]'ClientID'
}
New-OnPremIdentity @IdentitySplat -AlertManager -Verbose
