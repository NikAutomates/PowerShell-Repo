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

    $global:accessToken = (Invoke-RestMethod @TokenSplat).access_token
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

function Start-OneDriveBackup {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [String]$ContainerUri,
        [Parameter(Mandatory = $true)]
        [String]$SasToken
    )
        
    $global:Users = (Invoke-GraphAPIRequest -GraphURL "https://graph.microsoft.com/beta/users?`$filter=accountenabled eq false" -Method 'GET' -AccessToken $accessToken | 
        Where-Object { $_.onPremisesExtensionAttributes.extensionAttribute1 -ne "Data Retained" -and $_.onPremisesExtensionAttributes.extensionAttribute2 -ne "LOA"}).Userprincipalname

    foreach ($user in $Users) {
        $AllItems = Invoke-GraphAPIRequest -GraphURL "https://graph.microsoft.com/v1.0/users/$($user)/drive/root/children" -Method GET -AccessToken $accessToken
        $localDirectory = "C:\$user"

        function Get-OneDriveItems {
            param (
                [array]$Items,
                [string]$RootDirectory
            )

            foreach ($Item in $Items) {
                $LocalPath = "$RootDirectory/$($Item.name)"
                if (! ([string]::IsNullOrEmpty($Item.folder))) {
                    if (-not (Test-Path -Path $LocalPath)) {
                        New-Item -ItemType Directory -Path $LocalPath
                    }
                    $FolderUrl = "https://graph.microsoft.com/v1.0/users/$($user)/drive/items/$($item.id)/children"
                    $FolderItems = Invoke-GraphAPIRequest -GraphURL $FolderUrl -Method GET -AccessToken $accessToken
                    Get-OneDriveItems -Items $folderItems -RootDirectory $LocalPath
                }
                else {
                    $downloadUrl = $item.'@microsoft.graph.downloadUrl'
                    if (![string]::IsNullOrEmpty($DownloadUrl) -and $DownloadUrl -ne '') {
                        Invoke-WebRequest -Uri $DownloadUrl -OutFile $LocalPath
                    }
                }
            }
        }

        Get-OneDriveItems -Items $AllItems -RootDirectory $LocalDirectory
    }
  
        foreach ($User in $Users) {
            Compress-Archive -Path C:\$user -DestinationPath "$($user).zip" 
        }
        Get-ChildItem -Filter "*.zip" | Foreach-Object {
            [hashtable]$HashArguments = @{
                Uri     = [string]"$($ContainerUri)/$($PSItem.Name)?$($SasToken)"
                Method  = [string]"PUT"
                InFile  = $PSItem.Name
                Headers = [hashtable]@{"x-ms-blob-type" = "BlockBlob" }
                Verbose = [boolean]$true
            }
            try {
                Invoke-RestMethod @HashArguments 
            }
            catch {
                throw $Error[0].Exception.Message
            }
        }
        Remove-Item "*.zip" -Force -Recurse
 
    foreach ($User in $users) {
        $JsonPayload = @"
{
    "onPremisesExtensionAttributes": {
        "extensionAttribute1": "Data Retained"
    }
}
"@
        try {
            Invoke-GraphAPIRequest -GraphURL "https://graph.microsoft.com/v1.0/users/$($User)" -Method 'PATCH' -JsonBody $JsonPayload -AccessToken $accessToken
        }
        catch [System.Exception] {
            throw $Error[0].Exception.Message
        }
    }
}

function Send-EmailNotification {
    [CmdletBinding()]
    param (
        [parameter(Mandatory = $true)]
        [string]$NoReplySenderAddress,
        [parameter(Mandatory = $true)]
        [string]$RecipientAddress
    )

    if (-not [string]::IsNullOrEmpty($users)) {
        $JsonBody = @"
  {
      "message": {
        "subject": "Onedrive Backup Retained in Blob Storage",
        "body": {
          "contentType": "HTML",
          "content": "The following users have their onedrive content downloaded and backed up to Azure Storage.<br>
            <br>
          
          $([string]::Join(", ", $users) | Out-String) <br>
          
          "
        },
        "toRecipients": [
          {
            "emailAddress": {
              "address": "$($RecipientAddress)"
            }
          }
        ]
      },
      "saveToSentItems": "false"
    }
"@   
        try {
            Invoke-GraphAPIRequest `
                -GraphURL "https://graph.microsoft.com/v1.0/users/$($NoReplySenderAddress)/sendMail" `
                -Method 'POST' `
                -JsonBody $JsonBody `
                -AccessToken $accessToken   
        }
        catch {
            throw $global:Error[0].Exception.Message
        }
    }
    Else {
        Write-Output 'No Applicable Users to Backup'
    }
}

<#
Notes for others:

The MSI, if using runbook will need Exchange Perms and Manage as App + Module imported into Automation Account
Adjust authentication as needed.
#>

function ConvertTo-SharedMailbox {
    [CmdletBinding()]
    param ()
}

Connect-ExchangeOnline -ManagedIdentity -Organization 'domain.com'
$Mailboxes = Get-Mailbox -ResultSize Unlimited | Where-Object {$_.CustomAttribute1 -eq 'Data Retained'}
foreach ($Mailbox in $Mailboxes) {
    try {
        if ($Mailbox.RecipientTypeDetails -ne 'SharedMailbox') {
        Set-Mailbox -Identity $Mailbox.name -Type 'Shared' -Force -Verbose
        Write-Output "Converting $($Mailbox.Alias) to Shared"
        }
        else {
            Write-Output "Mailbox $($Mailbox.Alias) is Already Converted"
        }
    }
    catch {
        throw $Error[0].Exception.Message
    }
}

<#

Notes for whoever schedules this code in AWS/Azure/OnPrem:

Preference: Azure Runbooks
Second Preference: Azure Function 
Third Preference: AWS Lambda Function
Fourth: On-Prem task scheduler 

1.) Ensure to create an app reg in tenant and consent entitlements: User.Read, User.Read.All, Files.Read.All, Files.ReadWrite.All, Group.Read.All, Group.ReadWrite.All, Directory.Read.All, Directory.ReadWrite.All, Mail.Send"
2.) Buy an Entra ID Workload License ($3) and apply CAE and Network Restrictions against ClientID via conditional access policy
2.) Secure ClientID secret safely. if you prefer to use Auth code, you'll have to auth with an account via browser. Preference to use the ClientID Grant_type oAuth flow
3.) Setup a SaS Token and Copy Container URI from Storage Account
4.) Setup a NoReply Mailbox for informational alerting post-backup

#>

Get-OAuthToken -ClientID '' -ClientSecret '' -TenantName 'company.com' #run this function first
Start-OneDriveBackup -ContainerUri "https://exampletest.blob.core.windows.net/containername" -SasToken "sv=2022-11-02" -Verbose
Send-EmailNotification -NoReplySenderAddress '' -RecipientAddress ''  
ConvertTo-SharedMailbox
