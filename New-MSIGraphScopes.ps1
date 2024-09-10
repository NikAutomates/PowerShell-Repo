#Import/Install Graph Module here - https://www.powershellgallery.com/packages/Graph/1.0.2

<#
.SYNOPSIS
   Short function to grant Graph Scopes (API Scopes) on an MSI/SP
.DESCRIPTION
  Functions works in conjunction with the graph module & an access token with your preference of OAuth flow, I.E Client creds, auth code, etc.
.EXAMPLE
  New-MSIGraphScopes -MSIName 'IAM-Automation' -GraphScopes 'Device.Read.All', 'Device.ReadWrite.All' -AccessToken $GraphToken
#>


function New-MSIGraphScopes {
    [CmdletBinding()]
    param (
        [parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)][ValidateNotNullOrEmpty()]
        [string]$MSIName,
        [parameter(Mandatory = $true, Position = 1, ValueFromPipeline = $true)][ValidateNotNullOrEmpty()]
        [array]$GraphScopes,
        [parameter(Mandatory = $true, Position = 2, ValueFromPipeline = $true)][ValidateNotNullOrEmpty()]
        [array]$GraphToken
    )

    $GlobalSP = Invoke-GraphAPIRequest `
        -GraphURL "https://graph.microsoft.com/beta/servicePrincipals?`$filter=appID eq '00000003-0000-0000-c000-000000000000'" `
        -AccessToken $GraphToken `
        -Method 'GET'

    $MSI = Invoke-GraphAPIRequest `
        -GraphURL "https://graph.microsoft.com/beta/servicePrincipals?`$filter=displayname eq '$($MSIName)'"`
        -AccessToken $GraphToken `
        -Method 'GET'

    [string]$PrincipalID = $MSI.value.id
    [string]$ResourceID = $GlobalSP.id
    $GraphScopeIDs = [system.Collections.ArrayList]::new()

    foreach ($GraphScope in $GraphScopes) {
        $GraphScopeIDs.Add(($GlobalSP.value.AppRoles | Where-Object { $_.Value -eq $GraphScope }))
    }


    foreach ($GraphScopeID in $GraphScopeIDs) {

        $JsonPayLoad = @"
{
  "principalId": "$($PrincipalID)",
  "resourceId": "$($ResourceID)",
  "appRoleId": "$($GraphScopeID.ID)"
}
  
"@
        Invoke-GraphAPIRequest `
            -GraphURL "https://graph.microsoft.com/beta/servicePrincipals/$($MSI.value.ID)/appRoleAssignments" `
            -Method POST `
            -AccessToken $token `
            -JsonBody $JsonPayLoad
    }
}

New-MSIGraphScopes -MSIName 'IAM-Automation' -GraphScopes 'Device.Read.All', 'Device.ReadWrite.All' -AccessToken $GraphToken
