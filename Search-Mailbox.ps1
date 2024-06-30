function Search-Mailbox {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 1, HelpMessage = "Client ID from App Reg")]
        [string]$ClientID,
        [Parameter(Mandatory = $true, Position = 2, HelpMessage = "Client Secret from Vault")]
        [string]$ClientSecret,
        [Parameter(Mandatory = $true, Position = 3, HelpMessage = "Tenant Primary Domain Name")]
        [string]$TenantName,
        [Parameter(Mandatory = $true, Position = 0, HelpMessage = "Entra ID User Object ID")]
        [string]$UserObjectID
    )

    begin {
        if (-not [string]::IsNullOrEmpty($hashtable)) {
            $hashtable.Clear()
        }

        [hashtable]$Body = @{ #ONLY Change grant type and other values if you are using a different oAuth2 flow
            grant_type    = [string]"client_credentials"
            Client_id     = [string]$ClientID
            client_secret = [string]$ClientSecret #store secret in a keyvault or similar
            Scope         = [string]"https://graph.microsoft.com/.default"
        }

        [string]$token = (Invoke-RestMethod -Method "POST" -Body $Body `
                -Uri "https://login.microsoftonline.com/$($TenantName)/oauth2/v2.0/token").access_token

        #if you want to extract from all users, just change the objectID to a looped var and invoke a foreach loop against all users, ensure to paginate if over 1k
        [string]$Uri = "https://graph.microsoft.com/v1.0/users/$($UserObjectID)/messages" 

        $HashtableHeaders = [System.Collections.Hashtable]::new()
        $HashtableHeaders['Authorization'] = "Bearer $($token)"
        $HashtableHeaders['Prefer'] = 'outlook.body-content-type="text"'
        $results = [System.Collections.ArrayList]::new()

        $Mailbox = (Invoke-RestMethod `
                -Uri "https://graph.microsoft.com/v1.0/users/?`$filter=id eq '$($UserObjectID)'" `
                -Method 'GET' -Headers $HashtableHeaders).value.mail
    }
    process {

        [int]$counter = 0
        do {
            $GraphResponse = Invoke-RestMethod -Uri $Uri -Method 'GET' -Headers $HashtableHeaders
            foreach ($Response in $GraphResponse.Value) {
                $counter++
                Write-Host "Extracting Email #$($counter): $($Response.subject) from $($Mailbox)" -ForegroundColor Green
                [void][array]$results.Add($Response)
            }
            $Uri = $GraphResponse.'@odata.nextLink'
        } while ($Uri)

        $global:hashtable = [System.Collections.Specialized.OrderedDictionary]::new()
        for ($i = 0; $i -lt $results.Count; $i++) {
            $global:hashtable[$results.subject[$i]] = $results[$i]
        }
    }
    end {
        $body.Remove("client_secret")
    }
}

Search-Mailbox `
    -ClientID '' `
    -ClientSecret $(Get-AzKeyVaultSecret -VaultName "Az-KV" `
    -Name "ClientID-Secret" -AsPlainText) `
    -TenantName 'mydomain.com' `
    -UserObjectID ''

Function Get-MailboxSearchResults {[hashtable]$Global:hashtable}

Get-MailboxSearchResults



