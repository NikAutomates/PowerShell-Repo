<#
.SYNOPSIS
    Secret-Renewals.ps1
    Automatically renews oAuth & API App Reg Secrets that will expire soon

.DESCRIPTION
    This Script is intended to be used in an Azure Automation Runbook.
    Ensure to use a PowerShell 7.2 Runbook and Encrypt the Client Secret

    A Combination of REST API and the Graph SDK is used. 
    This is to ensure the original App Reg will not break or hault REST API

.NOTES
    Version: V.1.0.0
    Date Written: 08/27/2023
    Written By: Nik Chikersal

    Change Log:
    N/A
#>


Connect-MgGraph

$clientid = "bd815829-a3fb-425c-add5-37e2008b8855"
$Secret = Get-AzKeyVaultSecret -VaultName 'AH-LocalAccounts' -Name 'AppReg-ReadAll' -AsPlainText
$TenantName = 'apex4health.com'

$Body = @{
    Grant_Type    = "client_credentials"
    Scope         = "https://graph.microsoft.com/.default"
    client_Id     = $clientID
    Client_Secret = $Secret
}

$TokenArgs = @{
       Uri    = "https://login.microsoftonline.com/$TenantName/oauth2/v2.0/token" 
       Method = 'POST'
       Body   = $Body
}

$BearerToken = (Invoke-RestMethod @TokenArgs).access_token

$SplatArgs = @{
    Headers =  @{Authorization = "Bearer $($BearerToken)"}
    Uri     =  'https://graph.microsoft.com/v1.0/applications'
    Method  =  'GET'
}

#Store All App Reg values into a Custom Object to use for later
$Results = [System.Collections.ArrayList]@()

$Date = Get-Date
$Tomorrow = $Date.AddDays(1).ToString().Split(" ")[0]
$Today    = $Date.ToString().Split(" ")[0]

(Invoke-RestMethod @SplatArgs).Value | 
    Where-Object {$_.PasswordCredentials.Enddatetime.count -gt "0"} | ForEach-Object {
        $AppReg = $_ 
        $SecretExpiryDate = $AppReg.PasswordCredentials.Enddatetime[0].ToString().Split(" ")[0]

        $CustomObject = [PSCustomObject]@{
            AppName          = $AppReg.DisplayName
            SecretName       = $AppReg.PasswordCredentials.DisplayName
            SecretExpiryDate = $SecretExpiryDate
            SecretKeyID      = $AppReg.PasswordCredentials.KeyID
            AppID            = $AppReg.ID
        }
    [void]$Results.Add($CustomObject)
    }
    

      $ExpiringSecrets = [System.Collections.ArrayList]@()

      $Results | Where-Object {$_.SecretExpiryDate.Equals($Tomorrow)} | ForEach-Object {
      $Expiring = $_

         $Object = [PSCustomObject][Ordered]@{
             AppName          = $Expiring.AppName
             SecretName       = $Expiring.SecretName
             SecretExpiryDate = $Expiring.SecretExpiryDate
             SecretKeyID      = $Expiring.SecretKeyID
             AppID            = $Expiring.AppID
         }
        $ExpiringSecrets.Add($Object)
      }
          

Write-Output "The following Secrets are expiring soon:"
$ExpiringSecrets | Format-Table -AutoSize

$ExpiringSecrets | ForEach-Object {
    $SecretToRemove = $_
    [Array]$SecretToRemove.SecretKeyID | ForEach-Object {
        $SecretKeyID = $_    

        $RemoveSecretParams = @{
            KeyId = $SecretKeyID
        }

        Try {
            Write-Output "Removing Secret: $SecretKeyID from $($SecretToRemove.AppName)"
            Start-Sleep -Seconds 12

        $SecretRemovalArgs = @{
                ApplicationId = $SecretToRemove.AppID
                BodyParameter = $RemoveSecretParams
                ErrorAction   = 'SilentlyContinue'
            }
            Remove-MgApplicationPassword @SecretRemovalArgs 
        } 
        Catch {
            Write-Output "Failed to remove secret $($Error.Exception.Message)[0]"
        }
    }
}

$ExpiringSecrets | ForEach-Object {
$SecretToRenew = $_

 $RenewSecretParams = @{
    passwordCredential = @{
     DisplayName = "AutoRenewed on $Today"
     EndDateTime = (Get-Date).AddMonths(6)
  }
}

   Try {
   $SecretRenewalArgs = @{
         ApplicationId = $SecretToRenew.AppID
         BodyParameter = $RenewSecretParams
      }
      Add-MgApplicationPassword @SecretRenewalArgs | Out-Null
    }
    Catch {
        Write-Output "There was an Error renewing the Secret for $($Expiring.AppName)"
           [PSCustomObject][Ordered]@{
            Failure           = $Error.Exception.Message
            AdditionalDetails = $Error.FullyQualifiedErrorId
           }
        }
    }
   
     if ($ExpiringSecrets -ne $null) {

     $EmailOutput = $ExpiringSecrets | 
     Select-Object AppName, SecretExpiryDate | 
      ConvertTo-Html -Fragment | Out-String -Width 10
     $Headers = @{
     "Authorization" = "Bearer $BearerToken"
     "Content-type"  = "application/json"
}

$MailboxSender = "OneID@apex4health.com"
$Recipients = @("Nik.Chikersal@apex4health.com", "NikTest@apex4health.com")
$Subject    =  "Alert: One or More App Registration Secrets are Expiring"

foreach ($Email in $Recipients) {
    
$URLsend = "https://graph.microsoft.com/v1.0/users/$MailBoxSender/sendMail"
$BodyJsonsend = @"
                    {
                        "message": {
                          "subject": "$subject",
                          "body": {
                            "contentType": "HTML",
                            "content": "The following App Registration Secrets will expire in under 24 hours <br>
                            <br>
                            <br> Warning: App Registrations have Secrets Expiring. The Secrets will be Renewed: <br>
                            $Emailoutput <br>

                            <br>
                            <br>
                            THIS IS AN AUTOMATED MESSAGE, DO NOT REPLY DIRECTLY TO THIS MESSAGE AS IT IS SENT FROM AN UNMONITORED MAILBOX <br>
                           
                            "
                          },
                          "toRecipients": [
                            {
                              "emailAddress": {
                                "address": "$email"
                              }
                            }
                          ]
                        },
                        "saveToSentItems": "false"
                      }
"@

     $EmailSendArgs = @{
       Method  = 'POST'
       Uri     = $URLsend
       Headers = $headers
       Body    = $BodyJsonsend
       }
       Invoke-RestMethod @EmailSendArgs
    }
}
     


    
