

function Send-GraphEmail {
    param(
        [Parameter(Mandatory)]
        [string]$AccessToken,
        [Parameter(Mandatory)]
        [string]$SenderEmailAddress,
        [Parameter(Mandatory)]
        [string]$RecipientEmailAddress,
        [Parameter(Mandatory)]
        [string]$Subject,
        [Parameter(Mandatory)]
        [System.Object]$Body
    )

    $JsonBody = @"
{
  "message": {
    "subject": "$($Subject)",
    "body": {
      "contentType": "HTML",
      "content": "$($body)"
    },
    "toRecipients": [       
      {
        "emailAddress": {
          "address": "$($RecipientEmailAddress)"
        }
      }
    ]
  },
  "saveToSentItems": "false"
}
"@

    Invoke-GraphAPIRequest `
        -Uri "https://graph.microsoft.com/v1.0/users/$($SenderEmailAddress)/sendMail" `
        -Method POST `
        -Body $JsonBody `
        -AccessToken $AccessToken
}

Send-GraphEmail -Subject 'Test' -RecipientEmailAddress "" `
 -AccessToken $token -Sender "" -Body (gci | Select Name, Length, LastWriteTime | ConvertTo-Html -Fragment)
