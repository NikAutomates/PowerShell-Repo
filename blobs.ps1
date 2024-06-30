function Set-BlobAccessTiers {
    [CmdletBinding()]
    param (
        [parameter(Mandatory = $True, Position = 0)][ValidatePattern("^[0-9A-Fa-f]{8}-([0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12}$")]
        [string]$SubscriptionID,
        [parameter(Mandatory = $True, Position = 1)]
        [string]$StorageAccountName,
        [parameter(Mandatory = $True, Position = 3)][ValidateLength("86", "88")]
        [string]$StorageAccountKey,
        [parameter(Mandatory = $True, Position = 2)]
        [string]$Container, 
        [parameter(Mandatory = $True, Position = 4)][ValidateSet("Archive", "Hot", "Cool", "Cold")]
        [string]$SourceAccessTier, 
        [parameter(Mandatory = $True, position = 5)][ValidateSet("Archive", "Hot", "Cool", "Cold")]
        [string]$DestinationAccessTier,
        [parameter(Mandatory = $True, position = 6)]
        [switch]$UseMSI

    )

    begin {
        if ($PSCmdlet.MyInvocation.BoundParameters["UseMSI"]) {
            try {
                [void](Connect-AzAccount -Identity -SubscriptionId $SubscriptionID)
            }
            catch [system.exception] {
                throw $global:Error[0].Exception.Message   
            } 
        }
        elseif (-not ($PSCmdlet.MyInvocation.BoundParameters["UseMSI"])) {
            try {
                [void](Connect-AzAccount -SubscriptionId $SubscriptionID)
            }
            catch [system.exception] {
                throw $global:Error[0].Exception.Message   
            }
        }
        $BlobContextSplat = [system.Collections.Specialized.OrderedDictionary]::new()
        $BlobContextSplat["StorageAccountName"] = [string]$StorageAccountName.ToString().ToLower()
        $BlobContextSplat["StorageAccountKey"] = [string]$StorageAccountKey  

        $BlobSplat = [system.Collections.Specialized.OrderedDictionary]::new()
        $BlobSplat["Context"] = (New-AzStorageContext @BlobContextSplat)
        $BlobSplat["Container"] = [string]$Container

        try {
            $global:Blobs = Get-AzStorageBlob @BlobSplat | Where-Object { $_.AccessTier -eq [string]$SourceAccessTier }
        }
        catch [system.exception] {
            throw $global:Error[0].Exception.Message
        }
    }
    process {

        If ($Error[0].FullyQualifiedErrorId.Equals('StorageException,Microsoft.WindowsAzure.Commands.Storage.Blob.Cmdlet.GetAzureStorageBlobCommand')) {
            throw "Please ensure a valid access key was provided"
        }
 
        if ([string]::IsNullOrEmpty($Blobs)) {
            Write-Warning "There are no blobs with the access tier $($SourceAccessTier)"
            return
        }

        switch ($PSCmdlet.MyInvocation.BoundParameters["SourceAccessTier"]) {
            "Archive" {
                foreach ($blob in $blobs) {
                    if ($blob.BlobProperties.ArchiveStatus -eq "rehydrate-pending-to-$($DestinationAccessTier)") {
                        Write-Warning "$($blob.name) is already pending rehydration"
                    }
                    else {
                        try {
                            Write-Output "Archiving $($Blob.Name) from $($Blob.AccessTier) to $($DestinationAccessTier)"
                            [void]$blob.BlobClient.SetAccessTier([Azure.Storage.Blobs.Models.AccessTier]::$($DestinationAccessTier))
                        }
                        catch [system.exception] {
                            return $global:Error[0].Exception.Message
                        }
                    }
                }
            }
            "Hot" {
                foreach ($blob in $Blobs) {
                    try {
                        Write-Output "Setting $($Blob.Name) from $($Blob.AccessTier) to $($DestinationAccessTier)"
                        [void]$blob.BlobClient.SetAccessTier([Azure.Storage.Blobs.Models.AccessTier]::$($DestinationAccessTier))
                    }
                    catch [system.exception] {
                        return $global:Error[0].Exception.Message
                    }
                }
            }
            "Cold" {
                foreach ($blob in $Blobs) {
                    try {
                        Write-Output "Setting $($Blob.Name) from $($Blob.AccessTier) to $($DestinationAccessTier)"
                        [void]$blob.BlobClient.SetAccessTier([Azure.Storage.Blobs.Models.AccessTier]::$($DestinationAccessTier))
                    }
                    catch [system.exception] {
                        return $global:Error[0].Exception.Message
                    }
                }
            }
            "Cool" {
                foreach ($blob in $Blobs) {
                    try {
                        Write-Output "Setting $($Blob.Name) from $($Blob.AccessTier) to $($DestinationAccessTier)"
                        [void]$blob.BlobClient.SetAccessTier([Azure.Storage.Blobs.Models.AccessTier]::$($DestinationAccessTier))
                    }
                    catch [system.exception] {
                        return $global:Error[0].Exception.Message
                    }
                }
            }
        }
    }
}

[hashtable]$CommandSplat = @{
    SubscriptionID        = '2b044532-6ead-4467-9f2d-940c5ebe5fa2'  #Azure Sub ID
    StorageAccountName    = 'vertilocitytest'   #StorageAccountName
    StorageAccountKey     = ''  #StorageAccountKey Goes Here
    Container             = 'test2'  #Azure Container
    SourceAccessTier      = 'Hot'  #Access Tier to target
    DestinationAccessTier = 'Archive' #Access Tier to change to
    UseMSI                = [boolean]$false
}

Set-BlobAccessTiers @CommandSplat
