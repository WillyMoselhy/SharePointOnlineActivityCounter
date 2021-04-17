function Get-AzStorageBlobSasUri {
    [CmdletBinding()]
    param (
        [string] $BlobURL,
        [string] $Permission = 'rw',
        [string] $ValidityMinutes = '15'
    )

    # Extract storage account info from Blob URL
    $matchString = '^https:\/\/(?<StorageAccountName>.+).blob.core.windows.net\/(?<ContainerName>.+?)\/(?<BlobName>.*)$'
    if ($BlobURL -match $matchString) {
        $storageAccountName = $matches.StorageAccountName
        $containerName = $matches.ContainerName
        $blobName = $matches.BlobName
    }
    else {
        throw "Blob URL is not valid."
    }
    # Get Storage Account Keys
    $saKeys = Get-AzResource -Name $storageAccountName -ErrorAction Stop | Get-AzStorageAccountKey -ErrorAction Stop
    IF(-not $saKeys) {throw 'Could not find any keys. Make sure MSI has proper permissions to the storage account.'}

    # Create Storage Context
    $saContext = New-AzStorageContext -StorageAccountName $storageAccountName -StorageAccountKey $saKeys[0].value -ErrorAction Stop

    # Generate SAS Token
    $uri = New-AzStorageBlobSASToken -Context $saContext -Container $containerName -Blob $blobName -Permission $Permission -ExpiryTime (Get-Date).AddMinutes($ValidityMinutes) -FullUri -ErrorAction Stop

    # return URI

    return $uri

}