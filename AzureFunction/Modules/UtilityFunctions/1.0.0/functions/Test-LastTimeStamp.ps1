function Test-LastTimeStamp {
    [CmdletBinding()]
    param (
        $LastTimeStamp
    )

    # Validate User ID is valid GUID

    #if (-not ([system.guid]::TryParse($LastTimeStamp.UserId, [System.Management.Automation.PSReference]([System.Guid]::Empty)))){
    if([string]::IsNullOrEmpty($LastTimeStamp.UserId)){
        throw "Last Time Stamp File: User ID is missing."
        #throw "Last Time Stamp File: User ID is not valid. This should be the GUID of the user."
    }

    # The list of accepted operations is available here: https://docs.microsoft.com/en-us/office/office-365-management-api/office-365-management-activity-api-schema#sharepoint-file-operations
    # The list below is incomplete.
    $validSharePointOperations = @(
        'FileDeleted'
        'FileCopied'
        'FileDownloaded'
    )
    if($LastTimeStamp.Operation -notin $validSharePointOperations){
        throw "Last Time Stamp File: Operation is not valid."
    }

    # Time stamp
    if(-not [string]::IsNullOrEmpty($LastTimeStamp.LastTimeStamp)){
        try{
            Get-Date -Date $LastTimeStamp.LastTimeStamp | Out-Null
        }
        catch{
            throw
        }

    }

    return $true
}