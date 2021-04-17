function Get-SharePointActivityCount {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string] $UserId,
        [string] $Operation,

        [datetime] $BeginTimeStamp,
        [datetime] $EndTimeStamp
    )

    $SearchUnifiedAuditLogParams = @{
        StartDate  = $BeginTimeStamp
        EndDate    = $EndTimeStamp
        RecordType = 'SharePointFileOperation'
        Operations = $Operation
        ResultSize = 5000
        UserIds    = $UserId
    }
    # get count of files
    try {
        $SearchResult = Search-UnifiedAuditLog @SearchUnifiedAuditLogParams -ErrorAction Stop
    }
    catch {
        throw
    }

    $SearchResultCount = $SearchResult |
    Select-Object -ExpandProperty AuditData |
    ForEach-Object { $_ | ConvertFrom-Json } |
    Group-Object -Property Workload |
    Select-Object Name, Count

    # If no results, set results to 0

    if (-not $SearchResultCount) {
        $SearchResultCount = [PSCustomObject]@{
            Name  = 'NoResults'
            Count = 0
        }

    }

    # Additional members for posting to LAW
    $SearchResultCount | ForEach-Object {
        $_ | Add-Member -MemberType NoteProperty -Name UserId -Value $UserId
        $_ | Add-Member -MemberType NoteProperty -Name Operation -Value $Operation
        $_ | Add-Member -MemberType NoteProperty -Name BeginTimeStamp -Value $BeginTimeStamp
        $_ | Add-Member -MemberType NoteProperty -Name EndTimeStamp -Value $EndTimeStamp
    }

    $SearchResultCount
}
