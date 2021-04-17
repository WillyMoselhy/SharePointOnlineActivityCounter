function Add-LAWEntry {
    [CmdletBinding()]
    param (
        [Parameter()]
        $InputObject,

        [Parameter()]
        [string]
        $LAWId,

        [Parameter()]
        [string]
        $LAWKey,

        [string] $LAWTableName

    )
    begin {
        $LogAnalyticsWorkspaceParameters = @{
            CustomerId     = $LAWId
            SharedKey      = $LAWKey
            TimeStampField = "CollectionTime"
            LogType        = $LAWTableName
        }

    }
    Process{
        foreach ($count in $InputObject){
            $LAWentry = [PSCustomObject]@{
                CollectionTime = [System.DateTime]::UtcNow
                BeginTimeStamp = $count.BeginTimeStamp
                EndTimeStamp   = $count.EndTimeStamp
                UserId         = $count.UserId
                Operation      = $count.Operation
                Workload       = $count.Name
                Count          = $count.Count
            }
            $LAWExportResult = Export-LogAnalytics @LogAnalyticsWorkspaceParameters $LAWentry
            if ($LAWExportResult -ne "200") { throw "An error ($LawExportResult) ocurred while exporting to Log Analytics Workspace" }
        }
    }
}
