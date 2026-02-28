$LogPath = "\\vmware-host\Shared Folders\shared_logs\normalized_auth.log"

Write-Host "[*] Live Auth Collector (Polished, Ordered, Deduped) started"

# Cache of already processed EventRecordIDs
$seenEvents = @{}

while ($true) {

    $allEvents = @()

    # -------- FAILED LOGONS (4625) --------
    $failedEvents = Get-WinEvent -FilterHashtable @{
        LogName   = 'Security'
        Id        = 4625
        StartTime = (Get-Date).AddSeconds(-30)
    } -ErrorAction SilentlyContinue

    foreach ($e in $failedEvents) {
        if ($seenEvents.ContainsKey($e.RecordId)) { continue }

        $xml = [xml]$e.ToXml()
        $user = ($xml.Event.EventData.Data |
                Where-Object { $_.Name -eq "TargetUserName" }).'#text'

        if (![string]::IsNullOrWhiteSpace($user) -and
            -not $user.EndsWith('$') -and
            $user -ne 'SYSTEM') {

            $allEvents += [PSCustomObject]@{
                Time   = $e.TimeCreated
                Record = $e.RecordId
                User   = $user
                Status = "failed"
            }

            $seenEvents[$e.RecordId] = $true
        }
    }

    # -------- SUCCESS LOGONS (4624) --------
    $successEvents = Get-WinEvent -FilterHashtable @{
        LogName   = 'Security'
        Id        = 4624
        StartTime = (Get-Date).AddSeconds(-30)
    } -ErrorAction SilentlyContinue

    foreach ($e in $successEvents) {
        if ($seenEvents.ContainsKey($e.RecordId)) { continue }

        $xml = [xml]$e.ToXml()
        $logonType = ($xml.Event.EventData.Data |
                     Where-Object { $_.Name -eq "LogonType" }).'#text'

        # Interactive (2) or Unlock (7)
        if ($logonType -ne '2' -and $logonType -ne '7') { continue }

        $user = ($xml.Event.EventData.Data |
                Where-Object { $_.Name -eq "TargetUserName" }).'#text'

        if (![string]::IsNullOrWhiteSpace($user) -and
            -not $user.EndsWith('$') -and
            $user -ne 'SYSTEM') {

            $allEvents += [PSCustomObject]@{
                Time   = $e.TimeCreated
                Record = $e.RecordId
                User   = $user
                Status = "success"
            }

            $seenEvents[$e.RecordId] = $true
        }
    }

    # -------- WRITE IN TIME ORDER --------
    if ($allEvents.Count -gt 0) {
        $allEvents |
            Sort-Object Time |
            ForEach-Object {
                $line = "$($_.Time.ToString('yyyy-MM-dd HH:mm:ss')) | user=$($_.User) | action=login | status=$($_.Status)"
                Add-Content -Path $LogPath -Value $line
            }
    }

    Start-Sleep -Seconds 10
}
