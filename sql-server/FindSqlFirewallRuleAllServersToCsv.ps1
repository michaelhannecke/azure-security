<#
.SYNOPSIS
Scans all accessible Azure subscriptions for SQL Servers and reports whether the
'AllowAllWindowsAzureIps' firewall rule is enabled for each, saving the results to a CSV file.

.DESCRIPTION
This script iterates through all Azure subscriptions the logged-in user has access to.
Within each subscription, it iterates through Azure SQL Servers and checks their firewall rules
for the presence of the 'AllowAllWindowsAzureIps' rule.
A CSV file is generated listing all scanned servers and indicating the status of this specific rule.
Console output is minimized to status messages.

.PARAMETER OutputCsvPath
Specifies the full path for the output CSV file.
Example: C:\Temp\SqlFirewallAudit_AllServers.csv

.NOTES
Ensure you are connected to Azure via Connect-AzAccount before running.
The script requires permissions to list subscriptions and read SQL Server/Firewall rule details across those subscriptions.
If the specified CSV file exists, it will be overwritten.
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$OutputCsvPath
)

# Ensure connection to Azure
if (-not (Get-AzContext)) {
    Write-Warning "Not connected to Azure. Please run Connect-AzAccount first."
    return
}

# Initialize an array to store the results from all subscriptions
$allServerStatuses = @()

# Get all subscriptions the user has access to
Write-Host "Retrieving accessible Azure subscriptions..."
$subscriptions = Get-AzSubscription
Write-Host "Found $($subscriptions.Count) subscriptions. Starting scan..."

# Loop through each subscription
foreach ($subscription in $subscriptions) {
    Write-Host "Scanning Subscription: $($subscription.Name) (ID: $($subscription.Id))..."

    # Set the execution context to the current subscription in the loop
    try {
        Set-AzContext -SubscriptionId $subscription.Id -ErrorAction Stop | Out-Null
    }
    catch {
        Write-Error "Failed to set context for subscription $($subscription.Name) (ID: $($subscription.Id)). Skipping. Error: $($_.Exception.Message)"
        continue # Skip to the next subscription
    }

    # Get all SQL Servers in the current subscription
    $sqlServers = Get-AzSqlServer -ErrorAction SilentlyContinue # Continue if no servers or permission issues

    if ($null -eq $sqlServers -or $sqlServers.Count -eq 0) {
        Write-Host "No SQL Servers found or unable to retrieve servers in subscription $($subscription.Name)."
        continue # Skip to the next subscription
    }

    # Iterate through each SQL Server in the current subscription
    foreach ($server in $sqlServers) {
        Write-Verbose "Checking server: $($server.ServerName) in Resource Group: $($server.ResourceGroupName)" # Verbose for detailed tracing if needed

        $ruleFound = $false
        $ruleDetails = $null

        try {
            # Get firewall rules for the current server
            $firewallRules = Get-AzSqlServerFirewallRule -ResourceGroupName $server.ResourceGroupName -ServerName $server.ServerName -ErrorAction Stop

            # Check if the specific rule 'AllowAllWindowsAzureIps' exists [1, 2]
            $matchingRule = $firewallRules | Where-Object { $_.FirewallRuleName -eq 'AllowAllWindowsAzureIps' }

            if ($null -ne $matchingRule) {
                $ruleFound = $true
                # Capture details only if the rule is found
                $ruleDetails = @{
                    RuleName       = $matchingRule.FirewallRuleName
                    StartIpAddress = $matchingRule.StartIpAddress
                    EndIpAddress   = $matchingRule.EndIpAddress
                }
                Write-Host "Found 'AllowAllWindowsAzureIps' rule on server: $($server.ServerName) (RG: $($server.ResourceGroupName)) in Subscription: $($subscription.Name)" -ForegroundColor Yellow
            }
        }
        catch {
            # Log error for specific server but continue script
            Write-Warning "Failed to retrieve firewall rules for server $($server.ServerName) in subscription $($subscription.Name). Error: $($_.Exception.Message)"
            # Add server to list even if rules couldn't be checked, mark as error? Or skip? Adding with RuleEnabled=$false and note.
            # For simplicity, we'll add it with RuleEnabled = $false and null rule details if an error occurs during rule check.
        }

        # Add server status to the results array regardless of rule presence
        $allServerStatuses += @{
            SubscriptionId    = $subscription.Id
            SubscriptionName  = $subscription.Name
            ResourceGroupName = $server.ResourceGroupName
            ServerName        = $server.ServerName
            RuleEnabled       = $ruleFound # True if rule exists, False otherwise or on error
            RuleName          = if ($ruleFound) { $ruleDetails.RuleName } else { $null }
            StartIpAddress    = if ($ruleFound) { $ruleDetails.StartIpAddress } else { $null }
            EndIpAddress      = if ($ruleFound) { $ruleDetails.EndIpAddress } else { $null }
        }
    } # End foreach server
} # End foreach subscription

Write-Host "`nScan across all subscriptions complete."

# Export the results to CSV
if ($allServerStatuses.Count -gt 0) {
    try {
        # Select the properties in desired order for the CSV
        $allServerStatuses | Select-Object SubscriptionId, SubscriptionName, ResourceGroupName, ServerName, RuleEnabled, RuleName, StartIpAddress, EndIpAddress | Export-Csv -Path $OutputCsvPath -NoTypeInformation -Force -ErrorAction Stop
        Write-Host "Results for all scanned servers saved to: $OutputCsvPath" -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to save results to CSV file '$OutputCsvPath'. Error: $($_.Exception.Message)"
    }
}
else {
    Write-Host "No SQL servers found in any of the accessible subscriptions." -ForegroundColor Green
}