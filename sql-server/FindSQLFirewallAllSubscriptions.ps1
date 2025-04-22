<#
.SYNOPSIS
Identifies Azure SQL Servers with the 'AllowAllWindowsAzureIps' firewall rule enabled across ALL accessible subscriptions.

.DESCRIPTION
This script iterates through all Azure subscriptions the logged-in user has access to.
Within each subscription, it iterates through Azure SQL Servers and checks their firewall rules
for the presence of the 'AllowAllWindowsAzureIps' rule.

.NOTES
Ensure you are connected to Azure via Connect-AzAccount before running.
The script requires permissions to list subscriptions and read SQL Server/Firewall rule details across those subscriptions.
#>

# Ensure connection to Azure
if (-not (Get-AzContext)) {
    Write-Warning "Not connected to Azure. Please run Connect-AzAccount first."
    return
}

# Initialize an array to store the results from all subscriptions
$allFoundServers = @()

# Get all subscriptions the user has access to
Write-Host "Retrieving accessible Azure subscriptions..."
$subscriptions = Get-AzSubscription
Write-Host "Found $($subscriptions.Count) subscriptions. Starting scan..."

# Loop through each subscription
foreach ($subscription in $subscriptions) {
    Write-Host "`n-----------------------------------------------------"
    Write-Host "Scanning Subscription: $($subscription.Name) (ID: $($subscription.Id))"
    Write-Host "-----------------------------------------------------"

    # Set the execution context to the current subscription in the loop
    try {
        Set-AzContext -SubscriptionId $subscription.Id -ErrorAction Stop | Out-Null
    }
    catch {
        Write-Error "Failed to set context for subscription $($subscription.Name) (ID: $($subscription.Id)). Skipping. Error: $($_.Exception.Message)"
        continue # Skip to the next subscription
    }

    # Get all SQL Servers in the current subscription
    Write-Host "Retrieving SQL Servers in subscription $($subscription.Name)..."
    $sqlServers = Get-AzSqlServer -ErrorAction SilentlyContinue # Continue if no servers or permission issues

    if ($null -eq $sqlServers -or $sqlServers.Count -eq 0) {
        Write-Host "No SQL Servers found or unable to retrieve servers in subscription $($subscription.Name)."
        continue # Skip to the next subscription
    }

    Write-Host "Found $($sqlServers.Count) SQL Servers. Checking firewall rules..."

    # Iterate through each SQL Server in the current subscription
    foreach ($server in $sqlServers) {
        Write-Verbose "Checking server: $($server.ServerName) in Resource Group: $($server.ResourceGroupName)"
        try {
            # Get firewall rules for the current server
            $firewallRules = Get-AzSqlServerFirewallRule -ResourceGroupName $server.ResourceGroupName -ServerName $server.ServerName -ErrorAction Stop

            # Check if the specific rule 'AllowAllWindowsAzureIps' exists
            # Optionally add: -and $_.StartIpAddress -eq '0.0.0.0' -and $_.EndIpAddress -eq '0.0.0.0' for stricter validation
            $matchingRule = $firewallRules | Where-Object { $_.FirewallRuleName -eq 'AllowAllWindowsAzureIps' }

            if ($null -ne $matchingRule) {
                Write-Host "Found 'AllowAllWindowsAzureIps' rule on server: $($server.ServerName) (RG: $($server.ResourceGroupName)) in Subscription: $($subscription.Name)" -ForegroundColor Yellow
                # Add server details to the results array
                $allFoundServers += @{
                    SubscriptionId    = $subscription.Id
                    SubscriptionName  = $subscription.Name
                    ResourceGroupName = $server.ResourceGroupName
                    ServerName        = $server.ServerName
                    RuleName          = $matchingRule.FirewallRuleName
                    StartIpAddress    = $matchingRule.StartIpAddress
                    EndIpAddress      = $matchingRule.EndIpAddress
                }
            }
        }
        catch {
            # Log error for specific server but continue script
            Write-Warning "Failed to retrieve firewall rules for server $($server.ServerName) in subscription $($subscription.Name). Error: $($_.Exception.Message)"
        }
    }
    Write-Host "Finished checking servers in subscription $($subscription.Name)."
}

Write-Host "`n====================================================="
Write-Host "Scan across all subscriptions complete."
Write-Host "====================================================="

# Output the list of servers found across all subscriptions
if ($allFoundServers.Count -gt 0) {
    Write-Host "`nServers with 'AllowAllWindowsAzureIps' rule enabled (across all scanned subscriptions):" -ForegroundColor Green
    $allFoundServers | Format-Table -AutoSize
}
else {
    Write-Host "`nNo servers found with the 'AllowAllWindowsAzureIps' rule enabled in any of the accessible subscriptions." -ForegroundColor Green
}