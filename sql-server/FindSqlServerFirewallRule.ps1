<#
.SYNOPSIS
Identifies Azure SQL Servers with the 'AllowAllWindowsAzureIps' firewall rule enabled.

.DESCRIPTION
This script iterates through Azure SQL Servers in the specified subscription (or all accessible subscriptions)
and checks their firewall rules for the presence of the 'AllowAllWindowsAzureIps' rule.

.NOTES
Ensure you are connected to Azure via Connect-AzAccount before running.
Modify the $SubscriptionId variable or remove the Set-AzContext line to scan all accessible subscriptions.
#>

param(
    [Parameter(Mandatory=$false)]
    [string]$SubscriptionId = (Get-AzContext).Subscription.Id # Defaults to the current context's subscription
)

# Set the execution context to the target subscription
Write-Host "Setting context to Subscription ID: $SubscriptionId"
Set-AzContext -SubscriptionId $SubscriptionId | Out-Null

# Initialize an array to store the results
$foundServers = @()

# Get all SQL Servers in the subscription
Write-Host "Retrieving SQL Servers in subscription $SubscriptionId..."
$sqlServers = Get-AzSqlServer

Write-Host "Found $($sqlServers.Count) SQL Servers. Checking firewall rules..."

# Iterate through each SQL Server
foreach ($server in $sqlServers) {
    Write-Verbose "Checking server: $($server.ServerName) in Resource Group: $($server.ResourceGroupName)"
    try {
        # Get firewall rules for the current server
        $firewallRules = Get-AzSqlServerFirewallRule -ResourceGroupName $server.ResourceGroupName -ServerName $server.ServerName -ErrorAction Stop

        # Check if the specific rule 'AllowAllWindowsAzureIps' exists
        # Optionally add: -and $_.StartIpAddress -eq '0.0.0.0' -and $_.EndIpAddress -eq '0.0.0.0' for stricter validation
        $matchingRule = $firewallRules | Where-Object { $_.FirewallRuleName -eq 'AllowAllWindowsAzureIps' }

        if ($null -ne $matchingRule) {
            Write-Host "Found 'AllowAllWindowsAzureIps' rule on server: $($server.ServerName) (RG: $($server.ResourceGroupName))" -ForegroundColor Yellow
            # Add server details to the results array
            $foundServers +=@{
                SubscriptionId  = $SubscriptionId
                ResourceGroupName = $server.ResourceGroupName
                ServerName      = $server.ServerName
                RuleName        = $matchingRule.FirewallRuleName
                StartIpAddress  = $matchingRule.StartIpAddress
                EndIpAddress    = $matchingRule.EndIpAddress
            }
        }
    }
    catch {
        Write-Error "Failed to retrieve firewall rules for server $($server.ServerName). Error: $($_.Exception.Message)"
    }
}

Write-Host "Scan complete."

# Output the list of servers found
if ($foundServers.Count -gt 0) {
    Write-Host "`nServers with 'AllowAllWindowsAzureIps' rule enabled:" -ForegroundColor Green
    $foundServers | Format-Table
} else {
    Write-Host "`nNo servers found with the 'AllowAllWindowsAzureIps' rule enabled in subscription $SubscriptionId." -ForegroundColor Green
}