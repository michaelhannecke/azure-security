# Azure SQL Security Check: Finding Servers Open to All Azure Services

![SQL Server attacked](/data/sqlfirewallallip.jpeg)

## Introduction: Convenience vs. Security

In the Azure portal, when configuring network access for an Azure SQL Server, you'll find a convenient toggle: **"Allow Azure services and resources to access this server"**. It seems straightforward – perhaps you need your Azure Web App or Azure Functions to connect to your database. Checking this box makes that connection seamless.

However, this convenience comes with a significant security implication often overlooked. Enabling this setting creates a specific firewall rule named `AllowAllWindowsAzureIps` with a start and end IP address of `0.0.0.0`. This *doesn't* just mean *your* Azure services; it means **any IP address originating from within the entire Azure backbone** can potentially reach your SQL server's public endpoint. This includes services running in other customers' subscriptions.

Understanding which of your Azure SQL Servers have this rule enabled is crucial for maintaining a strong security posture. This document introduces a PowerShell script designed to audit your Azure environment and identify these servers.

## Why is Finding the `AllowAllWindowsAzureIps` Rule So Important?

Leaving the `AllowAllWindowsAzureIps` rule enabled unnecessarily can expose your databases to significant risks:

1.  **Massively Increased Attack Surface:** Instead of limiting access to known IPs, you're opening the door to potentially millions of IP addresses across the Azure cloud.[4, 5] If your authentication methods (like SQL logins with weak passwords) are compromised, an attacker running *any* service within Azure could potentially connect.
2.  **Bypassing Network Segmentation:** This rule effectively punches a hole through typical network segmentation strategies at the Azure fabric level for SQL access.
3.  **Compliance Concerns:** Security benchmarks, like the CIS Microsoft Azure Foundations Benchmark, explicitly recommend *against* using this rule unless absolutely necessary and advocate for more granular controls. It flags configurations allowing overly broad access.
4.  **Cross-Tenant Access:** The rule doesn't distinguish between *your* Azure services and those belonging to other Azure tenants.[4, 5] While authentication is still required, the network path is open.

Visibility is the first step to security. You need to know where this rule is active before you can assess the risk and take appropriate action.

## The Solution: An Auditing PowerShell Script

To help you gain this visibility across your Azure environment, we've developed a PowerShell script. This script automates the process of:

1.  Connecting to your Azure account.
2.  Iterating through all subscriptions you have access to.
3.  Identifying all Azure SQL Servers within each subscription.
4.  Checking the firewall rules for each server.
5.  Reporting whether the specific `AllowAllWindowsAzureIps` rule is present.
6.  Saving the comprehensive results to a CSV file for easy review and documentation.

The script operates in a **read-only** mode. It **does not make any changes** to your Azure configuration; it only gathers information about the firewall rules.

## How to Use the Script

Follow these steps to run the audit script:

**Prerequisites:**

  * **Windows PowerShell or PowerShell Core:** You need PowerShell installed on your machine.

  * **Azure Az PowerShell Module:** If you don't have it, install it by running PowerShell as an administrator and executing:powershell

    ```
    Install-Module -Name Az -Scope CurrentUser -Repository PSGallery -Force -AllowClobber
    ```
    *(You might be prompted to trust the repository; answer Yes (`Y`) or Yes to All (`A`)).*


**Steps:**

1.  **Save the Script:** Copy the PowerShell script code provided below into a plain text editor (like Notepad, VS Code, etc.) and save it with a `.ps1` extension (e.g., `FindSqlFirewallRule_AllServers_ToCsv.ps1`). Remember the location where you save it.

```powershell
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
Example: C:\\Temp\\SqlFirewallAudit\_AllServers.csv

.NOTES
Ensure you are connected to Azure via Connect-AzAccount before running.
The script requires permissions to list subscriptions and read SQL Server/Firewall rule details across those subscriptions.
If the specified CSV file exists, it will be overwritten.
\#\>

param(
    [Parameter(Mandatory=$true)]
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
                    RuleName        = $matchingRule.FirewallRuleName
                    StartIpAddress  = $matchingRule.StartIpAddress
                    EndIpAddress    = $matchingRule.EndIpAddress
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
} else {
    Write-Host "No SQL servers found in any of the accessible subscriptions." -ForegroundColor Green
}

```

2.  **Open PowerShell:** Launch a PowerShell console. Running as Administrator might be necessary depending on your system's execution policy settings.

3.  **Connect to Azure:** Run the following command and log in with your Azure credentials when prompted:
    ```powershell
    Connect-AzAccount
    ```

4.  **Navigate to Script Location:** Use the `cd` command to change directory to where you saved the `.ps1` file. For example:
    ```powershell
    cd C:\Scripts
    # or
    cd $HOME\Documents\AzureScripts
    ```

5.  **Run the Script:** Execute the script, providing the full path where you want to save the CSV output file using the mandatory `-OutputCsvPath` parameter:

```powershell

.\FindSqlFirewallRuleAllServersToCsv.ps1 -OutputCsvPath "C:\\Temp\\AzureSqlFirewallAudit.csv"
```

*(Replace `C:\Temp\AzureSqlFirewallAudit.csv` with your desired path and filename).*


*Execution Policy Note:* If you encounter an error about script execution being disabled, you might need to adjust your execution policy. Try running this command (as Administrator) and then run the script again:

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser -Force
```


6.  **Review Output:** The script will print status messages indicating which subscription it's scanning. It will specifically highlight when it finds a server with the `AllowAllWindowsAzureIps` rule enabled. Once finished, it will confirm where the CSV file has been saved.

## Understanding the CSV Output

The generated CSV file (`OutputFile.csv` in the example) contains the following columns for *every* Azure SQL Server scanned:

  * **SubscriptionId:** The ID of the Azure subscription.
  * **SubscriptionName:** The name of the Azure subscription.
  * **ResourceGroupName:** The name of the resource group containing the SQL server.
  * **ServerName:** The name of the Azure SQL Server.
  * **RuleEnabled:** `True` if the `AllowAllWindowsAzureIps` rule exists on the server; `False` otherwise.
  * **RuleName:** `AllowAllWindowsAzureIps` if RuleEnabled is True; blank otherwise.
  * **StartIpAddress:** `0.0.0.0` if RuleEnabled is True; blank otherwise.
  * **EndIpAddress:** `0.0.0.0` if RuleEnabled is True; blank otherwise.

This comprehensive list allows you to easily filter and identify servers requiring attention.

## Mitigation Steps: What To Do Next?

After running the script and identifying servers with `RuleEnabled` set to `True`, follow these steps:

1.  **Review and Validate:** Examine each identified server. Is the broad access granted by `AllowAllWindowsAzureIps` genuinely required for its function? Often, more specific configurations are possible and preferable.
2.  **Remediate (Preferable):**
      * **Disable the Rule:** If the broad access isn't needed, disable the "Allow Azure services and resources to access this server" setting in the Azure portal (Networking blade of the SQL Server) or remove the rule using Azure CLI or PowerShell.
          * *PowerShell:* `Remove-AzSqlServerFirewallRule -ResourceGroupName "YourRG" -ServerName "YourServer" -FirewallRuleName "AllowAllWindowsAzureIps"`
          * *Azure CLI:* `az sql server firewall-rule delete --resource-group "YourRG" --server "YourServer" --name "AllowAllWindowsAzureIps"`
      * **Use Specific IPs:** Replace the rule with specific firewall rules allowing only the necessary public IP addresses or ranges.
      * **Use Private Endpoints:** For the most secure approach, disable public access entirely and use Azure Private Endpoints to allow connections only from within your virtual networks.
3.  **Strengthen Authentication (If Rule Must Stay):** If you absolutely *must* keep the `AllowAllWindowsAzureIps` rule enabled, ensure robust authentication and authorization are in place. Strongly prefer Microsoft Entra ID (formerly Azure Active Directory) authentication over SQL authentication. Entra ID allows for features like Multi-Factor Authentication (MFA), Conditional Access, and Managed Identities, significantly reducing the risk associated with compromised credentials.

4.  **Implement Azure Policy (Proactive Governance):** Create a custom Azure Policy to audit or deny the creation of the `AllowAllWindowsAzureIps` firewall rule. This helps prevent the configuration from being enabled accidentally in the future. You can target the `Microsoft.Sql/servers/firewallrules` type and check if the `name` field equals `AllowAllWindowsAzureIps`.
5.  **Configure Monitoring:** Set up Azure Monitor Activity Log Alerts to notify you whenever a SQL Server firewall rule is created or updated (`Microsoft.Sql/servers/firewallRules/write` operation). This allows for rapid detection of potentially insecure changes.

## Conclusion

The "Allow Azure services and resources to access this server" setting offers convenience but opens a significant network security gap if not managed carefully. Regularly auditing your environment using the provided PowerShell script gives you the necessary visibility to understand your exposure. By reviewing the findings and implementing appropriate mitigation steps – prioritizing the removal of the rule in favor of more secure alternatives like specific IPs or Private Endpoints – you can significantly strengthen the security posture of your Azure SQL databases. Stay vigilant, audit regularly, and enforce the principle of least privilege\!

-----

**Disclaimer:** This script is provided for informational and auditing purposes. Always test scripts in a non-production environment first. This script performs read-only operations against Azure Resource Manager and does not modify your Azure configuration.



