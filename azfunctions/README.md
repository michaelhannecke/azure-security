# Automating Azure SQL Firewall Auditing with Azure Functions and Table Storage
IntroductionMaintaining secure configurations across numerous Azure SQL Servers, potentially spanning multiple subscriptions, presents a significant operational challenge. 
Firewall rules, a critical component of SQL Server security, require regular auditing to ensure compliance with organizational policies and prevent unauthorized access. Manually performing these audits is time-consuming, error-prone, and difficult to scale.

This post details a robust and automated solution for auditing Azure SQL Server firewall rules across an Azure environment. By leveraging Azure Functions with PowerShell, Managed Identities for secure authentication, and Azure Table Storage for centralized reporting, organizations can achieve continuous, automated compliance checks without managing credentials. 

This approach enhances security posture by providing timely insights into firewall configurations, facilitates automated reporting, and significantly reduces the manual effort required for audits. The core benefits include improved security through credential-less access, automation of repetitive tasks, scalability across numerous subscriptions and servers, and a centralized, queryable audit log stored efficiently in Azure Table Storage. 

[Managed Identities - Azure App Service](https://learn.microsoft.com/en-us/azure/app-service/overview-managed-identity)

[Managed Identities for Azure resources](https://learn.microsoft.com/en-us/entra/identity/managed-identities-azure-resources/overview)

## Phase 1 : Azure Function App Setup
The foundation of this automated audit solution is an Azure Function App configured to run PowerShell scripts.

#### Creating the Function App Resource
The first step involves creating the Function App resource within Azure. This can be accomplished through various methods, including the Azure portal, Azure CLI, or Azure PowerShell. When using the Azure portal, the process involves selecting "Create a resource," choosing "Function App," and configuring the basic settings.

[Create your first function in the Azure Portal](https://learn.microsoft.com/en-us/azure/azure-functions/functions-create-function-app-portal)

Crucially, during the creation process, the Runtime stack must be set to PowerShell Core. This ensures the Function App environment is equipped to execute the PowerShell audit script. 

Select the desired PowerShell version compatible with the script's dependencies. Additionally, choose an appropriate Hosting Plan. The Consumption plan is often suitable for event-driven tasks like this audit, offering cost-efficiency by billing only for execution time, although it has execution time limits to consider.

Select a region, provide a globally unique name for the Function App, and assign it to a resource group.

Accepting the defaults for Storage and Monitoring typically provisions a required Azure Storage account and an Application Insights instance for logging and monitoring.

#### Enabling System-Assigned Managed Identity
To eliminate the need for storing credentials within the script or application settings, a system-assigned Managed Identity should be enabled for the Function App. This identity is automatically managed by Azure, tied to the lifecycle of the Function App, and can be granted permissions to other Azure resources using Azure Role-Based Access Control (RBAC).

Enabling the system-assigned identity can be done through:

**Azure Portal:** 
Navigate to the Function App, select "Identity" under "Settings," switch the "Status" on the "System assigned" tab to "On," and save the changes.

**Azure CLI:**
Use the az webapp identity assign command (which applies to Function Apps as well).

````
az webapp identity assign --resource-group <YourResourceGroupName> --name <YourFunctionAppName>
````


**Azure PowerShell:**
Use the Update-AzFunctionApp cmdlet with the -IdentityType SystemAssigned parameter.

```
Update-AzFunctionApp -ResourceGroupName <YourResourceGroupName> -Name <YourFunctionAppName> -IdentityType SystemAssigned
````

Once enabled, Azure provisions a service principal in Microsoft Entra ID representing the Function App's identity. This identity's Object (principal) ID will be used in the next phase to assign necessary permissions.

## Phase 2: Permissions Configuration via Azure RBAC
The Managed Identity created in the previous step requires specific permissions to read Azure SQL Server configurations and write audit results to Azure Table Storage. These permissions are granted using Azure Role-Based Access Control (RBAC).

RBAC allows for fine-grained access management by assigning roles to security principals (like Managed Identities) at specific scopes.8Assigning roles involves defining the security principal (the Function App's Managed Identity), the role definition (the set of permissions), and the scope (the set of resources the permissions apply to).

[Steps to assign an Azure role](https://learn.microsoft.com/en-us/azure/role-based-access-control/role-assignments-steps)

[Assign roles using Azure CLI](https://learn.microsoft.com/en-us/azure/role-based-access-control/role-assignments-cli)

83.1 Identifying the Managed Identity Principal IDBefore assigning roles, obtain the Object (principal) ID of the Function App's system-assigned Managed Identity. This ID uniquely identifies the service principal in Microsoft Entra ID. It can be found in the Azure portal on the Function App's "Identity" page after enabling the system-assigned identity 1 or retrieved using Azure CLI (az webapp identity show) or Azure PowerShell (Get-AzFunctionApp).3.2 Assigning Reader Role for SQL Resource DiscoveryTo allow the Function App to list subscriptions (if necessary) and discover Azure SQL Servers and their firewall rules within those subscriptions, the Managed Identity needs read permissions.
Role: The Reader role is sufficient. This role allows viewing all resources but prohibits making changes.11
Scope: The scope determines which resources the identity can read. It must encompass all subscriptions intended for auditing.

Management Group: Assigning the Reader role at a Management Group level grants access to all subscriptions within that group and any future subscriptions added to it. This is often the most efficient approach for broad auditing.14
Subscription: Alternatively, assign the Reader role individually to each target subscription.14 This provides more granular control but requires more management overhead if the list of subscriptions changes frequently.
Resource Group/Resource: Assigning at these levels is too narrow for discovering servers across subscriptions.


Assignment: Use the Azure portal's Access Control (IAM) page at the chosen scope (Management Group or Subscription), select "Add role assignment," choose the "Reader" role, select "Managed identity" as the member type, and find/select the Function App's Managed Identity using its name or Object ID.16
3.3 Assigning Storage Table Data Contributor Role for Audit OutputTo enable the Function App to write the audit results (firewall rule details) into the designated Azure Storage Table, the Managed Identity requires data plane permissions on the target storage account.
Role: The Storage Table Data Contributor role provides the necessary permissions to read, write, and delete table entities.11
Scope: Assign this role at the level of the Storage Account that contains the target audit table. Assigning at a broader scope (Resource Group or Subscription) would grant unnecessary permissions to other storage resources.20 Scoping directly to the table is possible via CLI/PowerShell but often simpler to manage at the account level for this use case.18
Assignment: Use the Azure portal's Access Control (IAM) page on the target Storage Account, select "Add role assignment," choose the "Storage Table Data Contributor" role, select "Managed identity" as the member type, and find/select the Function App's Managed Identity.16
Granting permissions with the least privilege necessary at the narrowest effective scope is a fundamental security best practice.94. Phase 3: Azure Storage Table SetupAzure Table Storage provides a cost-effective, scalable NoSQL key-attribute store suitable for storing the structured audit data generated by the PowerShell script.224.1 Creating the Azure Storage AccountIf a suitable Azure Storage account is not already available, one needs to be created. This account will host the table containing the audit results.
Creation: Use the Azure portal 24, Azure PowerShell (New-AzStorageAccount 26), or Azure CLI (az storage account create 24) to create a new storage account.
Account Type: A Standard general-purpose v2 account is recommended for most scenarios, offering access to tables, blobs, queues, and files.27 Premium tiers are available but typically unnecessary for this audit log use case.24
Configuration: Provide a globally unique name (3-24 lowercase letters/numbers), select the subscription and resource group, choose a region (ideally the same region as the Function App for lower latency), and select a redundancy option (e.g., LRS, GRS) based on availability requirements.24
4.2 Creating the Audit TableWithin the chosen storage account, a specific table must be created to hold the firewall audit data.
Creation: Use the Azure portal's Storage Browser 29 or Azure PowerShell (New-AzStorageTable 26) to create the table.
Naming: Assign a meaningful name, such as SqlFirewallAudit. Table names have specific naming conventions (e.g., alphanumeric, cannot start with a number).35
4.3 Defining the Table Schema (Entity Properties)Azure Table Storage is schema-less, meaning tables don't enforce a fixed structure on entities beyond the required keys.22 However, defining a consistent structure within the PowerShell script is essential for querying and interpreting the audit data. Each record written to the table is an "entity," analogous to a row in a relational database, composed of properties (key-value pairs).22Every entity must have the following system properties 36:
PartitionKey (String): Groups related entities together physically. Entities with the same PartitionKey are stored in the same partition, enabling efficient queries and atomic transactions (Entity Group Transactions) within that partition.36 Choosing a good PartitionKey is critical for scalability and performance.39 For this audit scenario, using the SubscriptionID is a reasonable choice, grouping all rules from the same subscription together.
RowKey (String): Uniquely identifies an entity within a specific partition.36 The combination of PartitionKey and RowKey forms the unique primary key for the entity.39 Querying by both PartitionKey and RowKey (a "point query") is the most efficient way to retrieve data.38 A composite key incorporating the ServerName and FirewallRuleName (e.g., ServerName + "_" + FirewallRuleName) ensures uniqueness within a subscription and allows direct lookup of a specific rule on a specific server.
Timestamp (DateTime): Automatically maintained by Azure, indicating the last modification time. Used for optimistic concurrency.36
In addition to the required keys, the following custom properties should be included in each entity written by the script:
SubscriptionName (String): Human-readable name of the subscription.
ResourceGroupName (String): Name of the resource group containing the SQL server.
ServerName (String): Name of the SQL server.
FirewallRuleName (String): Name of the specific firewall rule.
StartIpAddress (String): The starting IP address of the rule, [100].
EndIpAddress (String): The ending IP address of the rule, [100].
IsAllowAllWindowsAzureIpsRule (Boolean): Flag indicating if this is the special rule (AllowAllWindowsAzureIps) representing "Allow Azure services..." [50],.
IsRuleEnabled (Boolean): Flag indicating if the rule was found during the current audit run (useful for tracking deleted rules).
AuditTimestamp (DateTime): Timestamp recorded by the function when the audit for this rule was performed.
Designing the PartitionKey and RowKey based on expected query patterns is paramount for performance in Azure Table Storage.38 Using SubscriptionID as PartitionKey balances partitioning (avoiding a single hot partition) with the ability to query all rules for a given subscription efficiently.395. Phase 4: PowerShell Script Adaptation (run.ps1)The core PowerShell script (run.ps1) residing within the Function App needs modification to authenticate using the Managed Identity and to direct its output to the configured Azure Storage Table instead of a local file. The basic structure involves connecting to Azure, iterating through subscriptions and servers, retrieving firewall rules, and writing data to the table.4PowerShell# Input bindings are passed in via param block.
param($Timer) # Or $Request for HTTP trigger

# Get the current universal time
$currentUTCtime = (Get-Date).ToUniversalTime()
Write-Host "PowerShell timer trigger function starting audit at: $currentUTCtime"

# --- Core Audit Logic Start ---

# 1. Connect to Azure using Managed Identity
# 2. Get Subscriptions (accessible by Managed Identity)
# 3. Loop through Subscriptions
# 4.   Set Azure Context to current Subscription
# 5.   Get SQL Servers in Subscription
# 6.   Loop through SQL Servers
# 7.     Get Firewall Rules for Server
# 8.     Connect to/Get reference for Azure Table Storage
# 9.     (Optional: Pre-fetch existing rules for this server from Table Storage for stale detection)
# 10.    Loop through current Firewall Rules
# 11.      Construct Table Entity Object (mapping rule properties)
# 12.      Write/Update Table Entity using appropriate method (Upsert)
# 13.    (Optional: Identify and mark stale rules in Table Storage)

# --- Core Audit Logic End ---

# Optional: Log completion
Write-Host "Audit completed at: $((Get-Date).ToUniversalTime())"

5.1 Implementing Managed Identity AuthenticationThe script must authenticate to Azure Resource Manager using the Function App's Managed Identity. This replaces interactive login prompts or stored credentials.
Method: Use the Connect-AzAccount cmdlet with the -Identity switch.44 This command automatically utilizes the Managed Identity available in the Azure Functions execution environment.
Placement: Execute this command at the beginning of the script, before any cmdlets requiring Azure authentication (like Get-AzSubscription or Get-AzSqlServer).
Error Handling: Wrap the connection attempt in a try/catch block to handle potential authentication failures and log appropriate errors.48
PowerShelltry {
    Write-Host "Connecting to Azure using Managed Identity..."
    Connect-AzAccount -Identity
    Write-Host "Successfully connected to Azure."
} catch {
    Write-Error "FATAL: Failed to connect to Azure using Managed Identity: $_"
    # Exit the function if connection fails, as subsequent operations will fail.
    return
}
5.2 Iterating Through Subscriptions and SQL ServersThe script needs to discover the SQL servers within the scope granted to the Managed Identity.
Get Subscriptions: Use Get-AzSubscription to retrieve a list of subscriptions accessible by the Managed Identity (based on the 'Reader' role assigned earlier). If the 'Reader' role was assigned at a Management Group scope, this cmdlet will return all subscriptions within that scope. Filter this list if only specific subscriptions need auditing.
Looping and Context: Implement a foreach loop to iterate through the retrieved subscriptions. Inside the loop, use Set-AzContext -SubscriptionId $sub.Id to switch the current execution context to the specific subscription. Within this context, use Get-AzSqlServer to retrieve all SQL servers in that subscription.
Error Handling: Enclose calls to Get-AzSubscription and Get-AzSqlServer within try/catch blocks. This handles scenarios where the Managed Identity might lack access to a specific subscription returned by a higher-level scope or where a subscription contains no SQL servers. Log these non-fatal errors and continue to the next subscription/server.
5.3 Retrieving Firewall RulesFor each SQL server identified, the script must fetch its firewall rules.
Command: Use the Get-AzSqlServerFirewallRule cmdlet, providing the server name and resource group name obtained in the previous step.50
Properties: Extract the necessary properties from the returned rule objects: FirewallRuleName, StartIpAddress, and EndIpAddress,, [101], [100].
Special Rule Identification: Specifically check if a rule's name is AllowAllWindowsAzureIps and its IP addresses are 0.0.0.0. This rule corresponds to the "Allow Azure services and resources to access this server" setting in the portal and often requires special attention during audits [102], [50], [51],, [51], [52], [52], [53], [103], [104],. Store this identification as a boolean flag (e.g., $isAllowAzureRule) for inclusion in the table entity.
5.4 Connecting to Azure Table Storage via Managed IdentityWriting data to Azure Table Storage using the Function App's Managed Identity requires careful consideration, as the standard PowerShell module for Table Storage (AzTable) presents challenges with this authentication method.

The AzTable Limitation: The AzTable module primarily relies on Storage Account Keys (Shared Key authorization) for data plane operations like adding or updating rows (Add-AzTableRow, Update-AzTableRow).26 It does not natively integrate with the Connect-AzAccount -Identity context for authenticating these data operations.54 Attempting to use AzTable cmdlets with a context created via -UseConnectedAccount after Connect-AzAccount -Identity often fails because the underlying mechanism may still attempt to retrieve account keys, which the Managed Identity typically doesn't have permission for.56


Workaround 1 (Recommended): Using.NET SDK from PowerShell: The most robust and recommended approach is to leverage the Azure SDK for.NET directly within the PowerShell script. Specifically, use the Azure.Data.Tables library.

Availability: Ensure the necessary.NET assemblies for Azure.Data.Tables and Azure.Identity are accessible within the Azure Functions PowerShell environment. This might involve adjusting dependency management or relying on the assemblies included in the Functions runtime.
Authentication: Instantiate the Azure.Identity.DefaultAzureCredential class. This class automatically detects and uses the available Managed Identity in the Azure Functions environment.21
Client Creation: Create an instance of Azure.Data.Tables.TableServiceClient, passing the Table Storage endpoint URL and the DefaultAzureCredential object.57
Table Client: Get a TableClient object for the target table (e.g., SqlFirewallAudit) using TableServiceClient.GetTableClient("SqlFirewallAudit").
Operations: Use methods on the TableClient object, such as AddEntityAsync, UpdateEntityAsync, or preferably UpsertEntityAsync, to interact with the table data.57



Workaround 2 (Alternative): Using REST API with Managed Identity Token: A more complex alternative involves manually interacting with the Table Storage REST API.

Get Token: Use Get-AzAccessToken -ResourceUrl "https://storage.azure.com/" within the script (after Connect-AzAccount -Identity) to obtain an OAuth 2.0 bearer token for the Managed Identity, scoped to Azure Storage.47
Construct Request: Manually build HTTP requests (using Invoke-RestMethod or Invoke-WebRequest) targeting the appropriate Table Storage REST API endpoints for inserting or updating entities.35
Authorization Header: Include the obtained bearer token in the Authorization header of each request: Authorization: Bearer <token>.46
Complexity: This method requires handling HTTP request formatting, headers (including Content-Type, Accept, date headers), request body serialization (JSON), and response parsing, making it significantly more complex than using the SDK.35



Workaround 3 (Less Secure - Avoid): Using Storage Account Key: While AzTable works seamlessly with storage account keys (New-AzStorageContext -StorageAccountName... -StorageAccountKey... 34), using this method negates the security benefits of Managed Identity for accessing the storage account. It requires retrieving the storage key securely (e.g., from Azure Key Vault, which itself would ideally be accessed via Managed Identity) and managing its rotation, adding complexity and potential security risks. This approach is strongly discouraged unless the other methods are unfeasible.

The gap in native Managed Identity support within the AzTable module necessitates these workarounds. While PowerShell is the chosen language for the Function, interacting with Table Storage requires either dropping down to the underlying.NET SDK or constructing manual REST calls to maintain a fully credential-less solution using the Managed Identity.5.5 Constructing and Writing/Updating Table EntitiesOnce connectivity to Table Storage is established (preferably via the.NET SDK), the script needs to format the firewall rule data and perform write operations.

Data Mapping: Within the loop iterating through the firewall rules retrieved for a server, construct a data object representing a single entity for the SqlFirewallAudit table. If using the.NET SDK, this would be an object of type Azure.Data.Tables.TableEntity.57 If using AzTable (with keys) or REST, a PowerShell hash table is suitable.34 Map the collected data (SubscriptionID, SubscriptionName, ResourceGroupName, ServerName, FirewallRuleName, StartIpAddress, EndIpAddress, $isAllowAzureRule) to the corresponding property names defined in the table schema (Section 4.3). Set IsRuleEnabled to $true for rules found in the current scan and add the current AuditTimestamp. Remember to set the PartitionKey (e.g., $SubscriptionID) and RowKey (e.g., "$($ServerName)_$($Rule.FirewallRuleName)").


Upsert Logic: The goal is to maintain an up-to-date record for each rule. An "upsert" (update or insert) operation is ideal. For each rule found during the scan:

If an entity with the same PartitionKey and RowKey already exists in the table, update its AuditTimestamp, IsRuleEnabled flag, and potentially other properties if they can change.
If no such entity exists, insert a new one.



Implementing Upsert:

.NET SDK (Recommended): The Azure.Data.Tables.TableClient provides an UpsertEntityAsync method. This method efficiently handles the insert-or-replace logic in a single operation. Specify TableUpdateMode.Merge to only update provided properties or TableUpdateMode.Replace to overwrite the entire entity if it exists.59
PowerShell# Conceptual Example using.NET SDK (requires setup from 5.4)
# Assumes $tableClient is an initialized Azure.Data.Tables.TableClient

$entity =::new($SubscriptionID, $RowKey)
$entity.Add("SubscriptionName", $SubscriptionName)
$entity.Add("ResourceGroupName", $ResourceGroupName)
$entity.Add("ServerName", $ServerName)
$entity.Add("FirewallRuleName", $Rule.FirewallRuleName)
$entity.Add("StartIpAddress", $Rule.StartIpAddress)
$entity.Add("EndIpAddress", $Rule.EndIpAddress)
$entity.Add("IsAllowAllWindowsAzureIpsRule", $isAllowAzureRule)
$entity.Add("IsRuleEnabled", $true) # Mark as currently enabled/found
$entity.Add("AuditTimestamp", (Get-Date).ToUniversalTime())

try {
    # Use UpsertEntityAsync with Merge mode
    $upsertResponse = $tableClient.UpsertEntityAsync($entity,::Merge)
    $upsertResponse.Wait() # Wait for async operation to complete in sync PS script
    Write-Host "Successfully upserted rule '$($Rule.FirewallRuleName)' for server '$ServerName'"
} catch {
    Write-Error "Failed to upsert entity for rule '$($Rule.FirewallRuleName)' on server '$ServerName': $_"
}


AzTable Cmdlets (More Complex): Since Update-AzTableRow doesn't offer a direct upsert and modifies behavior based on key changes 64, you would need to first attempt to retrieve the entity (Get-AzTableRow with specific PartitionKey and RowKey). If it exists, update it using Update-AzTableRow; otherwise, insert it using Add-AzTableRow.63 This requires multiple calls per rule.
REST API (Most Complex): Use the PUT verb with the specific entity URI for an upsert operation, or implement a GET-then-POST/MERGE logic manually.60



Handling Deleted Rules (Stale Entries): To ensure the table reflects rules that have been deleted since the last audit, a mechanism to identify and mark stale entries is needed. A common approach involves:

Pre-fetch: Before processing the current rules for a specific server (PartitionKey + ServerName prefix in RowKey), query the SqlFirewallAudit table to retrieve all existing entities associated with that server. Store these, perhaps in a hash table keyed by RowKey.
Mark as Seen: As each current firewall rule is processed and upserted into the table, remove the corresponding entry from the pre-fetched list.
Identify Stale: After iterating through all current rules for the server, any entities remaining in the pre-fetched list represent rules that existed previously but are now deleted.
Update Stale: Loop through these remaining stale entities and update them in the table by setting the IsRuleEnabled property to $false and updating the AuditTimestamp. This requires an update operation (using the.NET SDK's UpdateEntityAsync or equivalent).


The native complexity of implementing reliable upserts and handling stale data using only AzTable cmdlets further reinforces the recommendation to use the.NET SDK via PowerShell, leveraging its UpsertEntityAsync method for simplicity and efficiency.6. Phase 5: Azure Function Configuration and DependenciesProper configuration of the Azure Function itself, including its trigger mechanism and PowerShell module dependencies, is crucial for reliable execution.6.1 Configuring the Function TriggerThe trigger defines how the Function App's run.ps1 script is initiated. The two primary options for this audit scenario are Timer and HTTP triggers.
Timer Trigger: This trigger executes the function based on a predefined schedule defined by a CRON expression.65 It is ideal for automated, periodic audits (e.g., daily at 4:00 AM UTC: "schedule": "0 0 4 * * *"). The configuration resides in the function.json file associated with the specific function within the Function App.4 The runOnStartup setting can optionally trigger the function when the runtime starts.66 A $Timer object containing schedule information is passed to the run.ps1 script.4
HTTP Trigger: This trigger executes the function in response to an incoming HTTP request.68 It's suitable for on-demand audits or integration with other systems. Configuration in function.json includes specifying allowed HTTP methods ("methods": ["get", "post"]) and the authorization level ("authLevel": "function", "admin", or "anonymous") to control access.69 An $Request object containing HTTP request details is passed to run.ps1.4
Recommendation: For the purpose of regular, automated firewall auditing, the Timer trigger is generally the more appropriate choice. It ensures consistent execution without requiring external invocation and simplifies security, as the function runs entirely within the Azure environment based on its schedule.Table: Trigger Comparison for Audit Function
FeatureTimer TriggerHTTP TriggerRecommendation for AuditInvocationSchedule (CRON expression) 65HTTP Request (GET/POST) 68Timer (for automation)Use CaseScheduled tasks (e.g., daily audit)On-demand execution, API integrationScheduled AuditConfigurationfunction.json (schedule) 66function.json (methods, authLevel) 69Simple CRON in function.jsonInput Object$Timer 4$Request 4$Timer objectSecurityRuns automatically within AzureRequires auth (API key, AAD)Timer (simpler security)Manual RunPossible via Portal/API for testingDirect HTTP callTest via Portal/API
6.2 Managing PowerShell Module Dependencies (requirements.psd1)Azure Functions for PowerShell uses a requirements.psd1 file at the root of the Function App to manage dependencies on modules from the PowerShell Gallery.4 When the managedDependency feature is enabled in host.json, the Functions host automatically downloads and manages these declared modules.72
Required Modules: For this audit script, the following Az PowerShell modules are necessary:

Az.Accounts: For Connect-AzAccount -Identity.76
Az.Sql: For Get-AzSqlServer and Get-AzSqlServerFirewallRule.78
Az.Resources: Potentially needed for Get-AzSubscription if iterating across subscriptions not defined explicitly.76


AzTable Consideration: If using the recommended.NET SDK workaround (Workaround 1 in Section 5.4) for Table Storage interaction, do not include AzTable in requirements.psd1. The necessary SDK components should be handled separately or be part of the runtime. If opting for the less secure Workaround 3 (using AzTable with storage keys), then 'AzTable' = '2.*' (or a specific version) would need to be listed.4
Syntax: Specify modules using a hash table format. Using major version wildcards ('Az.Accounts' = '2.*') allows automatic updates within that major version, while specific versions ('Az.Sql' = '4.7.0') provide greater stability.72
PowerShell# Example requirements.psd1 (assuming.NET SDK for Table Storage)
@{
    # Using major version wildcards for Az modules
    'Az.Accounts' = '2.*'
    'Az.Sql' = '4.*'
    'Az.Resources' = '6.*' # Only if Get-AzSubscription or similar is used
}


Performance: Listing only the required Az sub-modules (Az.Accounts, Az.Sql, Az.Resources) is strongly recommended over importing the entire Az module ('Az' = '11.*'). The full Az module is large, and downloading/loading it significantly increases the function's cold start time (the delay during the first execution after a period of inactivity).72 Importing only essential modules minimizes this overhead.
Enabling Managed Dependencies: Ensure the host.json file at the root of the Function App contains "managedDependency": { "enabled": true } to activate this feature.72
Manual Module Upload: As an alternative, modules can be manually uploaded to a Modules folder within the Function App's wwwroot directory (D:\home\site\wwwroot\Modules via Kudu tools). This bypasses the managed dependency feature but requires manual updates.74 This is generally less desirable than using managed dependencies.
7. Phase 6: DeploymentDeploying the PowerShell function involves packaging the script (run.ps1), configuration files (function.json, host.json), and the dependency manifest (requirements.psd1) and transferring them to the Azure Function App resource.7.1 PackagingThe standard deployment mechanism for Azure Functions involves creating a deployment package, typically a.zip file, containing the function's code and configuration files structured correctly. The root of the zip file should correspond to the wwwroot directory of the Function App.7.2 Deployment MethodsSeveral methods are available to deploy the packaged function:
Azure Functions Core Tools: The func azure functionapp publish <FunctionAppName> command, run from the local project directory, packages and deploys the function using zip deployment.81 This is suitable for command-line workflows and scripting.
Visual Studio Code Extension: The Azure Functions extension for VS Code provides a user-friendly interface to deploy the current workspace to a selected Function App in Azure.85 This is often the most convenient method during development and testing.
Zip Deployment (Azure CLI/Portal): A.zip file containing the function files can be created manually or via a build process. This zip file can then be deployed using the Azure CLI command az functionapp deployment source config-zip 82 or through the deployment options in the Azure portal. Ensure the WEBSITE_RUN_FROM_PACKAGE application setting is configured appropriately if using zip deploy directly.90
CI/CD Pipelines (Azure DevOps/GitHub Actions): For automated build and release processes, dedicated tasks (like AzureFunctionApp@2 for Azure Pipelines 78) or actions can be used to build, package, and deploy the function app as part of a larger workflow.
Recommendation: For iterative development, the VS Code extension offers a streamlined experience. For automated deployments or integration into broader DevOps practices, Azure CLI commands (like func azure functionapp publish or az functionapp deployment source config-zip) or CI/CD pipelines are preferred.8. Phase 7: Execution and Operational ConsiderationsOnce deployed, the Function App will execute according to its trigger. Several operational factors must be considered for reliable and efficient auditing.8.1 Execution Flow and Monitoring
Execution: The function execution begins when the trigger fires (either on schedule for a Timer trigger or via an HTTP request for an HTTP trigger). The PowerShell runtime loads, processes dependencies from requirements.psd1 (if managed dependencies are enabled), executes the profile.ps1 (if present), and finally runs the run.ps1 script.4
Monitoring: Application Insights, typically configured during Function App creation 3, is the primary tool for monitoring. It captures execution logs (including output from Write-Host, Write-Warning, Write-Error), performance metrics (duration, memory usage), dependency calls, and exceptions.91 Logs can also be viewed in near real-time via the Function App's "Monitor" section in the Azure portal or through Live Metrics Stream in Application Insights. Effective monitoring is crucial for diagnosing failures and understanding performance.
8.2 Implementing Error Handling (try/catch)Robust error handling is essential for ensuring the audit function completes as much work as possible even when encountering issues, and for providing clear diagnostic information.
Necessity: The script interacts with multiple Azure services (Resource Manager for subscriptions/servers/rules, Table Storage for output). Network issues, transient failures, permission errors, or unexpected API responses can occur.91
Technique: Employ try/catch blocks around critical sections of the script, such as connecting to Azure (Connect-AzAccount), retrieving resources (Get-AzSubscription, Get-AzSqlServer, Get-AzSqlServerFirewallRule), and interacting with Table Storage.48
Error Details: Within the catch block, use the automatic variable $_ to access details about the error that occurred. Log this information using Write-Error for visibility in Application Insights.49
Terminating vs. Non-Terminating Errors: By default, many PowerShell cmdlets generate non-terminating errors, which do not trigger catch blocks. To ensure errors are caught, either set $ErrorActionPreference = "Stop" at the beginning of the script or use the -ErrorAction Stop common parameter on individual cmdlet calls.49 This converts non-terminating errors into terminating errors (exceptions) that the try/catch mechanism can handle.
PowerShell# Example: Error handling around Get-AzSqlServer
try {
    $servers = Get-AzSqlServer -ResourceGroupName $rgName -ErrorAction Stop
    #... process servers...
} catch {
    Write-Error "Error retrieving SQL servers in RG '$rgName', Subscription '$($sub.Id)': $_"
    # Decide whether to continue to the next resource group/subscription or stop
    continue # Example: Skip this RG and continue
}
8.3 Logging StrategiesEffective logging provides visibility into the function's execution path and helps diagnose problems.
Built-in Cmdlets: Utilize standard PowerShell output streams:

Write-Host: For general informational messages (captured as 'Information' level traces).4
Write-Warning: For potential issues or non-critical problems.
Write-Output: To return data (less common for background tasks like this).
Write-Error: To log errors, especially within catch blocks.48


Best Practices:

Log the start and end of the function execution, including timestamps.
Log the current subscription and server being processed within loops.
Log the number of rules found and processed for each server.
Log any errors encountered, including details from the $_ variable in catch blocks.
Avoid logging sensitive information like connection strings or full API keys (though Managed Identity avoids these).
Consider prefixing log messages (e.g., [INFO], ,) for easier filtering in Application Insights.


8.4 Managing Execution TimeoutsThe maximum time a function can run before being terminated depends on its hosting plan. This is a critical constraint for potentially long-running audit scripts.
Plan Limits:

Consumption Plan: Default timeout is 5 minutes, maximum configurable timeout is 10 minutes.93
Flex Consumption Plan: No host-enforced limit, but instances can still be terminated for platform reasons.95
Premium Plan: Default 30 minutes, maximum configurable (effectively unlimited, though subject to platform events).94
Dedicated (App Service) Plan: Default 30 minutes, maximum configurable to unlimited (-1).94


HTTP Trigger Limit: Regardless of the plan's function timeout, HTTP-triggered functions have an additional limit of 230 seconds (3 minutes 50 seconds) imposed by the Azure Load Balancer's idle timeout.93 Timer triggers are not subject to this specific limit.
Audit Scope Impact: Auditing a large number of subscriptions and servers sequentially within a single function execution could easily exceed the 10-minute limit of the Consumption plan. The function would be terminated mid-audit, leaving the results incomplete.
Mitigation Strategies:

Optimization: Ensure the PowerShell script is as efficient as possible (e.g., minimize unnecessary API calls).
Batching/Parallelism: Modify the function design. Instead of one function auditing everything, trigger multiple instances. For example, have a master function get the list of subscriptions and place each subscription ID onto a queue. A second queue-triggered function then audits only one subscription per execution.
Durable Functions: For complex, long-running, stateful processes, Azure Durable Functions provide an orchestration framework built on Azure Functions.92 The audit could be modeled as an orchestrator function that calls activity functions to audit individual subscriptions or servers. Durable Functions manage state and checkpoints, making them resilient to timeouts and infrastructure issues.92 This is a more advanced pattern but suitable for large-scale, reliable auditing.
Upgrade Hosting Plan: If the audit inherently takes longer than 10 minutes and architectural changes are undesirable, upgrade the Function App to a Premium or Dedicated plan to leverage longer execution timeouts.93 This incurs higher baseline costs.


Table: Azure Functions Timeout Limits by Plan
Hosting PlanDefault TimeoutMaximum TimeoutHTTP Trigger TimeoutNotesConsumption5 minutes 9410 minutes 93230 seconds 93Cost-effective, pay-per-execution.Flex ConsumptionNo host limitNo host limit230 seconds (?)Newer plan, instances can still terminate.95Premium30 minutes 94Configurable (effectively unlimited) 94230 seconds 93No cold starts, VNet integration.Dedicated (App Svc)30 minutes 94Unlimited (-1) 94230 seconds 93Runs on existing App Service Plan resources.
The potential mismatch between the desire to audit many resources and the strict timeout of the cost-effective Consumption plan necessitates careful design. The timeout constraint often drives architectural decisions towards breaking down the workload or selecting a higher-tier hosting plan.8.5 Cost ConsiderationsWhile serverless functions can be cost-effective, understanding the billing model is important.
Function Execution (Consumption Plan): Billing is based on two primary metrics:

Total Executions: A charge per million executions (first million free per month per subscription).5
Execution Time (GB-seconds): Calculated by multiplying average memory consumption (rounded up to the nearest 128MB) by execution duration in seconds (first 400,000 GB-s free per month per subscription).5 Longer-running, memory-intensive functions cost more.


Function Execution (Premium Plan): Billing is based on vCPU-seconds and GB-seconds of provisioned instance time, regardless of execution count. There's a cost for keeping instances warm.5
Storage Transactions: Every read and write (including upsert) operation against Azure Table Storage counts as a transaction and incurs a small cost 5 (Implied).99 Auditing thousands of rules frequently will generate a corresponding number of transactions.
Application Insights: Data ingestion and retention in Application Insights can incur costs, depending on the volume of logs and telemetry generated.
8.6 Security Best PracticesMaintaining a strong security posture extends to the Function App itself.
Managed Identity: The use of Managed Identity is the cornerstone of security for this solution, eliminating embedded credentials.1
Least Privilege: Consistently apply the principle of least privilege when assigning RBAC roles to the Managed Identity. Grant only the necessary permissions ('Reader' for discovery, 'Storage Table Data Contributor' for output) at the narrowest required scope (Management Group/Subscription for Reader, Storage Account for Contributor).8 Regularly audit these role assignments.
Input Validation: If using an HTTP trigger, rigorously validate any input parameters received in the request payload or query string to prevent injection or unexpected behavior.
Secure Configuration: Store non-secret configuration values (like the target storage account name or table name) in Application Settings rather than hardcoding them in the script.
Network Security (Optional): For environments requiring stricter network controls, consider using Azure Private Endpoints for the Storage Account and enabling VNet integration for the Function App (requires Premium or Dedicated plan 95). This ensures traffic between the function and storage stays off the public internet but adds configuration complexity.
9. ConclusionAutomating the audit of Azure SQL Server firewall rules using Azure Functions, Managed Identity, and Azure Table Storage offers a secure, scalable, and efficient alternative to manual checks. By leveraging the PowerShell runtime within Azure Functions, existing scripting investments can be utilized. Managed Identity provides a robust, credential-less authentication mechanism, significantly enhancing the security posture.1 Storing the results in Azure Table Storage creates a centralized, queryable repository for compliance reporting and analysis.22Key considerations during implementation include selecting the appropriate trigger (Timer for scheduled audits, HTTP for on-demand), managing PowerShell module dependencies correctly via requirements.psd1 4, handling the AzTable module's limitations regarding Managed Identity by using the.NET SDK or REST API for Table Storage interaction 54, and addressing potential execution timeouts inherent in the Consumption plan, possibly requiring architectural adjustments like batching, Durable Functions, or plan upgrades for large environments.93 Implementing robust error handling and logging is crucial for operational reliability.48This solution provides a foundation for continuous compliance monitoring of Azure SQL firewall rules. Potential enhancements could include integrating the audit data with security information and event management (SIEM) systems like Microsoft Sentinel, creating automated alerts based on non-compliant rules found in the table, developing visualization dashboards (e.g., in Power BI) using the Table Storage data, or extending the script to audit additional SQL security configurations.