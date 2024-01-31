[CmdletBinding()]
param (
    #[Parameter (Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [String] $TenantFolder
)

# To run the script locally comment out the section belows
# $DefaultWorkingDirectory = "C:\Git\ManagedCyberSecurity"
# $TenantFolder = "$DefaultWorkingDirectory\Tenants\"
# ######################

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest


if (-not (Test-Path $TenantFolder)) {
    throw "Template file does not exist at the location: $TenantFolder"
}

# Connect-AzAccount
$allContexts = Get-AzContext -ListAvailable
$AllTenants = @()
foreach ($context in $allContexts) {
    $AllTenants += $context.Tenant.Id
}

$context = Get-AzContext
$profileClient = [Microsoft.Azure.Commands.ResourceManager.Common.RMProfileClient]::new([Microsoft.Azure.Commands.Common.Authentication.Abstractions.AzureRmProfileProvider]::Instance.Profile)
$token = $profileClient.AcquireAccessToken($context.Subscription.TenantId)
$jwtPayload = $token.AccessToken.Split('.')[1]
$jwtPayload = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($jwtPayload))
$jwtPayloadObj = ConvertFrom-Json $jwtPayload
$issuedAtUnix = $jwtPayloadObj.iat
$issuedAtDateTime = [DateTimeOffset]::FromUnixTimeSeconds($issuedAtUnix).UtcDateTime
$issuedAtISO8601 = $issuedAtDateTime.ToString("o")

Write-Host "Bearer token issued at $($issuedAtISO8601)"
Write-Host "Processing configuration files in '$($TenantFolder)'"

$headers = @{
    "Authorization" = "Bearer $($token.AccessToken)"
    "Content-Type"  = "application/json"
}

$Configurations = Get-ChildItem -Path $TenantFolder -Filter "*.config.json" -Recurse -File -Depth 1

foreach ($Configuration in $Configurations) {
    Write-Host "Processing configuration file $($Configuration)"
    $Config = Get-Content $Configuration.FullName | ConvertFrom-Json
    if ($AllTenants -contains $Config.TenantId) {
        Write-Output "TenantId $($Config.TenantId) is in the Service Connection"
        foreach ($Connection in $Config.Connections){
            $newinstance = $false
            # Validate access to subscription
            $subscriptionUrl = "https://management.azure.com/subscriptions/$($Connection.SubscriptionId)?api-version=2022-12-01"
            try {
                $response = Invoke-RestMethod -Uri $subscriptionUrl -Headers $headers
                Write-Host "Successfully accessed subscription with ID $($Connection.SubscriptionId)"
            } catch {
                $statusCode = $_.Exception.Response.StatusCode.Value__
                $statusDescription = $_.Exception.Response.StatusDescription
                throw "Failed to get subscription with ID $($Connection.SubscriptionId). Status code: $statusCode. Status description: $statusDescription"
            }
            # Validate access to resource group
            $resourceGroupUrl = "https://management.azure.com/subscriptions/$($Connection.SubscriptionId)/resourcegroups/$($Connection.ResourceGroup)?api-version=2022-12-01"
            try {
                $response = Invoke-RestMethod -Uri $resourceGroupUrl -Headers $headers
                Write-Host "Successfully accessed resource group $($Connection.ResourceGroup) in subscription $($Connection.SubscriptionId)"
            } catch {
                if ($_.Exception.Response.StatusCode.Value__ -eq 404) {
                    Write-Host "Resource group $($Connection.ResourceGroup) does not exist in subscription $($Connection.SubscriptionId). Attempting to create..."
                    $resourceGroupBody = @{
                        "location" = $Connection.Location
                    } | ConvertTo-Json
                    $createResourceGroupUrl = "https://management.azure.com/subscriptions/$($Connection.SubscriptionId)/resourcegroups/$($Connection.ResourceGroup)?api-version=2022-12-01"
                    $response = Invoke-RestMethod -Method Put -Uri $createResourceGroupUrl -Headers $headers -Body $resourceGroupBody -ContentType "application/json"
                    Write-Host "Successfully created resource group $($Connection.ResourceGroup) in subscription $($Connection.SubscriptionId)"
                } else {
                    $statusCode = $_.Exception.Response.StatusCode.Value__
                    $statusDescription = $_.Exception.Response.StatusDescription
                    throw "Failed to get resource group $($Connection.ResourceGroup) in subscription $($Connection.SubscriptionId). Status code: $statusCode. Status description: $statusDescription"
                }
            }   
            # Validate Log Analytics Workspace
            $workspaceApiUrl = "https://management.azure.com/subscriptions/$($Connection.SubscriptionId)/resourcegroups/$($Connection.ResourceGroup)/providers/Microsoft.OperationalInsights/workspaces/$($Connection.LogAnalyticsWorkspace)?api-version=2020-03-01-preview"
            try {
                $workspaceResponse = Invoke-RestMethod -Method Get -Uri $workspaceApiUrl -Headers $headers
                Write-Host "Successfully accessed Log Analytics Workspace $($Connection.LogAnalyticsWorkspace) in resource group $($Connection.ResourceGroup) and subscription $($Connection.SubscriptionId)"
            } catch {
                if ($_.Exception.Response.StatusCode.Value__ -eq 404) {
                    Write-Host "Log Analytics Workspace $($Connection.LogAnalyticsWorkspace) does not exist in resource group $($Connection.ResourceGroup) and subscription $($Connection.SubscriptionId). Attempting to create..."
                    $workspaceBody = @{
                        "location" = $Connection.Location
                        "properties" = @{
                            "sku" = @{
                                "name" = $Connection.SKU
                            }
                            "retentionInDays" = $Connection.Retention
                        }
                    } | ConvertTo-Json
                    $workspaceResponse = Invoke-RestMethod -Method Put -Uri $workspaceApiUrl -Headers $headers -Body $workspaceBody
                    if ($workspaceResponse.properties.provisioningState -eq 'Succeeded') {
                        Write-Host "Successfully created Log Analytics Workspace $($Connection.LogAnalyticsWorkspace) in resource group $($Connection.ResourceGroup) and subscription $($Connection.SubscriptionId)"
                    } else {
                        Write-Output "Failed to create Log Analytics Workspace $($Connection.LogAnalyticsWorkspace). Provisioning state: $($workspaceResponse.properties.provisioningState)"
                    }
                } else {
                    $statusCode = $_.Exception.Response.StatusCode.Value__
                    $statusDescription = $_.Exception.Response.StatusDescription
                    throw "Failed to get Log Analytics Workspace $($Connection.LogAnalyticsWorkspace) in resource group $($Connection.ResourceGroup) and subscription $($Connection.SubscriptionId). Status code: $statusCode. Status description: $statusDescription"
                }
            }
            # Validate Microsoft Sentinel
            $sentinelApiUrl = "https://management.azure.com/subscriptions/$($Connection.SubscriptionId)/resourceGroups/$($Connection.ResourceGroup)/providers/Microsoft.OperationsManagement/solutions/SecurityInsights($($Connection.LogAnalyticsWorkspace))?api-version=2015-11-01-preview"
            try {
                # Try to get the Azure Sentinel solution
                $sentinelResponse = Invoke-WebRequest -Method Get -Uri $sentinelApiUrl -Headers $headers
                Write-Output "Azure Sentinel is already enabled on $($Connection.LogAnalyticsWorkspace)."
            } catch {
                if ($_.Exception.Response.StatusCode -eq 'NotFound') {
                    # Enable Azure Sentinel
                    $sentinelBody = @{
                        "location" = $Connection.Location
                        "properties" = @{
                            "workspaceResourceId" = "/subscriptions/$($Connection.SubscriptionId)/resourcegroups/$($Connection.ResourceGroup)/providers/microsoft.operationalinsights/workspaces/$($Connection.LogAnalyticsWorkspace)"
                        }
                        "plan" = @{
                            "name" = "SecurityInsights($($Connection.LogAnalyticsWorkspace))"
                            "publisher" = "Microsoft"
                            "product" = "OMSGallery/SecurityInsights"
                            "promotionCode" = ""
                        }
                    } | ConvertTo-Json
                    $sentinelDeploymentResponse = Invoke-WebRequest -Method Put -Uri $sentinelApiUrl -Headers $headers -Body $sentinelBody
                    if ($sentinelDeploymentResponse.StatusCode -eq 200 -or $sentinelDeploymentResponse.StatusCode -eq 201) {
                        $newinstance = $true
                        Write-Output "Azure Sentinel enabled successfully on $($Connection.LogAnalyticsWorkspace)."
                    } else {
                        Write-Output "Failed to enable Azure Sentinel on $($Connection.LogAnalyticsWorkspace). Response: $($sentinelDeploymentResponse.Content)"
                    }
                }
            }
            # Validate installed solutions
            $installedSolutionsApiUrl = "https://management.azure.com/subscriptions/$($Connection.SubscriptionId)/resourceGroups/$($Connection.ResourceGroup)/providers/Microsoft.OperationalInsights/workspaces/$($Connection.LogAnalyticsWorkspace)/providers/Microsoft.SecurityInsights/contentPackages?api-version=2023-10-01-preview"
            # Try to get the Azure Sentinel solution
            $installedSolutionsResponse = Invoke-WebRequest -Method Get -Uri $installedSolutionsApiUrl -Headers $headers
            $installedSolutions = $installedSolutionsResponse.Content | ConvertFrom-Json
            # If $installedSolutions.value is $null or not an array, set it to an empty array
            if ($null -eq $installedSolutions.value) {
                foreach ($solution in $Connection.Solutions) {
                    $installSolutionApiUrl = "https://management.azure.com/subscriptions/$($Connection.SubscriptionId)/resourceGroups/$($Connection.ResourceGroup)/providers/Microsoft.OperationalInsights/workspaces/$($Connection.LogAnalyticsWorkspace)/providers/Microsoft.SecurityInsights/contentPackages/$($solution.contentId)?api-version=2023-10-01-preview"
                    Write-Output "Solution $($solution.contentId) is not installed. Installing..."
                    $body = @{
                        properties = @{
                            contentId = $($solution.contentId)
                            contentProductId = $($solution.contentProductId)
                            contentKind = $($solution.contentKind)
                            version = $($solution.version)
                            displayName = $($solution.displayName)
                        }
                    } | ConvertTo-Json
                    $installSolutionsResponse = Invoke-WebRequest -Method Put -Uri $installSolutionApiUrl -Headers $headers -Body $body
                    Write-Output "Solution $($solution.contentId) installed successfullyWith status code $($installSolutionsResponse.StatusCode)"
                }
            }
            else {
                $filteredSolutions = $installedSolutions.value | Where-Object { $_.properties.PSObject.Properties.Name -contains 'displayName' -and $_.properties.displayName }
                foreach ($solution in $Connection.Solutions) {
                    # Check if there's a solution in $filteredSolutions where both contentProductId and contentId match the current solution
                    $matchingSolution = $filteredSolutions | Where-Object { $_.properties.contentProductId -eq $solution.contentProductId -and $_.properties.contentId -eq $solution.contentId }

                    if ($null -ne $matchingSolution) {
                        Write-Output "Solution with contentProductId $($solution.contentProductId) and contentId $($solution.contentId) is installed"
                    } else {
                        $installSolutionApiUrl = "https://management.azure.com/subscriptions/$($Connection.SubscriptionId)/resourceGroups/$($Connection.ResourceGroup)/providers/Microsoft.OperationalInsights/workspaces/$($Connection.LogAnalyticsWorkspace)/providers/Microsoft.SecurityInsights/contentPackages/$($solution.contentId)?api-version=2023-10-01-preview"
                        Write-Output "Solution $($solution.contentProductId) is not installed. Installing..."
                        $body = @{
                            properties = @{
                                contentId = $($solution.contentId)
                                contentProductId = $($solution.contentProductId)
                                contentKind = $($solution.contentKind)
                                version = $($solution.version)
                                displayName = $($solution.displayName)
                            }
                        } | ConvertTo-Json
                        $installSolutionsResponse = Invoke-WebRequest -Method Put -Uri $installSolutionApiUrl -Headers $headers -Body $body
                    }
                }
            }
       } 
    } else {
        throw "Error: TenantId $($Config.TenantId) is not available within the Service Connection"
    }
}