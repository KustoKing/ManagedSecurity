# Tenant Configration

Each tenant must have a Tenant configration file. The file contains a JSON object, which contains the TenantId and an array of connection settings. These settings are required to validate and deploy the Microsoft Sentinel Environment.

{
    "TenantId": "",
    "Connections": [
        {
            "SubscriptionId": "",
            "ResourceGroup": "",
            "LogAnalyticsWorkspace": "",
            "SKU": "",
            "Retention": ,
            "Location": "",
            "Solutions": [
                {
                    
                }
            ] 
        }
    ]
}
