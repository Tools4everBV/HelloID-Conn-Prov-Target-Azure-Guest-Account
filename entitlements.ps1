# AzureAD Application Parameters #
$AADtenantID = "<Provide your Tenant ID here>"
$AADAppId = "<Provide your Client ID here>"
$AADAppSecret = "<Provide your Client Secret here>"

# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

try{
    Write-Verbose -Verbose "Generating Microsoft Graph API Access Token user.."
    $baseUri = "https://login.microsoftonline.com/"
    $authUri = $baseUri + "$AADTenantID/oauth2/token"

    $body = @{
        grant_type      = "client_credentials"
        client_id       = "$AADAppId"
        client_secret   = "$AADAppSecret"
        resource        = "https://graph.microsoft.com"
    }

    $Response = Invoke-RestMethod -Method POST -Uri $authUri -Body $body -ContentType 'application/x-www-form-urlencoded'
    $accessToken = $Response.access_token;

    #Add the authorization header to the request
    $authorization = @{
        Authorization = "Bearer $accesstoken";
        'Content-Type' = "application/json";
        Accept = "application/json";
    }

    Write-Verbose -Verbose "Searching for AzureAD groups.."

    #Add the authorization header to the request
    $authorization = @{
        Authorization = "Bearer $accesstoken";
        'Content-Type' = "application/json";
        Accept = "application/json";
    }
 
    $baseSearchUri = "https://graph.microsoft.com/"
    $searchUri = $baseSearchUri + 'v1.0/groups?$orderby=displayName'

    $azureADGroupsResponse = Invoke-RestMethod -Uri $searchUri -Method Get -Headers $authorization -Verbose:$false
    [System.Collections.ArrayList]$azureADGroups = $azureADGroupsResponse.value
    while (![string]::IsNullOrEmpty($azureADGroupsResponse.'@odata.nextLink')) {
        $azureADGroupsResponse = Invoke-RestMethod -Uri $azureADGroupsResponse.'@odata.nextLink' -Method Get -Headers $authorization -Verbose:$false
        $null = $azureADGroups.Add($azureADGroupsResponse.value)
    }    
    Write-Verbose -Verbose "Finished searching for AzureAD Groups. Found [$($azureADGroups.id.Count) groups]"    
    
    #Filter for only Cloud groups, since synced groups can only be managed by the Sync
    Write-Verbose -Verbose "Filtering for only Cloud groups.."
    $azureADGroups = foreach($azureADGroup in $azureADGroups){
        if($azureADGroup.onPremisesSyncEnabled -eq $null){
            $azureADGroup
        }
    }
    Write-Verbose -Verbose "Successfully filtered for only Cloud groups. Filtered down to [$($azureADGroups.id.Count) groups]"
}catch{
    throw "Could not gather Azure AD groups, errorcode: 0x$('{0:X8}' -f $_.Exception.HResult), message: $($_.Exception.Message)"
}

$permissions = @(foreach($azureADGroup in $azureADGroups){
    @{
        DisplayName = $azureADGroup.displayName;
        Identification = @{
            Id = $azureADGroup.id;
        }
    }
})

write-output $permissions | ConvertTo-Json -Depth 10;