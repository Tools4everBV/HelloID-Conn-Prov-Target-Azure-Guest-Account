# AzureAD Application Parameters #
$config = ConvertFrom-Json $configuration

$AADtenantDomain = $config.AADtenantDomain
$AADtenantID = $config.AADtenantID
$AADAppId = $config.AADAppId
$AADAppSecret = $config.AADAppSecret

# Enable TLS 1.2
if ([Net.ServicePointManager]::SecurityProtocol -notmatch "Tls12") {
    [Net.ServicePointManager]::SecurityProtocol += [Net.SecurityProtocolType]::Tls12
}

#Initialize default properties
$success = $False;
$p = $person | ConvertFrom-Json;
$m = $manager | ConvertFrom-Json;
$auditMessage = "Guest account invitation for person " + $p.DisplayName + " not created successfully";

#Change mapping here
$account = [PSCustomObject]@{
    invitedUserDisplayName = $p.Accounts.MicrosoftActiveDirectory.displayName;
    invitedUserEmailAddress = $p.Accounts.MicrosoftActiveDirectory.userPrincipalName;
    sendInvitationMessage = $true;
    inviteRedirectUrl = "https://portal.azure.com/";
}

try {
    if (-Not($dryRun -eq $True)) {
        Write-Verbose -Verbose "Generating Microsoft Graph API Access Token user.."
        $baseUri = "https://login.microsoftonline.com/"
        $authUri = $baseUri + "$AADTenantID/oauth2/token"

        $body = @{
            grant_type    = "client_credentials"
            client_id     = "$AADAppId"
            client_secret = "$AADAppSecret"
            resource      = "https://graph.microsoft.com"
        }

        $Response = Invoke-RestMethod -Method Post -Uri $authUri -Body $body -ContentType 'application/x-www-form-urlencoded'
        $accessToken = $Response.access_token;

        #Add the authorization header to the request
        $authorization = @{
            Authorization  = "Bearer $accesstoken";
            'Content-Type' = "application/json";
            Accept         = "application/json";
        }

        $userExists = $false
        try{
            $userPrincipalName = $account.invitedUserEmailAddress.replace("@","_") + "#EXT#@$AADtenantDomain"
            $userPrincipalName = [System.Web.HttpUtility]::UrlEncode($userPrincipalName)
            Write-Verbose -Verbose "Searching for AzureAD user with userPrincipalName '$($userPrincipalName)'.."

            $baseSearchUri = "https://graph.microsoft.com/"
            $properties = @("id","displayName","userPrincipalName")        
            $searchUri = $baseSearchUri + "v1.0/users/$userPrincipalName" + '?$select=' + ($properties -join ",")
            $azureADUser = Invoke-RestMethod -Uri $searchUri -Method Get -Headers $authorization -Verbose:$false
            Write-Verbose -Verbose "Found AzureAD user [$($azureADUser.userPrincipalName)]"
            $userExists = $true
        }catch{
            Write-Verbose -Verbose "Could not find AzureAD user [$($account.invitedUserEmailAddress)]"
            $userExists = $false             
        }

        if($userExists -eq $false){
            Write-Verbose -Verbose "Inviting AzureAD user [$($account.invitedUserEmailAddress)] for domain $AADtenantDomain.."
            $baseCreateUri = "https://graph.microsoft.com/"
            $createUri = $baseCreateUri + "/v1.0/invitations"
            $body = $account | ConvertTo-Json -Depth 10

            $response = Invoke-RestMethod -Uri $createUri -Method POST -Headers $authorization -Body $body -Verbose:$false
            $aRef = $response.invitedUser.id

            $success = $True;
            $auditMessage = " invitation $($account.invitedUserEmailAddress) successfully";         
        }else{
            Write-Verbose -Verbose "AzureAD user [$($azureADUser.userPrincipalName)] already exists as a Guest in domain $AADtenantDomain"

            $aRef = $azureADUser.id

            $success = $True; 
            $auditMessage = " $($azureADUser.userPrincipalName) already exists for this person. Skipped action and treated like";       
        }
    }
}
catch {
    $errResponse = $_;
    $auditMessage = " invitation $($account.invitedUserEmailAddress) : ${errResponse}";
}

#build up result
$result = [PSCustomObject]@{
    Success          = $success;
    AccountReference = $aRef;
    AuditDetails     = $auditMessage;
    Account          = $account;

<#
    # Optionally return data for use in other systems
    ExportData       = [PSCustomObject]@{
        displayName = $account.displayName;
        userPrincipalName = $account.userPrincipalName;
    };
#>
};
    
Write-Output $result | ConvertTo-Json -Depth 10;