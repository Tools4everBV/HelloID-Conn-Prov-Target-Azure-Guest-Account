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
$aRef = $accountReference | ConvertFrom-Json;
$mRef = $managerAccountReference | ConvertFrom-Json;
$auditMessage = "Guest account for person " + $p.DisplayName + " not updated successfully";

#Change mapping here
$account = [PSCustomObject]@{
    displayName =   $p.Accounts.MicrosoftAzureAD.displayName;
    givenName   =   $p.Accounts.MicrosoftAzureAD.givenName;
    surname     =   $p.Accounts.MicrosoftAzureAD.surname;
    #otherMails = @("email@domain.local");
}

try{
    if(-Not($dryRun -eq $True)){
        $baseUri = "https://login.microsoftonline.com/"
        $authUri = $baseUri + "$AADTenantID/oauth2/token"

        $body = @{
            grant_type      = "client_credentials"
            client_id       = "$AADAppId"
            client_secret   = "$AADAppSecret"
            resource        = "https://graph.microsoft.com"
        }

        $Response = Invoke-RestMethod -Method Post -Uri $authUri -Body $body -ContentType 'application/x-www-form-urlencoded'
        $accessToken = $Response.access_token;

        #Add the authorization header to the request
        $authorization = @{
            Authorization = "Bearer $accesstoken";
            'Content-Type' = "application/json";
            Accept = "application/json";
        }

        $baseCreateUri = "https://graph.microsoft.com/"
        $patchUri = $baseCreateUri + "v1.0/users/$aRef"
        $body = $account | ConvertTo-Json -Depth 10

        $response = Invoke-RestMethod -Uri $patchUri -Method PATCH -Headers $authorization -Body $body -Verbose:$false
    }
    $success = $True;
    $auditMessage = " $($aRef) successfully"; 
}catch{
    $errResponse = $_;
    $auditMessage = " $($aRef) : ${errResponse}";
}

#build up result
$result = [PSCustomObject]@{
    Success= $success;
    AccountReference= $aRef;
    AuditDetails=$auditMessage;
    Account= $account;
};
    
Write-Output $result | ConvertTo-Json -Depth 10;