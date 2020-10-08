#Initialize default properties
$success = $False;
$auditMessage = " not revoked succesfully";

$p = $person | ConvertFrom-Json;
$m = $manager | ConvertFrom-Json;
$aRef = $accountReference | ConvertFrom-Json;
$mRef = $managerAccountReference | ConvertFrom-Json;
$pRef = $permissionReference | ConvertFrom-json;

# AzureAD Application Parameters #
$AADtenantID = "<Provide your Tenant ID here>"
$AADAppId = "<Provide your Client ID here>"
$AADAppSecret = "<Provide your Client Secret here>"

# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

#Retrieve account information for notifications
$account = [PSCustomObject]@{}

# The permissionReference contains the Identification object provided in the retrieve permissions call
if(-Not($dryRun -eq $True)) {
    try {
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

        $baseGraphUri = "https://graph.microsoft.com/"
        $removeGroupMembershipUri = $baseGraphUri + "v1.0/groups/$($pRef.id)/members/$($aRef)" + '/$ref'
        $response = Invoke-RestMethod -Method DELETE -Uri $removeGroupMembershipUri -Headers $authorization -Verbose:$false
        
        $success = $True;
        $auditMessage = "AzureAD user [$($aRef)]"
    } catch {
        <#
        $result = $_.Exception.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($result)
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        $errResponse = $reader.ReadToEnd();
        #>
        $errResponse = $_;
        if($errResponse -like "*Resource '$($pRef.id)' does not exist or one of its queried reference-property objects are not present*"){
            $success = $True;
            $auditMessage = "AzureAD user [$($aRef)]. Is already no longer a member or AzureAD group does not exist anymore";
        }else{
            $auditMessage = "AzureAD user [$($aRef)] : ${errResponse}";
        }
    }
}

#build up result
$result = [PSCustomObject]@{ 
    Success= $success;
    AccountReference = $aRef;
    AuditDetails=$auditMessage;
    Account = $account;
};

Write-Output $result | ConvertTo-Json -Depth 10;