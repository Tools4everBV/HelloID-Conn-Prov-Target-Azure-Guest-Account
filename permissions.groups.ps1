#####################################################
# HelloID-Conn-Prov-Target-Azure-Permissions-permissions-Groups
#
# Version: 1.1.0
#####################################################
# Initialize default values
$c = $configuration | ConvertFrom-Json

# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

# Set debug logging
switch ($($c.isDebug)) {
    $true { $VerbosePreference = 'Continue' }
    $false { $VerbosePreference = 'SilentlyContinue' }
}
$InformationPreference = "Continue"
$WarningPreference = "Continue"

# Used to connect to Azure AD Graph API
$AADtenantID = $c.AADtenantID
$AADAppId = $c.AADAppId
$AADAppSecret = $c.AADAppSecret

#region functions
function New-AuthorizationHeaders {
    [CmdletBinding()]
    [OutputType([System.Collections.Generic.Dictionary[[String], [String]]])]
    param(
        [parameter(Mandatory)]
        [string]
        $TenantId,

        [parameter(Mandatory)]
        [string]
        $ClientId,

        [parameter(Mandatory)]
        [string]
        $ClientSecret
    )
    try {
        Write-Verbose "Creating Access Token"
        $baseUri = "https://login.microsoftonline.com/"
        $authUri = $baseUri + "$TenantId/oauth2/token"
    
        $body = @{
            grant_type    = "client_credentials"
            client_id     = "$ClientId"
            client_secret = "$ClientSecret"
            resource      = "https://graph.microsoft.com"
        }
    
        $Response = Invoke-RestMethod -Method POST -Uri $authUri -Body $body -ContentType 'application/x-www-form-urlencoded'
        $accessToken = $Response.access_token
    
        #Add the authorization header to the request
        Write-Verbose 'Adding Authorization headers'

        $headers = [System.Collections.Generic.Dictionary[[String], [String]]]::new()
        $headers.Add('Authorization', "Bearer $accesstoken")
        $headers.Add('Accept', 'application/json')
        $headers.Add('Content-Type', 'application/json')
        # Needed to filter on specific attributes (https://docs.microsoft.com/en-us/graph/aad-advanced-queries)
        $headers.Add('ConsistencyLevel', 'eventual')

        Write-Output $headers  
    }
    catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}

function Resolve-HTTPError {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory,
            ValueFromPipeline
        )]
        [object]$ErrorObject
    )
    process {
        $httpErrorObj = [PSCustomObject]@{
            FullyQualifiedErrorId = $ErrorObject.FullyQualifiedErrorId
            MyCommand             = $ErrorObject.InvocationInfo.MyCommand
            RequestUri            = $ErrorObject.TargetObject.RequestUri
            ScriptStackTrace      = $ErrorObject.ScriptStackTrace
            ErrorMessage          = ''
        }
        if ($ErrorObject.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') {
            $httpErrorObj.ErrorMessage = $ErrorObject.ErrorDetails.Message
        }
        elseif ($ErrorObject.Exception.GetType().FullName -eq 'System.Net.WebException') {
            $httpErrorObj.ErrorMessage = [System.IO.StreamReader]::new($ErrorObject.Exception.Response.GetResponseStream()).ReadToEnd()
        }
        Write-Output $httpErrorObj
    }
}

function Resolve-MicrosoftGraphAPIErrorMessage {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory,
            ValueFromPipeline
        )]
        [object]$ErrorObject
    )
    process {
        try {
            $errorObjectConverted = $ErrorObject | ConvertFrom-Json -ErrorAction Stop

            if ($null -ne $errorObjectConverted.error_description) {
                $errorMessage = $errorObjectConverted.error_description
            }
            elseif ($null -ne $errorObjectConverted.error) {
                if ($null -ne $errorObjectConverted.error.message) {
                    $errorMessage = $errorObjectConverted.error.message
                    if ($null -ne $errorObjectConverted.error.code) { 
                        $errorMessage = $errorMessage + " Error code: $($errorObjectConverted.error.code)"
                    }
                }
                else {
                    $errorMessage = $errorObjectConverted.error
                }
            }
            else {
                $errorMessage = $ErrorObject
            }
        }
        catch {
            $errorMessage = $ErrorObject
        }

        Write-Output $errorMessage
    }
}
#endregion functions

# Get Microsoft 365 Groups (Currently only Microsoft 365 and Security groups are supported by the Microsoft Graph API: https://docs.microsoft.com/en-us/graph/api/resources/groups-overview?view=graph-rest-1.0)
try {
    try {
        $headers = New-AuthorizationHeaders -TenantId $AADtenantID -ClientId $AADAppId -ClientSecret $AADAppSecret

        [System.Collections.ArrayList]$m365Groups = @()

        # Define the properties to select (comma seperated)
        # Add optinal popertySelection (mandatory: id,displayName,onPremisesSyncEnabled)
        $properties = @("id", "displayName", "onPremisesSyncEnabled", "groupTypes")
        $select = "`$select=$($properties -join ",")"

        # Get Microsoft 365 Groups only (https://docs.microsoft.com/en-us/graph/api/group-list?view=graph-rest-1.0&tabs=http)
        Write-Verbose "Querying Microsoft 365 groups"

        $baseUri = "https://graph.microsoft.com/"
        $m365GroupFilter = "`$filter=groupTypes/any(c:c+eq+'Unified')"
        $splatWebRequest = @{
            Uri     = "$baseUri/v1.0/groups?$m365GroupFilter&$select"
            Headers = $headers
            Method  = 'GET'
        }
        $getM365GroupsResponse = $null
        $getM365GroupsResponse = Invoke-RestMethod @splatWebRequest -Verbose:$false
        foreach ($M365Group in $getM365GroupsResponse.value) { $null = $m365Groups.Add($M365Group) }
        
        while (![string]::IsNullOrEmpty($getM365GroupsResponse.'@odata.nextLink')) {
            $baseUri = "https://graph.microsoft.com/"
            $splatWebRequest = @{
                Uri     = $getM365GroupsResponse.'@odata.nextLink'
                Headers = $headers
                Method  = 'GET'
            }
            $getM365GroupsResponse = $null
            $getM365GroupsResponse = Invoke-RestMethod @splatWebRequest -Verbose:$false
            foreach ($M365Group in $getM365GroupsResponse.value) { $null = $m365Groups.Add($M365Group) }
        }

        Write-Information "Successfully queried Microsoft 365 groups. Result count: $($m365Groups.Count)"
    }
    catch {
        # Clean up error variables
        $verboseErrorMessage = $null
        $auditErrorMessage = $null

        $ex = $PSItem
        if ( $($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
            $errorObject = Resolve-HTTPError -Error $ex

            $verboseErrorMessage = $errorObject.ErrorMessage

            $auditErrorMessage = Resolve-MicrosoftGraphAPIErrorMessage -ErrorObject $errorObject.ErrorMessage
        }

        # If error message empty, fall back on $ex.Exception.Message
        if ([String]::IsNullOrEmpty($verboseErrorMessage)) {
            $verboseErrorMessage = $ex.Exception.Message
        }
        if ([String]::IsNullOrEmpty($auditErrorMessage)) {
            $auditErrorMessage = $ex.Exception.Message
        }

        Write-Verbose "Error at Line '$($ex.InvocationInfo.ScriptLineNumber)': $($ex.InvocationInfo.Line). Error: $($verboseErrorMessage)"

        throw "Error querying Microsoft 365 Groups. Error Message: $auditErrorMessage"
    }
}
finally {
    # Send results
    $m365Groups | ForEach-Object {
        # Shorten DisplayName to max. 100 chars
        $displayName = "Microsoft 365 Group - $($_.displayName)"
        $displayName = $displayName.substring(0, [System.Math]::Min(100, $displayName.Length)) 
        $permission = @{
            displayName    = $displayName
            identification = @{
                Id   = $_.id
                Name = $_.displayName
            }
        }
        Write-output ($permission | ConvertTo-Json -Depth 10)
    }
}

# Get Security Groups (Currently only Microsoft 365 and Security groups are supported by the Microsoft Graph API: https://docs.microsoft.com/en-us/graph/api/resources/groups-overview?view=graph-rest-1.0)
try {
    try {
        $headers = New-AuthorizationHeaders -TenantId $AADtenantID -ClientId $AADAppId -ClientSecret $AADAppSecret

        [System.Collections.ArrayList]$securityGroups = @()

        # Define the properties to select (comma seperated)
        # Add optinal popertySelection (mandatory: id,displayName,onPremisesSyncEnabled)
        $properties = @("id", "displayName", "onPremisesSyncEnabled", "groupTypes")
        $select = "`$select=$($properties -join ",")"

        # Get Security Groups only (https://docs.microsoft.com/en-us/graph/api/resources/groups-overview?view=graph-rest-1.0)
        Write-Verbose "Querying Security groups"

        $securityGroupFilter = "`$filter=NOT(groupTypes/any(c:c+eq+'DynamicMembership')) and onPremisesSyncEnabled eq null and mailEnabled eq false and securityEnabled eq true"
        $baseUri = "https://graph.microsoft.com/"
        $splatWebRequest = @{
            Uri     = "$baseUri/v1.0/groups?$securityGroupFilter&$select&`$count=true"
            Headers = $headers
            Method  = 'GET'
        }
        $getSecurityGroupsResponse = $null
        $getSecurityGroupsResponse = Invoke-RestMethod @splatWebRequest -Verbose:$false
        foreach ($SecurityGroup in $getSecurityGroupsResponse.value) { $null = $securityGroups.Add($SecurityGroup) }
        
        while (![string]::IsNullOrEmpty($getSecurityGroupsResponse.'@odata.nextLink')) {
            $baseUri = "https://graph.microsoft.com/"
            $splatWebRequest = @{
                Uri     = $getSecurityGroupsResponse.'@odata.nextLink'
                Headers = $headers
                Method  = 'GET'
            }
            $getSecurityGroupsResponse = $null
            $getSecurityGroupsResponse = Invoke-RestMethod @splatWebRequest -Verbose:$false
            foreach ($SecurityGroup in $getSecurityGroupsResponse.value) { $null = $securityGroups.Add($SecurityGroup) }
        }

        Write-Information "Successfully queried Security groups. Result count: $($securityGroups.Count)"
    }
    catch {
        $ex = $PSItem
        if ( $($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
            $errorObject = Resolve-HTTPError -Error $ex

            $verboseErrorMessage = $errorObject.ErrorMessage

            $auditErrorMessage = Resolve-MicrosoftGraphAPIErrorMessage -ErrorObject $errorObject.ErrorMessage
        }

        # If error message empty, fall back on $ex.Exception.Message
        if ([String]::IsNullOrEmpty($verboseErrorMessage)) {
            $verboseErrorMessage = $ex.Exception.Message
        }
        if ([String]::IsNullOrEmpty($auditErrorMessage)) {
            $auditErrorMessage = $ex.Exception.Message
        }

        Write-Verbose "Error at Line '$($ex.InvocationInfo.ScriptLineNumber)': $($ex.InvocationInfo.Line). Error: $($verboseErrorMessage)"

        throw "Error querying Security Groups. Error Message: $auditErrorMessage"
    }
}
finally {
    # Send results
    $securityGroups | ForEach-Object {
        # Shorten DisplayName to max. 100 chars
        $displayName = "Security Group - $($_.displayName)"
        $displayName = $displayName.substring(0, [System.Math]::Min(100, $displayName.Length)) 
        $permission = @{
            displayName    = $displayName
            identification = @{
                Id   = $_.id
                Name = $_.displayName
            }
        }
        Write-output ($permission | ConvertTo-Json -Depth 10)
    }
}