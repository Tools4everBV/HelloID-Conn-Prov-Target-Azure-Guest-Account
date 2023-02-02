#####################################################
# HelloID-Conn-Prov-Target-Azure-Guest-Account-Enable
#
# Version: 1.1.0
#####################################################
# Initialize default values
$c = $configuration | ConvertFrom-Json
$p = $person | ConvertFrom-Json
$success = $false
$auditLogs = [System.Collections.Generic.List[PSCustomObject]]::new()

# The accountReference object contains the Identification object provided in the create account call
$aRef = $accountReference | ConvertFrom-Json

# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

# Set debug logging
switch ($($c.isDebug)) {
    $true { $VerbosePreference = 'Continue' }
    $false { $VerbosePreference = 'SilentlyContinue' }
}
$InformationPreference = "Continue"
$WarningPreference = "Continue"

# Used to connect to Azure AD using Microsoft Graph
$AADtenantID = $c.AADtenantID
$AADAppId = $c.AADAppId
$AADAppSecret = $c.AADAppSecret

#Change mapping here
$account = [PSCustomObject]@{
    accountEnabled = $true
}

# Check if required fields are available
$incompleteAccount = $false
$requiredFields = @('accountEnabled')
foreach ($requiredField in $requiredFields) {
    if ([String]::IsNullOrEmpty($account.$requiredField)) {
        $incompleteAccount = $true
        Write-Warning "Account object field '$requiredField' has a null or empty value"
    }
}

# Check if aRef available
$aRefMissing = $false
if ([String]::IsNullOrEmpty($aRef)) {
    $aRefMissing = $true
    Write-Warning "aRef has a null or empty value"
}

#region functions
function New-AuthorizationHeaders {
    [CmdletBinding()]
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
        throw $_
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

try {
    if ($aRefMissing -eq $true) {
        if (-not($dryRun -eq $true)) {
            $auditLogs.Add([PSCustomObject]@{
                    # Action  = "EnableAccount" # Optional
                    Message = "aRef incomplete, cannot enable account"
                    IsError = $true
                })
        }
        else {
            Write-Warning "DryRun: aRef incomplete, cannot enable account. aRef object: $($aRef | ConvertTo-Json -Depth 10)" 
        }
    }
    elseif ($incompleteAccount -eq $true) {
        if (-not($dryRun -eq $true)) {
            $auditLogs.Add([PSCustomObject]@{
                    # Action  = "EnableAccount" # Optional
                    Message = "Account object incomplete, cannot enable account"
                    IsError = $true
                })
        }
        else {
            Write-Warning "DryRun: Account object incomplete, cannot enable account. Account object: $($account | ConvertTo-Json -Depth 10)" 
        }
    }
    else {
        # Get current Azure AD account
        try {
            $headers = New-AuthorizationHeaders -TenantId $AADtenantID -ClientId $AADAppId -ClientSecret $AADAppSecret

            Write-Verbose "Querying Azure AD account with id '$($aRef)'"

            $baseUri = "https://graph.microsoft.com/"
            $splatWebRequest = @{
                Uri     = "$baseUri/v1.0/users/$aRef"
                Headers = $headers
                Method  = 'GET'
            }
            $currentAccount = $null
            $currentAccount = Invoke-RestMethod @splatWebRequest -Verbose:$false

            if ($null -ne $currentAccount.id) {
                Write-Verbose "Successfully found Azure AD account id '$($aRef)': $($currentAccount.userPrincipalName) ($($currentAccount.id))"
            } 
            else {
                throw "No account found in Azure AD with id '$($aRef)'"
            }
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

            $auditLogs.Add([PSCustomObject]@{
                    # Action  = "EnableAccount" # Optional
                    Message = "Error querying Azure AD account with id '$($aRef)'. Error Message: $auditErrorMessage"
                    IsError = $true
                })
        }

        if (-NOT($auditLogs.IsError -contains $true)) {
            # Enable Azure AD account
            try {
                $baseUri = "https://graph.microsoft.com/"
                $body = $account | ConvertTo-Json -Depth 10
                $splatWebRequest = @{
                    Uri     = "$baseUri/v1.0/users/$($currentAccount.id)"
                    Headers = $headers
                    Method  = 'PATCH'
                    Body    = ([System.Text.Encoding]::UTF8.GetBytes($body))
                }

                if (-not($dryRun -eq $true)) {
                    Write-Verbose "Enabling Azure AD account '$($currentAccount.userPrincipalName) ($($currentAccount.id))'. Account object: $($account | ConvertTo-Json -Depth 10)"

                    $enableAccountResponse = $null
                    $enableAccountResponse = Invoke-RestMethod @splatWebRequest -Verbose:$false

                    # Define ExportData
                    $exportData = [PSCustomObject]@{
                        DisplayName       = $currentAccount.displayName
                        ID                = $currentAccount.id
                        UserPrincipalName = $currentAccount.userPrincipalName
                    }

                    $auditLogs.Add([PSCustomObject]@{
                            # Action  = "EnableAccount" # Optional
                            Message = "Successfully enabled Azure AD account '$($currentAccount.userPrincipalName) ($($currentAccount.id))'"
                            IsError = $false
                        })
                }
                else {
                    Write-Warning "DryRun: Would enable Azure AD account '$($currentAccount.userPrincipalName) ($($currentAccount.id))'. Account object: $($account | ConvertTo-Json -Depth 10)"
                }
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

                $auditLogs.Add([PSCustomObject]@{
                        # Action  = "EnableAccount" # Optional
                        Message = "Error enabling Azure AD account '$($currentAccount.userPrincipalName) ($($currentAccount.id))'. Account object: $($account | ConvertTo-Json -Depth 10). Error Message: $auditErrorMessage"
                        IsError = $true
                    })
            }
        }
    }
}
finally {
    # Check if auditLogs contains errors, if no errors are found, set success to true
    if (-NOT($auditLogs.IsError -contains $true) -and $aRefMissing -eq $false -and $incompleteAccount -eq $false) {
        $success = $true
    }

    # Send results
    $result = [PSCustomObject]@{
        Success          = $success
        AccountReference = $aRef
        AuditLogs        = $auditLogs
        Account          = $account

        # Optionally return data for use in other systems
        ExportData       = $exportData
    }

    Write-Output ($result | ConvertTo-Json -Depth 10)  
}