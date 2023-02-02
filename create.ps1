#####################################################
# HelloID-Conn-Prov-Target-Azure-Guest-Account-Create-Correlate
#
# Version: 1.1.0
#####################################################
# Initialize default values
$c = $configuration | ConvertFrom-Json
$p = $person | ConvertFrom-Json
$success = $false
$auditLogs = [System.Collections.Generic.List[PSCustomObject]]::new()

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
    invitedUserDisplayName  = $p.DisplayName -replace '( \().*$', '' # Remove everyting after ' (' to not include employeeID in displayname
    invitedUserEmailAddress = $p.Contact.Personal.Email
    sendInvitationMessage   = $true
    inviteRedirectUrl       = "https://portal.azure.com/"
    invitedUserMessageInfo  = @{
        # customizedMessageBody = "Personalized message body."
        messageLanguage = "nl-NL" # If the customizedMessageBody is specified, this property is ignored, and the message is sent using the customizedMessageBody. The language format should be in ISO 639. The default is en-US.
    }
}

# Check if required fields are available
$incompleteAccount = $false
$requiredFields = @('invitedUserEmailAddress', 'invitedUserDisplayName')
foreach ($requiredField in $requiredFields) {
    if ([String]::IsNullOrEmpty($account.$requiredField)) {
        $incompleteAccount = $true
        Write-Warning "Account object field '$requiredField' has a null or empty value"
    }
}

# Correlation values
$filterField = "EmployeeID"
$filtervalue = $p.externalId # Has to match the Azure AD value of the specified filter field ($filterField)

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
    if ($incompleteAccount -eq $true) {
        if (-not($dryRun -eq $true)) {
            $auditLogs.Add([PSCustomObject]@{
                    # Action  = "CreateAccount" # Optional
                    Message = "Account object incomplete, cannot create account"
                    IsError = $true
                })
        }
        else {
            Write-Warning "DryRun: Account object incomplete, cannot create account. Account object: $($account | ConvertTo-Json -Depth 10)" 
        }
    }
    else {
        # Get current Azure AD account and verify if a user must be either [created], [updated and correlated] or just [correlated]
        try {
            $headers = New-AuthorizationHeaders -TenantId $AADtenantID -ClientId $AADAppId -ClientSecret $AADAppSecret

            Write-Verbose "Querying Azure AD account with $($filterField) $($filtervalue)"

            $baseUri = "https://graph.microsoft.com/"
            $splatWebRequest = @{
                Uri     = "$baseUri/v1.0/users?`$filter=$filterField eq '$filtervalue'"
                Headers = $headers
                Method  = 'GET'
            }
            $currentAccount = $null
            $currentAccount = (Invoke-RestMethod @splatWebRequest -Verbose:$false).value

            if ($null -ne $currentAccount.id) {
                Write-Verbose "Successfully found Azure AD account with $($filterField) $($filtervalue): $($currentAccount.userPrincipalName) ($($currentAccount.id))"
                
                $action = 'Correlate'
            } 
            else {
                Write-Verbose "No account found in Azure AD with $($filterField) $($filtervalue). Creating new acount"
                $action = 'Create'
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
                    # Action  = "CreateAccount" # Optional
                    Message = "Error querying Azure AD account with $($filterField) $($filtervalue). Error Message: $auditErrorMessage"
                    IsError = $true
                })
        }

        # Either create or just correlate Azure AD account
        switch ($action) {
            'Create' {
                try {
                    $baseUri = "https://graph.microsoft.com/"
                    $body = $account | ConvertTo-Json -Depth 10
                    $splatWebRequest = @{
                        Uri     = "$baseUri/v1.0/invitations"
                        Headers = $headers
                        Method  = 'POST'
                        Body    = ([System.Text.Encoding]::UTF8.GetBytes($body))
                    }

                    if (-not($dryRun -eq $true)) {
                        Write-Verbose "Creating Azure AD Guest invitation for '$($account.invitedUserDisplayName) ($($account.invitedUserEmailAddress))'. Invitation object: $($account | ConvertTo-Json -Depth 10)"

                        $createInvitationResponse = $null
                        $createInvitationResponse = Invoke-RestMethod @splatWebRequest -Verbose:$false

                        # Set aRef object for use in futher actions
                        $aRef = $createInvitationResponse.invitedUser.id

                        # Define ExportData
                        $exportData = [PSCustomObject]@{
                            DisplayName             = $createInvitationResponse.invitedUserDisplayName
                            ID                      = $createInvitationResponse.invitedUser.id
                            invitedUserEmailAddress = $createInvitationResponse.invitedUserEmailAddress
                        }

                        $auditLogs.Add([PSCustomObject]@{
                                # Action  = "CreateAccount" # Optiponal
                                Message = "Successfully created Azure AD Guest invitation for '$($account.invitedUserDisplayName) ($($account.invitedUserEmailAddress))'"
                                IsError = $false
                            })
                    }
                    else {
                        Write-Warning "DryRun: Would create Azure AD Guest invitation for '$($account.invitedUserDisplayName) ($($account.invitedUserEmailAddress))'. Invitation object: $($account | ConvertTo-Json -Depth 10)"
                    }
                    break
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
                            # Action  = "CreateAccount" # Optional
                            Message = "Error creating Azure AD Guest invitation for '$($account.invitedUserDisplayName) ($($account.invitedUserEmailAddress))'. Invitation object: $($account | ConvertTo-Json -Depth 10). Error Message: $auditErrorMessage"
                            IsError = $true
                        })
                }
            }
            'Correlate' {
                Write-Verbose "Correlating to Azure AD account '$($currentAccount.userPrincipalName) ($($currentAccount.id))'"

                if (-not($dryRun -eq $true)) {
                    # Set aRef object for use in futher actions
                    $aRef = $currentAccount.id

                    # Define ExportData
                    $exportData = [PSCustomObject]@{
                        DisplayName       = $currentAccount.displayName
                        ID                = $currentAccount.id
                        UserPrincipalName = $currentAccount.userPrincipalName
                    }

                    $auditLogs.Add([PSCustomObject]@{
                            # Action  = "CreateAccount" # Optional
                            Message = "Successfully correlated to Azure AD account '$($currentAccount.userPrincipalName) ($($currentAccount.id))'"
                            IsError = $false
                        })
                }
                else {
                    Write-Warning "DryRun: Would correlate to Azure AD account '$($currentAccount.userPrincipalName) ($($currentAccount.id))'"
                }
                break
            }
        }
    }
}
finally {
    # Check if auditLogs contains errors, if no errors are found, set success to true
    if (-NOT($auditLogs.IsError -contains $true) -and $incompleteAccount -eq $false) {
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