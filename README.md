# HelloID-Conn-Prov-Target-Azure-Guest-Account

| :information_source: Information |
|:---------------------------|
| This repository contains the connector and configuration code only. The implementer is responsible to acquire the connection details such as username, password, certificate, etc. You might even need to sign a contract or agreement with the supplier before implementing this connector. Please contact the client's application manager to coordinate the connector requirements.       |

## Versioning
| Version | Description | Date |
| - | - | - |
| 1.1.0   | Updated with new logging and checks for existing accounts and missing aRef or account mapping | 2023/02/02  |
| 1.0.0   | Initial release | 2020/07/17  |

<!-- TABLE OF CONTENTS -->
## Table of Contents
- [HelloID-Conn-Prov-Target-Azure-Guest-Account](#helloid-conn-prov-target-azure-guest-account)
  - [Versioning](#versioning)
  - [Table of Contents](#table-of-contents)
  - [Introduction](#introduction)
  - [Getting the Azure AD graph API access](#getting-the-azure-ad-graph-api-access)
    - [Application Registration](#application-registration)
    - [Configuring App Permissions](#configuring-app-permissions)
    - [Authentication and Authorization](#authentication-and-authorization)
    - [Connection settings](#connection-settings)
  - [Getting help](#getting-help)
  - [HelloID Docs](#helloid-docs)

## Introduction
The interface to communicate with Microsoft Azure AD is through the Microsoft Graph API. GetConnectors are based on a pre-defined 'data collection', which is an existing view based on the data inside the Profit database.

- For this connector we can create the Azure AD Guest accounts by sending an invitation, this way they can log on with their invited email address.
  > If you want to create Azure AD Guest accounts directly (with a logon name of the tenant domain itself), please use the built-in Microsoft Azure Active Directory target system. By specifying the userType 'Guest' in the mapping you can create Guest accounts with a logon name of the tenant domain.
- > If you want to create regular Azure AD accounts, please use the built-in Microsoft Azure Active Directory target system.
- We can also correlate to an existing Azure AD account and manage this account (enable,disable,update and delete).
- Additionally we have the option to provision groupmemberships.
  > Currently only Microsoft 365 and Security groups are supported by the Microsoft Graph API

<!-- GETTING STARTED -->
## Getting the Azure AD graph API access

### Application Registration
The first step to connect to Graph API and make requests, is to register a new <b>Azure Active Directory Application</b>. The application is used to connect to the API and to manage permissions.

* Navigate to <b>App Registrations</b> in Azure, and select “New Registration” (<b>Azure Portal > Azure Active Directory > App Registration > New Application Registration</b>).
* Next, give the application a name. In this example we are using “<b>HelloID PowerShell</b>” as application name.
* Specify who can use this application (<b>Accounts in this organizational directory only</b>).
* Specify the Redirect URI. You can enter any url as a redirect URI value. In this example we used http://localhost because it doesn't have to resolve.
* Click the “<b>Register</b>” button to finally create your new application.

Some key items regarding the application are the Application ID (which is the Client ID), the Directory ID (which is the Tenant ID) and Client Secret.

### Configuring App Permissions
The [Microsoft Graph documentation](https://docs.microsoft.com/en-us/graph) provides details on which permission are required for each permission type.

To assign your application the right permissions, navigate to <b>Azure Portal > Azure Active Directory >App Registrations</b>.
Select the application we created before, and select “<b>API Permissions</b>” or “<b>View API Permissions</b>”.
To assign a new permission to your application, click the “<b>Add a permission</b>” button.
From the “<b>Request API Permissions</b>” screen click “<b>Microsoft Graph</b>”.
For this connector the following permissions are used as <b>Application permissions</b>:
*	Read and Write all user’s full profiles by using <b><i>User.ReadWrite.All</i></b>
*	Read and Write all groups in an organization’s directory by using <b><i>Group.ReadWrite.All</i></b>
*	Read and Write data to an organization’s directory by using <b><i>Directory.ReadWrite.All</i></b>
*	Invite Guests by using <b><i>User.Invite.All</i></b>

Some high-privilege permissions can be set to admin-restricted and require an administrators consent to be granted.

To grant admin consent to our application press the “<b>Grant admin consent for TENANT</b>” button.

### Authentication and Authorization
There are multiple ways to authenticate to the Graph API with each has its own pros and cons, in this example we are using the Authorization Code grant type.

*	First we need to get the <b>Client ID</b>, go to the <b>Azure Portal > Azure Active Directory > App Registrations</b>.
*	Select your application and copy the Application (client) ID value.
*	After we have the Client ID we also have to create a <b>Client Secret</b>.
*	From the Azure Portal, go to <b>Azure Active Directory > App Registrations</b>.
*	Select the application we have created before, and select "<b>Certificates and Secrets</b>". 
*	Under “Client Secrets” click on the “<b>New Client Secret</b>” button to create a new secret.
*	Provide a logical name for your secret in the Description field, and select the expiration date for your secret.
*	It's IMPORTANT to copy the newly generated client secret, because you cannot see the value anymore after you close the page.
*	At last we need to get the <b>Tenant ID</b>. This can be found in the Azure Portal by going to <b>Azure Active Directory > Overview</b>.

### Connection settings
The following settings are required to connect to the API.

| Setting     | Description |
| ------------ | ----------- |
| Azure AD Tenant ID | Id of the Azure tenant |
| Azure AD App ID | Id of the Azure app |
| Azure AD App Secret | Secret of the Azure app |

## Getting help
> _For more information on how to configure a HelloID PowerShell connector, please refer to our [documentation](https://docs.helloid.com/hc/en-us/articles/360012518799-How-to-add-a-target-system) pages_

> _If you need help, feel free to ask questions on our [forum](https://forum.helloid.com)_
- > _For any remarks about this connector, please use the [Connector specific forum post](https://forum.helloid.com/forum/helloid-connectors/provisioning/1269-helloid-provisioning-helloid-conn-prov-target-azure-guest-account)_

## HelloID Docs
The official HelloID documentation can be found at: https://docs.helloid.com/