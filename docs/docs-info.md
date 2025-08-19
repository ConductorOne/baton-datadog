hile developing the connector, please fill out this form. This information is needed to write docs and to help other users set up the connector.

## Connector capabilities

1. What resources does the connector sync?

    -Users
    -Schedules
    -Teams
    -Roles
    -API keys

2. Can the connector provision any resources? If so, which ones? 

    Yes, this includes entitlement provision for roles and teams

## Connector credentials 

1. What credentials or information are needed to set up the connector? (For example, API key, client ID and secret, domain, etc.)

    - **API Key**: Primary authentication credential for Datadog API access
    - **Application Key**: Secondary credential with specific scopes for user/team management
    - **Site**: Datadog site identifier (e.g., datadoghq.com, datadoghq.eu)

2. For each item in the list above: 

   * How does a user create or look up that credential or info? Please include links to (non-gated) documentation, screenshots (of the UI or of gated docs), or a video of the process. 

     * **API Key**: Organization Settings → API Keys → New Key. [Datadog API Keys Documentation](https://docs.datadoghq.com/account_management/api-app-keys/#api-keys)
     * **Application Key**: Organization Settings → Application Keys → New Key. [Datadog Application Keys Documentation](https://docs.datadoghq.com/account_management/api-app-keys/#application-keys)
     * **Site**: Check your Datadog URL (e.g., https://app.datadoghq.com → site is "datadoghq.com"). [Datadog Site Documentation](https://docs.datadoghq.com/getting_started/site/#access-the-datadog-site)

   * Does the credential need any specific scopes or permissions? If so, list them here. 

     * **API Key**: Access to user management, team management, role management, on-call schedules
     * **Application Key**: Access Management scope, Teams scope

    * If applicable: Is the list of scopes or permissions different to sync (read) versus provision (read-write)? If so, list the difference here. 

     * **Sync (Read-only)**: Read access to Access Management and Teams scopes
     * **Provisioning (Read-write)**: Full access to Access Management and Teams scopes, plus user creation, role assignment, team membership management

     * What level of access or permissions does the user need in order to create the credentials? (For example, must be a super administrator, must have access to the admin console, etc.)  

     * **API Key**: Admin or Standard user role, access to Organization Settings
     * **Application Key**: Admin or Standard user role, access to Organization Settings
     * **Site**: No special permissions required  
