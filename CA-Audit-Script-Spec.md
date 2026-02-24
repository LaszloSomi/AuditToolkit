# Microsoft 365 Conditional Access Audit Script

## Purpose

This document provides step-by-step instructions to build and run an audit script that exports Conditional Access (CA) policies from a Microsoft 365 tenant across Commercial, GCC, GCC High (GCCH), and DoD environments. The exported output is designed to be customer-shareable with Microsoft and machine-readable for downstream analysis by a Copilot agent to identify misconfigurations that could block Microsoft 365 Copilot usage.

---

## Supported Environments

The script must support the following environments:

| Environment | Identifier  | Default | Notes                                                         |
|-------------|-------------|---------|---------------------------------------------------------------|
| Commercial  | Commercial  | Yes     | Default when no input provided                                |
| GCC         | GCC         | No      | US Government Community Cloud — uses worldwide endpoints      |
| GCC High    | GCCH        | No      | GCC High / Azure Gov sovereign cloud                          |
| DoD         | DoD         | No      | Department of Defense sovereign cloud                         |

### Environment Behavior

- If no environment parameter is provided, the script defaults to **Commercial**.
- Environment selection controls: authentication endpoint, Microsoft Graph base URL, and token audience.

> **GCC Note:** GCC tenants use the same worldwide (Commercial) endpoints. The GCC row is explicit to prevent misconfiguration, not because the values differ from Commercial.

> **Token Boundary Note:** Access tokens are not interchangeable across cloud boundaries. A token issued by `login.microsoftonline.com` cannot be used against `graph.microsoft.us`.

---

## Script Capabilities (Required)

The audit script must:

1. Prompt for or accept an environment input (Commercial, GCC, GCCH, DoD)
2. Prompt for or accept a user account used to authenticate to the tenant
3. Authenticate to Microsoft Graph using delegated permissions
4. Export all Conditional Access policies in the tenant
5. Follow all `@odata.nextLink` tokens until all policies are retrieved (pagination)
6. Output results in CSV or JSON format with a consistent file naming convention
7. Produce output that can be shared with Microsoft support or engineering
8. Enable Copilot agent analysis for Copilot-blocking misconfigurations

---

## Prerequisites

### Operator Requirements

- Account must exist in the target tenant (personal Microsoft accounts are not supported)
- Account must hold one of the following Entra ID roles:
  - Conditional Access Administrator
  - Security Reader
  - Security Administrator
  - Global Reader
  - Global Administrator
- MFA should be enabled on the account

### Required Graph Permissions (Delegated)

| Permission           | Required    | Purpose                                                                                   |
|----------------------|-------------|-------------------------------------------------------------------------------------------|
| `Policy.Read.All`    | Yes         | Read Conditional Access policies                                                          |
| `Directory.Read.All` | Recommended | Resolve group, user, and role display names from the object IDs returned in policy assignments |

> **Note:** `Policy.Read.All` is the only permission required to read raw CA policy data. `Directory.Read.All` is recommended to resolve object IDs to human-readable display names in the export. Admin consent may be required for both permissions depending on tenant policy.

---

## Input Parameters

The script must accept the following inputs:

| Parameter         | Required | Default           | Description                                         |
|-------------------|----------|-------------------|-----------------------------------------------------|
| Environment       | No       | Commercial        | Target cloud: Commercial, GCC, GCCH, DoD            |
| UserPrincipalName | Yes      | None              | Account used to authenticate                        |
| AuthFlow          | No       | Interactive       | Authentication flow: prefer `Interactive` over `DeviceCode`  |
| OutputFormat      | No       | JSON              | `JSON` or `CSV`                                     |
| OutputPath        | No       | Current directory | File export location                                |

---

## Authentication Flow

The script must support two delegated authentication flows:

| Flow        | Use Case                          | Notes                                                       |
|-------------|-----------------------------------|-------------------------------------------------------------|
| Interactive | Admin running script locally      | Opens browser window for sign-in; supports MFA natively     |
| DeviceCode  | Headless / SSH / server context   | Displays a code; admin authenticates from a separate browser|

Both flows must acquire a delegated token scoped to the target environment's Graph API token audience (see Environment-to-Endpoint Mapping). Application-only authentication is not supported — delegated permissions are required to ensure the audit is attributable to the running account.

---

## Environment-to-Endpoint Mapping

The script must dynamically select endpoints based on environment input.

| Environment | Auth Authority                       | Graph API Endpoint              | Token Audience                  |
|-------------|--------------------------------------|---------------------------------|---------------------------------|
| Commercial  | https://login.microsoftonline.com    | https://graph.microsoft.com     | https://graph.microsoft.com     |
| GCC         | https://login.microsoftonline.com    | https://graph.microsoft.com     | https://graph.microsoft.com     |
| GCCH        | https://login.microsoftonline.us     | https://graph.microsoft.us      | https://graph.microsoft.us      |
| DoD         | https://login.microsoftonline.us     | https://dod-graph.microsoft.us  | https://dod-graph.microsoft.us  |

---

## Pagination

The Microsoft Graph `GET /identity/conditionalAccess/policies` endpoint returns results as a paged OData collection. The script must:

1. Request the first page of results
2. Check the response for an `@odata.nextLink` property
3. Follow each `@odata.nextLink` URL until no further link is present
4. Accumulate all policy objects across pages before writing output

> **Warning:** Failure to handle pagination will silently return incomplete results in tenants with many policies. This must not be treated as optional.

---

## Script Runtime

The script should be implemented in **PowerShell** using the **Microsoft.Graph PowerShell SDK** (`Microsoft.Graph.Identity.SignIns` module). This is the recommended runtime for Microsoft 365 administrators because:

- The SDK handles token acquisition, refresh, and pagination automatically
- It is available cross-platform (Windows, macOS, Linux)
- It supports sovereign cloud environments via the `-Environment` parameter
- No separate MSAL library integration is required

**Alternative:** Python using `msal` + `requests` is acceptable if PowerShell is unavailable, but requires manual pagination handling and token management.

---

## Output Specification

### File Naming Convention

Output files must follow this naming pattern:

```
CA-Export-{TenantId}-{Environment}-{Timestamp}.{ext}
```

Example: `CA-Export-00000000-0000-0000-0000-000000000000-Commercial-20260223T143000Z.json`

### JSON Format

Export a JSON array where each element represents one Conditional Access policy. The structure must preserve the full nested object hierarchy returned by the Graph API (no flattening for JSON). Include a metadata envelope:

```json
{
  "exportedBy": "user@tenant.com",
  "exportedAt": "2026-02-23T14:30:00Z",
  "environment": "Commercial",
  "tenantId": "00000000-0000-0000-0000-000000000000",
  "policyCount": 42,
  "policies": [ ... ]
}
```

### CSV Format

When exporting as CSV, nested objects and arrays must be serialized as JSON strings within their respective columns. Each row represents one policy. Column names must exactly match Graph API property paths to enable programmatic processing by downstream agents.

---

## Data Collection Scope

The script must export the following for each Conditional Access policy:

### Core Policy Metadata

| Field         | Graph Property    | Notes                                                    |
|---------------|-------------------|----------------------------------------------------------|
| Policy ID     | `id`              | Read-only                                                |
| Display name  | `displayName`     |                                                          |
| State         | `state`           | `enabled`, `disabled`, `enabledForReportingButNotEnforced` |
| Created       | `createdDateTime` | Read-only                                                |
| Last modified | `modifiedDateTime`| Read-only                                                |
| Template ID   | `templateId`      | Null if not created from a Microsoft template            |

### Assignments

| Field                        | Graph Property                                        |
|------------------------------|-------------------------------------------------------|
| Included users               | `conditions.users.includeUsers`                       |
| Excluded users               | `conditions.users.excludeUsers`                       |
| Included groups              | `conditions.users.includeGroups`                      |
| Excluded groups              | `conditions.users.excludeGroups`                      |
| Included roles               | `conditions.users.includeRoles`                       |
| Excluded roles               | `conditions.users.excludeRoles`                       |
| Included guests/external     | `conditions.users.includeGuestsOrExternalUsers`       |
| Excluded guests/external     | `conditions.users.excludeGuestsOrExternalUsers`       |
| Client apps / workload IDs   | `conditions.clientApplications`                       |

### Conditions

| Condition                  | Graph Property                                                                    |
|----------------------------|-----------------------------------------------------------------------------------|
| Applications (include)     | `conditions.applications.includeApplications`                                     |
| Applications (exclude)     | `conditions.applications.excludeApplications`                                     |
| User actions               | `conditions.applications.includeUserActions`                                      |
| Authentication context     | `conditions.applications.includeAuthenticationContextClassReferences`             |
| Client app types           | `conditions.clientAppTypes`                                                       |
| Device platforms           | `conditions.platforms`                                                            |
| Device filter              | `conditions.devices.deviceFilter` (OData rule syntax; include/exclude mode)       |
| Named locations            | `conditions.locations`                                                            |
| Sign-in risk levels        | `conditions.signInRiskLevels`                                                     |
| User risk levels           | `conditions.userRiskLevels`                                                       |
| Service principal risk     | `conditions.servicePrincipalRiskLevels`                                           |
| Insider risk levels        | `conditions.insiderRiskLevels`                                                    |
| Authentication flows       | `conditions.authenticationFlows`                                                  |

### Grant Controls

| Control                          | Graph Property / Value                            |
|----------------------------------|---------------------------------------------------|
| Grant control operator           | `grantControls.operator` (`AND` / `OR`)           |
| Block access                     | `block`                                           |
| Require MFA                      | `mfa`                                             |
| Require compliant device         | `compliantDevice`                                 |
| Require Hybrid Azure AD join     | `domainJoinedDevice`                              |
| Require approved client app      | `approvedApplication`                             |
| Require app protection policy    | `compliantApplication`                            |
| Require password change          | `passwordChange`                                  |
| Authentication strength          | `grantControls.authenticationStrength` (relationship object — specifies allowed authentication method combinations, e.g., phishing-resistant MFA, FIDO2 only) |
| Terms of use                     | `grantControls.termsOfUse`                        |
| Custom authentication factors    | `grantControls.customAuthenticationFactors`       |

### Session Controls

| Control                        | Graph Property                                   | Notes                                               |
|--------------------------------|--------------------------------------------------|-----------------------------------------------------|
| Sign-in frequency              | `sessionControls.signInFrequency`                | Interval (hours/days) or every time                 |
| Persistent browser session     | `sessionControls.persistentBrowser`              | Always/never persist cookies                        |
| App-enforced restrictions      | `sessionControls.applicationEnforcedRestrictions`| Exchange Online and SharePoint Online only          |
| Defender for Cloud Apps        | `sessionControls.cloudAppSecurity`               | Monitor, block downloads, etc.                      |
| Disable resilience defaults    | `sessionControls.disableResilienceDefaults`      | Blocks session extension during Entra outages       |
| Continuous access evaluation   | `sessionControls.continuousAccessEvaluation`     | **Beta** — strict location / disabled / strict enforcement |
| Token protection               | `sessionControls.secureSignInSession`            | **Beta** — binds tokens to device/session           |

> **Note:** Continuous access evaluation and token protection are beta-only Graph API properties. The script must attempt to collect them but must not fail if they are absent from the response.

---

## Microsoft 365 Copilot Application Scope

The downstream analysis must evaluate CA policies against the applications that constitute Microsoft 365 Copilot. The relevant application IDs are tenant- and environment-specific and must be identified from the tenant's service principal registrations before analysis.

To enumerate the relevant app IDs, query:

```
GET /servicePrincipals?$filter=startswith(displayName,'Microsoft 365 Copilot')
  &$select=id,appId,displayName
```

The script or analysis agent must maintain a configurable list of Copilot app IDs and flag any CA policy that:

- Explicitly includes or excludes these applications without appropriate controls
- Lacks coverage for all users across all apps (i.e., Copilot is not within scope of any enforcing policy)
- Applies session controls or grant controls that are incompatible with Copilot's supported authentication methods
