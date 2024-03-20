# Security: JWT User Identity

_NOTE: This page provides documentation for the JWT and Client Identity validation which is a pull request pending approval and merging into QuicSec. Integration via OIDC platforms like Auth0/Okta are enabled with this capability, enabling transparent user authentication workflows on behalf of the app.

## Overview: JWT Assignment (via OIDC) and Authorization (Claims Validation)

User Identity workflows (using JWT) can be enabled in a single step on behalf of the applications. The JWT assignment (via OIDC) and claims authorization workflows are implemented as a plugin allowing for dynamic addition when enabled. The notable capabilities implemented by the plugin include:

* OIDC Redirection: Requests missing an Authorization header are redirected via OIDC to a configured authorization service provider (e.g., Auth0/Okta).

* Claims Authorization: Individual transactions will be allowed or denied based on policies matching on the audience and scope embedded in the token

## Architecture


![User Identity and JWT Auth Architecture](/images/desktop/jwt-authorization.png)

When enabled, the User Identity / JWT workflow redirects all inbound http requests lacking a jwt authorization header to the configured Authorization service. Similarly, any clients whose requests successfully complete authorization and are redirected back to the redirection uri will have the issuer identity verified, and further authorization of the claims and scope for the resource being accessed will be authorized, as illustrated in the examples below. Authorization policies can either be via built-in Policy resources or via external authrization via plugins like OPA.



## Scenarios

The different scenarios to consider when creating User authentication (JWT) policies are illustrated with the help of the architecture diagram above.

The types of client accesses to consider when building policies:

* 1. Configure Authorization Provider (e.g., Auth0 / Okta) for this application, providing a redirection url during configuration and receiving a client secret.

* 2. Clients that haven't previously authenticated with the authorization service to receive a jwt. In this case, when the client application attempts to access the App, it will be redirected to the Authorization service via OIDC. Once the client has successfully authenticated with the Auth service, it will be assigned a jwt with embedded issuer, claims and scope, and redirected to the redirection uri via OIDC in order to access the resource previously requested.

* 3. Clients that have previously authenticated with the authorization service and initiate the requet with an authorization header containing a jwt. The issuer signature within the jwt is verified and the claims and scope extracted and authorized for the resource being accessed. This authorization can either be done with built-in policies, or via external authorization plugins (e.g., Open Policy Agent/OPA) using policy schema defined for the plugin (e.g., OPA rego).

## Audit

The built-in observability features provide detailed identity-enriched logs, telemetry and dashboards, as described in the [Observability](/docs/observability-dashboards) docs.


For example, logs listing the authorized or unauthorized identities accessing the application can be listed as below:
``` 
$ kubectl logs -n bookstore -l "app=AppName" -f |grep AUTHORIZED
16:35:00 [[QM]] WARN Ext_AuthZ/OPA "JWT Claims <CLAIM> not Authorized for Scope <SCOPE>" UNAUTHORIZED policy=extauth-opa
16:35:01 [[QM]] WARN Unknown Identity UNAUTHORIZED policy=default
```

## ASDEX Score

![Dashboard with mTLS Telemetry](/images/desktop/mtls-asdex-dashboard.png)

The product computes a simple **Application Security Index (ASDEX)** score for applications within the observability metrics and dashboards. This is a simple measure of how many of the inbound requests accessing the app are considered to be less secured or better secured relative to the total number of inbound accesses. The value is a number between 0.00 and 1.00. A lower value indicates that a greater proportion of inbound transactions are from clients lacking identity, policy, additional security defenses, or a combination of these. 

The desired objective for apps would be to get as close to 1.00 as possible. While a score of say 0.99 is not an absolute guarantee of perfect security, it provides some assurance that inbound transactions are associated with an attested client workload identity, is governed by a policy vetted by the organization, and has additional security defense-in-depth controls that have analysed the connection.

The ASDEX score is highlighted throughout the dashboards as well, providing an at-a-glance view of the percentage of inbound requests to an application that can be considered to be relatively suspicious or risky.



