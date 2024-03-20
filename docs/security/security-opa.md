# Security: Open Policy Agent (OPA) Filter

## Overview

Open Policy Agent (OPA) can be used for flexible and dynamic policy authorization, and can be included as part of the AppEdge filter chains on behalf of the application. 

Any existing ext_authz filter can be attached to the AppEdge filter chain, and the example below illustrates how OPA authorization can be attached as an AppEdge filter, enabling any dynamic rego-based policy to be used together with the OPA authorizer.

## Architecture

![Open Policy Agent / OPA Filter](/images/desktop/opa-architecture.png)





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



