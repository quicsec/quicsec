# Security: Mutual TLS


Mutual TLS is enabled in a single step, which can be further automated to allow for zero-config security. 


The important element to enable mTLS is the identity of the workload, and it is enabled with the help of pluggable solutions like SPIFFE and cert-manager. Identity managemement (including cert provisioning/attestation, hourly rotation and validation) is completely automated. For mTLS, peer certificates are automatically validated as governed by policy.


## Architecture

The key ingredients for zero-trust security with mTLS are Identity, AuthN/Z, Encryption and Audit. These are all enabled in a single step, which can be further automated for zero-config security which follows the workload instantly across any platform, and independent of infrastructure. Enforcement is consistent across all appEdge bindings, including native/proxyless HTTP apps.

* Identity: enabled with the help of pluggable solutions like SPIFFE and cert-manager. Identity managemement (including cert provisioning/attestation, hourly rotation and validation) is completely automated.

* AuthN/Z: Policy resources guide whether a connection to a given peer is authorized. The solution automates requesting and verification of the peer certificate, and enforcing the policy claims aligned within the embedded identity. Policies can either leverage peer identity via annotations of the application deployment resource, or by using Identity Sets (idSets) providing a scalable way of managing identity-based Auth rules.

* Encryption: Automatically enabled for all flows. Even if mutual TLS is disabled, the solution will still enable one-way TLS where traffic is encrypted even if policy allows for open access from peers (including peers lacking identity).

* Audit: Metrics, logging and traces with identity-enriched metadata is collected for all flows and transactions. The [Observability](/docs/observability-dashboards) docs provide more background on audit and visibility with the build-in observability tools, or integration with existing SIEM/SOAR and other security tools used.

![Mutual TLS Architecture](/images/desktop/mTLS-scenarios.png)


No access to the client side is required to enable mTLS on a service. If a client has an existing workload x509 identity, the existing identity is used for mTLS policy. If the client lacks a workload identity, policy determines whether one-way TLS will be used to allow access from that client, or if mutual TLS will deny the client.


## Scenarios

The different scenarios to consider when building identity-defined mTLS policies are illustrated with the help of the architecture diagram above.

The types of client accesses to consider when building policies:

* 1. Clients that lack attested x509 identity. These can only be allowed if policy disables mTLS.

* 2. Clients that have an attested x509 identity, but are not allowed in policy. 

* 3. Clients that have an attested x509 identity, and are members of an allowed identity. This is the recommended option to ensure identity-defined security across the organization. Client-C in the architecture diagram above.


## Audit

The built-in observability features provide detailed identity-enriched logs, telemetry and dashboards, these can be integrated with existing Audit, GRC and SIEM platforms. 

For example, logs listing the authorized or unauthorized identities accessing the application can be listed as below:
``` 
$ kubectl logs -n bookstore -l "app=AppName" -f |grep AUTHORIZED
16:35:00 [[QM]] WARN SPIFFE "spiffe://cluster.local/ns/teamRed-NS/sa/team-Red-clientapp-R" UNAUTHORIZED policy=default
16:35:01 [[QM]] WARN SPIFFE "spiffe://cluster.local/ns/teamC-NS/sa/team-C-clientapp-Z" AUTHORIZED policy=strict
16:35:01 [[QM]] WARN Unknown Identity UNAUTHORIZED policy=default
```

If using the native, proxyless HTTP application bindings instead, then the audit logs will be provided via the application logs directly.

## ASDEX Score

![Dashboard with mTLS Telemetry](/images/desktop/mtls-asdex-dashboard.png)

The product computes a simple **Application Security Index (ASDEX)** score for applications within the observability metrics and dashboards. This is a simple measure of how many of the inbound requests accessing the app are considered to be less secured or better secured relative to the total number of inbound accesses. The value is a number between 0.00 and 1.00. A lower value indicates that a greater proportion of inbound transactions are from clients lacking identity, policy, additional security defenses, or a combination of these. 

The desired objective for apps would be to get as close to 1.00 as possible. While a score of say 0.99 is not an absolute guarantee of perfect security, it provides some assurance that inbound transactions are associated with an attested client workload identity, is governed by a policy vetted by the organization, and has additional security defense-in-depth controls that have analysed the connection.

The ASDEX score is highlighted throughout the dashboards as well, providing an at-a-glance view of the percentage of inbound requests to an application that can be considered to be relatively suspicious or risky.




