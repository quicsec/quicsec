# QuicSec Features 

As of the current release, QuicSec includes support for the current options:

**Language Bindings**

* Golang
* (in development) C/C++
* (in planning) Java
* (in planning) Node.js
* (planned) python
* (planned) rust
* (contributions welcome) other

**Identity Plugins** 

Workload identity (Certificate) injection and rotation using
* Cert-manager
* Cert-manager-csi-spiffe


**Security (mTLS AuthN/Z)**

AuthZ Policies
* Transparent auto-mTLS
* Connection AuthZ: Simple ALLOW policy list based on SPIFFE URI's or DNS fqdn's in client certificate SAN
* (planned) Transaction AuthZ and policies
* (planned) Wildcard policies
* (planned) Label-based policies
* (contributions welcome) Pluggable higher-level policy frameworks

**Observability**

Logging
* Logging security authN/Z failures
* Logging security errors
* Logging transaction metadata
* Structured logs using golang zap, to file or stdout
* (in development) Opentelemetry log collection

Telemetry
* Transaction round trip time (rtt)
* Transaction errors and error rates
* (in development) Opentelemetry collector


Metrics
* Counts of transaction metrics
* Counts of connection metrics
* Counts of security metrics
* Prometheus endpoint
* (in development) Opentelemetry collector

Tracing
* (in development) Trace header injection


Performance Analysis
* (in development) client-side http and dns request latency tracing
* (in development) server-side application response time and client authentication latency tracing

**Connection Management**
* QUIC connection setup and teardown
* Backward compatibility with http/1.1 or http/2 on TCP connection setup and teardown
* (planned) Connection ID management



