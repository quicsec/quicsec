# QuicSec Features 

As of the current release, QuicSec includes support for the current options:

**Language Bindings**

* Golang

**Identity Plugins** 

Workload identity (Certificate) injection and rotation using
* [Cert-manager](https://cert-manager.io/)
* [Cert-manager-csi-spiffe](https://cert-manager.io/docs/projects/csi-driver-spiffe/)


**Security (mTLS AuthN/Z)**

AuthZ Policies
* Transparent auto-mTLS
* Connection AuthZ: Simple ALLOW policy list based on SPIFFE URI's in peer certificate SAN

**Observability**

Logging
* Logging security authN/Z failures
* Logging security errors
* Logging transaction metadata
* Structured logs using golang zap, to file or stdout
* (in development) Opentelemetry log collection

Metrics
* Counts of transaction metrics
* Counts of connection metrics
* Counts of security metrics
* Transaction round trip time (rtt)
* Transaction errors and error rates
* Prometheus endpoint
* (in development) Opentelemetry collector


**Connection Management**
* QUIC connection setup and teardown
* Backward compatibility with setup and teardown of http/1.1 or http/2 connections on TCP
