# QuicSec

QuicSec middleware allows for applications to be migrated to HTTP/3 while automating the injection of plugins for identity/certificate management and rotation, authentication/authorization and observability.
The [QuicStart](#quicstart) section below provides an example of how to use QuicSec in practice

As of the current release, QuicSec includes support for the current options:

**Language Bindings**

* Golang
* (in development) Java
* (in development) Node.js
* (planned) python
* (planned) rust
* (contributions welcome) other

**Identity Plugins** 

Workload identity (Certificate) injection and rotation using
* Cert-manager
* Cert-manager-csi-spiffe


**Security (mTLS AuthN/Z)**

AuthZ Policies
* Simple ALLOW policy list
* (planned) Pluggable policy frameworks

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

## QUICstart

### Running Applications with QuicSec

The [Bookstore Example](examples/bookstore/README.md) illustrates how a set of microservices can be migrated from HTTP/1 to HTTP/3 leveraging QuicSec, and in the process gaining automatic identity management (certificate injection and rotation), security (mTLS with AuthN/Z) and observability (metrics, logs, performance analysis).

### Porting Applications

The [Porting Guide](PORTING_GUIDE.md) describes how to update your golang app to leverage QuicSec to update your http/1 golang app to support http/3.

Demo applications are provided in the Examples folder, including a Bookstore application example and a Simple-http3-client-and-server example.


