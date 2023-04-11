# QuicSec

## Why



QuicSec middleware streamlines application migration to HTTP/3 and automates the injection of plugins for identity/certificate management and rotation, authentication/authorization and observability. The current QuicSec [Feature List](docs/Features.md) lists the current supported capabilities.

## Overview

Upgrading your application to HTTP/3 can be done in 3 steps
1. Build: Import QuicSec HTTP library  
2. Run with automated identity & security policies & observability & connection management


## Detailed How To

1. Build

Update your HTTP call with QuicSec Middleware [Detailed guide](https://quicsec.io/docs/porting)

![Update HTTP Service](https://quicsec.io/images/desktop/quicsec-listen-and-serve.png)

2. Run

Enable identity, security and observability plugins dynamically at runtime.

* Enable pluggable workload identity solution (E.g., [cert-manager-csi-spiffe](https://github.com/quicsec/quicsec/blob/main/examples/bookstore/CERT-MANAGER.md))
* (Optional) Enable pluggable external security/policy engines and WAFs or use built-in [policy configuration](https://quicsec.io/docs/use-cases/mtls)
* (Optional) Integrate with runtime observability platforms for log aggregation, telemetry, dashboards or use built-in [observability platform example](https://quicsec.io/docs/use-cases/observability)

## Sample App: Adding QuicSec to BookStore

### Running Applications with QuicSec

The [Bookstore Example](https://quicsec.io/docs/example-bookstore) illustrates how a set of microservices can be migrated with a one-line change to add HTTP/3 support, and in the process gain automatic identity management (certificate injection and rotation), security (mTLS with AuthN/Z) and observability (metrics, logs, performance analysis).

In addition, application access over HTTP/3 improves latency by up to a third vs using previous versions of HTTP.
