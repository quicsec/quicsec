# QuicSec

## Why



QuicSec middleware streamlines application migration to HTTP/3 and automates the injection of plugins for identity/certificate management and rotation, authentication/authorization and observability. The current QuicSec [Feature List](docs/Features.md) lists the current supported capabilities.

## Overview

Upgrading your application to HTTP/3 can be done in 3 steps
1. Build: Import QuicSec HTTP library  
2. Run with automated identity & security policies & observability & connection management


## Detailed How To

1. Build

Update your HTTP applications with QuicSec Middleware [Detailed guide](https://github.com/quicsec/quicsec/blob/main/docs/PORTING_GUIDE.md)

![Update HTTP Service](https://quicsec.io/images/desktop/quicsec-listen-and-serve.png)

```
import "github.com/quicsec/quicsec"

	err = quicsec.ListenAndServe(listenAddr, router)
```

2. Run

Enable identity, security and observability plugins dynamically at runtime.

* Enable pluggable workload identity management solutions (E.g., [cert-manager-csi-spiffe](https://github.com/quicsec/quicsec/blob/main/examples/bookstore/CERT-MANAGER.md))
* (Optional) Enable pluggable security policies (link)
* (Optional) Integrate with runtime observability platforms for log aggregation, telemetry/dashboards and operations (link)

## Sample App: Adding QuicSec to BookStore

### Running Applications with QuicSec

The [Bookstore Example](examples/bookstore/README.md) illustrates how a set of microservices can be migrated with a one-line change to add HTTP/3 support, and in the process gain automatic identity management (certificate injection and rotation), security (mTLS with AuthN/Z) and observability (metrics, logs, performance analysis).

In addition, application access over HTTP/3 improves latency by up to a third vs using previous versions of HTTP.
