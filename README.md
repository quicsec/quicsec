# QuicSec

## Why



QuicSec middleware streamlines application migration to HTTP/3 and automates the injection of plugins for identity/certificate management and rotation, authentication/authorization and observability. The current QuicSec [Feature List](docs/Features.md) lists the current supported capabilities.

## Overview

Upgrading your application to HTTP/3 can be done in 3 steps
1. Build: Upgrade your HTTP library to QuicSec
2. Run: Install or Configure your identity management solution. 
* Define security policies
* Enable logs desired observability platform

## Detailed How To

1. Build

Upgrade your HTTP library to QuicSec [Detailed guide](https://github.com/quicsec/quicsec/blob/main/docs/PORTING_GUIDE.md)

```
import "github.com/quicsec/quicsec"

	bs := []string {listenAddr}

	err = quicsec.ListenAndServe(bs, router)
```

2. Run

* Install or Configure Cert-manager and cert-manager-csi-spiffe to enable workload identity certificate provisioning. [Detailed guide](https://github.com/quicsec/quicsec/blob/main/examples/bookstore/CERT-MANAGER.md)

* Define security policies
 TBD
 
* Enable logs desired observability platform
 TBD

## Sample App: Adding QuicSec to BookStore

### Running Applications with QuicSec

The [Bookstore Example](examples/bookstore/README.md) illustrates how a set of microservices can be migrated from HTTP/1 to HTTP/3 leveraging QuicSec, and in the process gaining automatic identity management (certificate injection and rotation), security (mTLS with AuthN/Z) and observability (metrics, logs, performance analysis).

### Porting Applications

The [Porting Guide](docs/PORTING_GUIDE.md) describes how to update your golang app to leverage QuicSec to update your http/1 golang app to support http/3.

Demo applications are provided in the Examples folder, including a Bookstore application example and a Simple-http3-client-and-server example.


