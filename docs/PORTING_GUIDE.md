
## Porting Golang HTTP/1.1 apps to HTTP/3

The steps below describe how to use QuicSec middleware to allow your http/1 service or client to be updated to support http/3.

At the moment, QuicSec supports golang applications, using net/http.

### HTTP Service

1. Import the quicsec package

```
import "github.com/quicsec/quicsec"
```

2. Update calls to http.ListenAndServe to quicsec.ListenAndServe

An example of updating a http service from http1 to now supporting http1 and http3 listeners simultaneously is illustrated by the change in bookstore.go in the bookstore example within
this [commit](https://github.com/quicsec/quicsec/pull/2/commits/b137f24c912cf06f737030f183a13785fe87e4f7).
![Commit example](/images/desktop/quicsec-listen-and-serve.png)

The resulting service will now listen simultaneously on HTTP/1.1 (on TCP) and HTTP/3 (on QUIC+UDP). 
QuicSec will transparently inject security (Identity/certificate assignment, rotation, and optional client authentication/authorization for mTLS) as well as observability (metrics, logs) based on dynamic configuration.


### HTTP Client

1. Import the quicsec package

```
import "github.com/quicsec/quicsec"
```

2. Update calls to client.Do to quicsec.Do

An example of updating a http service from http1 to now supporting http1 and http3 listeners simultaneously is illustrated by the change in books.go in the bookstore example within
this [commit](https://github.com/quicsec/quicsec/pull/2/commits/b137f24c912cf06f737030f183a13785fe87e4f7).
![Commit example](/images/desktop/quicsec-client-do.png)

The resulting http client will now send requests on HTTP/3 (on QUIC+UDP), and fall back to HTTP/1 if the request fails.
QuicSec will transparently inject security (Identity/certificate assignment, rotation, and authentication/authorization) and observability (metrics, logs) based on dynamic configuration.


## Runtime Configuration Options

[Environment variables](QuicSec-ConfigurationManager-EnvVars.md) provide the runtime configuration options for QuicSec.


