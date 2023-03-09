
## Porting Golang HTTP/1.1 apps to HTTP/3

The steps below describe how to use QuicSec middleware to allow your http/1 service or client to be updated to support http/3.

At the moment, QuicSec supports golang applications, using net/http. Support for other language bindings and language-independent bindings will be released soon. There are no platform, kernel or OS dependencies - QuicSec middleware runs wherever your application does.

### HTTP Service

1. Import the quicsec package

```
import "github.com/quicsec/quicsec"
```

2. Update calls to http.ListenAndServe to quicsec.ListenAndServe

![Update HTTP Service](/images/desktop/quicsec-listen-and-serve.png)

An example of updating a http service from http1 to now supporting http1 and http3 listeners simultaneously is illustrated by the change in bookstore.go in the bookstore example within this [commit](https://github.com/quicsec/quicsec/commit/462e3a21dcd92ddf68246d889d0eb82722df20ae?diff=split#diff-f231874fc1fc2fbb45ba7b0adc5896d738300bce5d870fe37974c98f6be11d42).

QuicSec middleware will enable the service to now support http/3 (on QUIC/UDP) in addition to maintaining your existing HTTP (on TCP) connection for not disrupting existing HTTP/1.1 or HTTP/2 clients. In addition, QuicSec will transparently inject security (Identity/certificate assignment, rotation, and optional client authentication/authorization for mTLS) as well as observability (metrics, logs), so your app can benefit from automatic security and observability.


### HTTP Client

1. Import the quicsec package

```
import "github.com/quicsec/quicsec"
```

2. Update calls to client.Do to quicsec.Do

![Update HTTP Client](/images/desktop/quicsec-client-do.png)

An example of updating a http service from http1 to now supporting http1 and http3 listeners simultaneously is illustrated by the change in books.go in the bookstore example within this [commit](https://github.com/quicsec/quicsec/commit/462e3a21dcd92ddf68246d889d0eb82722df20ae?diff=split#diff-dd840cf1fc528e1bc0bc916e87b6e8ab1be29e0227344cc2cb56f43d6d48943b).

The resulting http client will now send requests on HTTP/3 (on QUIC+UDP), and fall back to HTTP/1 if the request fails. QuicSec will transparently inject security (Identity/certificate assignment, rotation, and authentication/authorization) and observability (metrics, logs), so your app can benefit from automatically injected security and observability.


## Runtime Configuration Options

[Environment variables](QuicSec-ConfigurationManager-EnvVars.md) can be used to provide the runtime configuration to your application for QuicSec middleware operation.

Independent control planes (e.g., a Kubernetes operator) can be used to provide runtime QuicSec configuration. Details and an example will be provided soon.


