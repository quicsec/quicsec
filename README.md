# QuicSec

QuicSec middleware streamlines application migration to HTTP/3 and automates the injection of plugins for identity/certificate management and rotation, authentication/authorization and observability.
The [QuicStart](#quicstart) section provides an example of how to use QuicSec in practice

The current QuicSec [Feature List](docs/Features.md) lists the current supported capabilities.

## QUICstart

### Running Applications with QuicSec

The [Bookstore Example](examples/bookstore/README.md) illustrates how a set of microservices can be migrated from HTTP/1 to HTTP/3 leveraging QuicSec, and in the process gaining automatic identity management (certificate injection and rotation), security (mTLS with AuthN/Z) and observability (metrics, logs, performance analysis).

### Porting Applications

The [Porting Guide](docs/PORTING_GUIDE.md) describes how to update your golang app to leverage QuicSec to update your http/1 golang app to support http/3.

Demo applications are provided in the Examples folder, including a Bookstore application example and a Simple-http3-client-and-server example.


