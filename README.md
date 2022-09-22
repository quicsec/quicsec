# Quicsec
Security wrapper for QUIC protocol.

This project uses [quic-go](https://github.com/lucas-clemente/quic-go) as QUIC implementation.

# QUICk start

## Server

Run the server app:

```
cd quicsec/examples/server
go run main.go -www ./www -bind localhost:4433 -v
```

## Client

Run the client app:

```
cd quicsec/examples/client
go run main.go -url https://localhost:4433/index.html
```

# Configuration Manager
The Configuration Manager is respossible to [configure the quicsec](#general-configuration) via env vars and also resposible to watch the [AuthZ rules](#authz-rules) in order to allow/deny mTLS.

## General configuration
All general configurations are done via env vars. It's possible to configure:

**1. Logger (info or verbose mode)**
```
QUICSEC_LOG_VERBOSE="0"                                 //default: 1
QUICSEC_LOG_FILE_PATH="/tmp/output.log"                 //default: ""
```
If `QUICSEC_LOG_FILE_PATH` is set to "", the stdout is automatically used.

**2. Flag to enable dump of pre shared secret and the path file**
```
QUICSEC_SECRET_FILE_PATH="./pre-shared-key.txt"         //default: ""
```
If `QUICSEC_SECRET_FILE_PATH` is set to "", no pre shared key is generated.

**3. Flag to enable qlog and the path directory**
```
QUICSEC_QLOG_DIR_PATH="/tmp/qlog/"                      //default: "./qlog/"
```
If `QUICSEC_QLOG_DIR_PATH` is set to "", no qlog is generated.

**4. Flag to enable tracing metrics using prometheus**

When metrics is enable (default), it's possible to export: counters (connection duration; transferred bytes recv/sent; packets recv/sent; handshake successful; and others) and TLS error. These metrics can be accessed via http by the prometheus (need to be configurade).
```
QUICSEC_METRICS_ENABLE="0"                              //default: 1
QUICSEC_PROMETHEUS_BIND="192.168.56.101:8080"           //default: ""
```
If `QUICSEC_PROMETHEUS_BIND` is set to "", the prometheus metrics won't be
avaiable via http.

**5. Certificate paths**

The certificates for both client/server are configurable via env vars:
```
QUICSEC_CERT_FILE="/path/to/server.pem"                 //default: "certs/cert.pem"
QUICSEC_KEY_FILE="/path/to/server.key"                  //default: "certs/cert.key"
QUICSEC_CA_FILE="/path/to/ca.pem"                       //default: "certs/ca.pem"
```

## AuthZ rules
The AuthZ rules are configuration via json [`config.json`](./config.json). The quicsec is notified when there is a change in this file - in this way is possible to change the rules and quicsec will be notified with the latest authz rules. The URI from client must be authorized in the configuration to a request be accepted by the server.
```
{
        "quicsec": {
                "authz_rules": [
                        "spiffe://demo.http3.page/quicmesh/client15/",
                        "spiffe://demo.http3.page/quicmesh/client03/",
                        "spiffe://example.http3.page/quicmesh/client31/"
                ]
        }
}
```
Inform the path for the authz rules using the following env vars:
```
QUICSEC_AUTHZ_RULES_PATH="/volume/config.json"              //default: "config.json"
```

In summary, the most important configurations are the following:
```
QUICSEC_CERT_FILE="/path/to/server.pem"
QUICSEC_KEY_FILE="/path/to/server.key"
QUICSEC_CA_FILE="/path/to/ca.pem"
QUICSEC_PROMETHEUS_BIND="192.168.56.101:8080"
QUICSEC_LOG_FILE_PATH="/tmp/output.log"
QUICSEC_AUTHZ_RULES_PATH="/volume/config.json"
```