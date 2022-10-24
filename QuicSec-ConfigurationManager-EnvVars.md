# QuicSec - Environment Variables for Configuration

QuicSec settings can be configured on a given quicsec-enabled workload with environment variables. As an alternative, a more sophisticated platform specific control plane (e.g., a Kubernetes operator) can be used to update configuration state and policy rules with the configuration manager via an API.



## QuicSec Configuration Manager - Environment Variables
Configuration Manager is a component of QuicSec that unifies configuration of each of the QuicSec components.  It [configures quicsec](#general-configuration) via environment variables and also watches [AuthZ rules](#authz-rules) in the json file within the file path specified in QUICSEC_AUTHZ_RULES_PATH to maintain connection authentication and authorization rules.

Optionally, an external control plane (e.g., a Kubernetes operator) can maintain the configurations pertinent to the particular workload including authorization rules

### General configuration
All general configurations are done via env vars. It's possible to configure:

**1. Logger (info or debug mode)**
```
QUICSEC_LOG_DEBUG="0"                                   //default: 1
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

**6. Flag to enable mTLS and skip the verify**

If insecure skip verify is true, the client won't check the server certificate.
```
QUICSEC_MTLS_ENABLE="0"                                   //default: 1
QUICSEC_INSEC_SKIP_VERIFY="1"                             //default: 0
```

### AuthZ rules
The AuthZ rules are configuration via json [`config.json`](./config.json), with the location of the file being specified in the environment variable QUICSEC_AUTHZ_RULES_PATH. The quicsec is notified when there is a change in this file - in this way is possible to change the rules and quicsec will be notified with the latest authz rules. The URI from client must be authorized in the configuration to a request be accepted by the server.
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
