# QuicSec - Configuration

QuicSec settings can be configured on a given quicsec-enabled workload with environment variables. As an alternative, a more sophisticated platform specific control plane (e.g., a Kubernetes operator) can be used to update configuration state and policy rules with the configuration manager via an API.

## QuicSec Configuration Manager
Configuration Manager is a component of QuicSec that unifies configuration of each of the QuicSec components.  It's possible to [configures quicsec](#general-configuration) via environment variables or via [Config rules](#config-rules) in the json file (path specified in QUICSEC_CORE_CONFIG). The [Config rules](#config-rules) is responsible to maintain authentication and authorization rules (this rules are constantly watches for changes - no need to restart application).

Optionally, an external control plane (e.g., a Kubernetes operator) can maintain the configurations pertinent to the particular workload including authorization rules

### General configuration
All general configurations are done via env vars. It's possible to configure:

**1. Logger (info or debug mode) and access logger (http request/response)**

Access logger is able to log both server and client side http request/respose information.

```
QUICSEC_LOG_DEBUG="0"                                   //default: 1
QUICSEC_LOG_PATH="/tmp/output.log"                      //default: ""
QUICSEC_HTTP_ACCESS_PATH="/var/log/access.log"          //default: ""
```
If `QUICSEC_LOG_PATH` is set to "", the stdout is automatically used.

**2. Flag to enable dump of pre shared secret and the path file**
```
QUICSEC_QUIC_DEBUG_SECRET_PATH="./pre-shared-key.txt"   //default: ""
```
If `QUICSEC_QUIC_DEBUG_SECRET_PATH` is set to "", no pre shared key is generated.

**3. Flag to enable qlog and the path directory**
```
QUICSEC_QUIC_DEBUG_QLOG_PATH="/tmp/qlog/"               //default: "./qlog/"
```
If `QUICSEC_QUIC_DEBUG_QLOG_PATH` is set to "", no qlog is generated.

**4. Flag to enable tracing metrics using prometheus**

When metrics is enable (default), it's possible to export: counters (connection duration; transferred bytes recv/sent; packets recv/sent; handshake successful; and others) and TLS error. These metrics can be accessed via http by the prometheus (need to be configurade).
```
QUICSEC_METRICS_ENABLE="0"                              //default: 1
QUICSEC_METRICS_BIND_PORT="8080"                        //default: ""
```
If `QUICSEC_METRICS_BIND_PORT` is set to "", the prometheus metrics won't be
avaiable via http.

**5. Certificate paths**

The certificates for both client/server are configurable via env vars:
```
QUICSEC_CERTS_CERT_PATH="/path/to/server.pem"           //default: "certs/cert.pem"
QUICSEC_CERTS_KEY_PATH="/path/to/server.key"            //default: "certs/cert.key"
QUICSEC_CERTS_CA_PATH="/path/to/ca.pem"                 //default: "certs/ca.pem"
```

**6. Flag to enable mTLS and skip the verify**

If insecure skip verify is true, the client won't check the server certificate.
```
QUICSEC_SECURITY_MTLS_ENABLE="0"                        //default: 1
QUICSEC_SECURITY_MTLS_INSEC_SKIP_VERIFY="1"             //default: 0
```

### Config rules
The Config rules are configuration via json [`config.json`](./config.json), with the location of the file being specified in the environment variable QUICSEC_CORE_CONFIG. The quicsec is notified when there is a change in this file - in this way is possible to change the configs and quicsec will be notified with the latest configs values.
```
{
    "version": "v1alpha2",
    "qm_service_conf": [
    {
		"server_instance_key": "192.168.0.10",
		"policy":{
				"spiffe://somedomain.foo.bar/foo/bar": {
				        "authz": "allow"
				},
				"spiffe://someotherdomain.foo.bar/foo/bar": {
				        "authz": "deny"
				}
		},
		"client_cert": true
    },{
		"server_instance_key": "192.168.0.11",
		"policy":{
				"spiffe://somedomain.foo.bar/foo/bar2": {
				        "authz": "allow"
				}
		},
		"client_cert": true
    }]
}
```
The policy rule is matched by the `server_instance_key` based on the address of an instance. This configuration file can thus be shared among instances. You can also configure Authorization (AuthZ) rules in this file. Under the `policy` section, it's possible to specify the URI from the client that must either be authorized (allow) or unauthorized (deny).

In order to enable/disable mTLS, just change the `client_cert` flag (true|false).

In summary, the most important configurations are the following:
```
QUICSEC_CERTS_CERT_PATH="/path/to/server.pem"
QUICSEC_CERTS_KEY_PATH="/path/to/server.key"
QUICSEC_CERTS_CA_PATH="/path/to/ca.pem"
QUICSEC_METRICS_BIND_PORT="192.168.56.101:8080"
QUICSEC_LOG_PATH="/tmp/output.log"
QUICSEC_CORE_CONFIG="/volume/config.json"
```
