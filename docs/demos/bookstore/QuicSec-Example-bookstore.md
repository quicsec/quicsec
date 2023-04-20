# Bookstore Demo - on Kubernetes

This example provides a simple bookstore demo, consisting of a set of microservices to illustrate QuicSec: 


(User or Ingress) --> Bookbuyer|Bookthief --> Bookstore --> Bookwarehouse --> MySQL-DB

![Bookstore Microservices Example](https://quicsec.io/images/desktop/Bookstore-baseline-before-quicsec.png)


## A. Cluster Installation

Deploy a Kubernetes cluster for the demo.


## B. Cert-Manager (and cert-manager-csi-spiffe) Installation

We recommend ensuring that your cluster does not already have a pre-existing cert-manager installed, since we will install it now with the auto-approver disabled (as specified in the cert-manager documentation for cert-manager-csi-spiffe).

1. [Install Cert-manager and cert-manager-csi-spiffe](https://quicsec.io/docs/cert-manager) to enable workload identity certificate provisioning via QuicSec to the bookstore demo components.

## C.  Install Bookstore application (with quicsec integration)

Note that the steps below refer to a pull-secrets.yaml that provides access to the bookstore demo containers within the quicsec repository.

Deploy manifests to create the namespaces for the bookstore demo (bookwarehouse, bookstore, bookbuyer and bookthief), the pull secrets to pull the relevant demo images from the quicsec repository and the bookstore demo application manifests.

```
kubectl apply -f kubernetes-manifests/bookstore-manifests/
```

## D. Enable bookstore access to the outside world

The simplest way to access the UI of the bookbuyer/bookthief microservices is with a kubectl port-foward.

```
kubectl port-forward -n bookbuyer deploy/bookbuyer-v3 8080:14001 &
kubectl port-forward -n bookthief deploy/bookthief-v3 8081:14001 &
```

Now, if you point your browser at localhost:8080 and another browser tab at localhost:8081, you should see the UI for bookbuyer and bookthief respectively, similar to the screenshot below, and showing the count of books incrementing from specific versions of bookstore deployments that bookbuyer/bookthief are accessing.


![Bookbuyer microservice UI](https://quicsec.io/images/desktop/bookbuyer-bookthief-screenshot.png)

The count of books indicates how many copies of books have been purchased (or stolen) from each version of the bookstore microservice. Since only bookstore-v1 has been deployed so far, you will find that the count for Bookstore-v2 stays at zero.

Alternatively, if you prefer to use an IngressGateway rather than kubectl port-forward to access the bookbuyer/bookthief demo microservice UI, ingress-gateway examples are provided for [the Contour IngressGateway](https://quicsec.io/docs/example-bookstore/bookstore-via-contour)


##  E. Demo Scenarios

### 1. Automatic Migration to HTTP/3

By virtue of building the bookstore app with QuicSec (quicsec.listenAndServe instead of http.listenAndServe), the application has been already transitioned to http/3 from http/1.

You will see (encrypted) traffic flowing on UDP port 14001 if you look at packet captures from the app.

### 2. Identity/Certificate Management

QuicSec works in concert with the Identity plugin (Cert-manager-CSI-SPIFFE) in the bookstore example above to automatically perform all certificate lifecycle tasks pertinent to the application (certificate provisioning, rotation, certificate validation and CA verification).

### 3. Connection Authentication and Authorization.

![Bookstore Microservices Example](https://quicsec.io/images/desktop/Quicsec-mTLS.png)

To enable mutual TLS (i.e., client authentication) instead of one-way TLS, update QUICSEC_MTLS_ENABLE to 1 in kubernetes-manifests/bookstore-manifests/43-bookstore-v3.yaml and reapply.

To change the permitted client identities allowed to access the bookstore service, update the spiffe uri's or dns names that are required in the presented client certificates.

You will notice that after the bookstore pod is updated, the count of books for bookbuyer will increment again, but the count of books for bookthief will stop. The logs for the bookstore pod will indicate the mTLS auth failure in logs.

![Bookbuyer microservice UI](https://quicsec.io/images/desktop/quicsec-auth-failure-log.png)

This demonstrates Mutual TLS for applications, highlighting the simplicity of leveraging QuicSec for mTLS.
### 4. Observability

![Bookstore Microservices Example](https://quicsec.io/images/desktop/Quicsec-observability.png)

QuicSec automatically collects logs and metrics of all http accesses on behalf of the application, and can be integrated with 3rd party observability platforms. The sample manifests below deploy an example Prometheus, Loki and Grafana instance to provide an example set of dashboards to display metrics, logs and a service graph visualization for QuicSec collected logs and metrics.

```
kubectl apply --server-side -f kubernetes-manifests/metrics/operator
kubectl apply -f kubernetes-manifests/metrics/
```

Access the dashboards using the port forward below, and connecting your browser to localhost:3000 and logging in with admin:admin credentials, and browsing to the various dashboards available, or the Explore tab to view the consolidated http logs for the application.
```
kubectl port-forward -n qm-monitoring prometheus-prometheus-0 9090:9090 &
kubectl port-forward -n qm-monitoring deploy/grafana 3000:3000 &
```


#### 4.A. Prometheus

- Prometheus telemetry can be scraped from the port configured in the [env vars](/docs/env-vars) (tcp port 9090 by default). 


#### 4.B. OpenTelemetry 

- The opentelemetry](https://opentelemetry.io) collector can be used to scrape metrics, and as a destination for access, security and error logs collected by QuicSec on behalf of the application workload. Metrics can be scraped from the port configured in the [env vars](https://quicsec.io/docs/env-vars) (tcp port 9090 by default).

#### 4.C. Logs

- Raw logs can be configured to be sent as part of stdout (so it's available as part of the container logs in container platforms), or can be configured to be written to a file. QuicSec Config Manager retrieves it's configuration options from [environment variables](https://quicsec.io/docs/env-vars). 

