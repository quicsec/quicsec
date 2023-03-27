# Bookstore Demo - on Kubernetes

This example provides a simple bookstore demo, consisting of a set of microservices to illustrate QuicSec: 


(User or Ingress) --> Bookbuyer|Bookthief --> Bookstore --> Bookwarehouse --> MySQL-DB

## A. Cluster Installation

Deploy a Kubernetes cluster for the demo.


## B. Cert-Manager (and cert-manager-csi-spiffe) Installation

We recommend ensuring that your cluster does not already have a pre-existing cert-manager installed, since we will install it now with the auto-approver disabled (as specified in the cert-manager documentation for cert-manager-csi-spiffe).

1. [Install Cert-manager and cert-manager-csi-spiffe](CERT-MANAGER.md) to enable workload identity certificate provisioning via QuicSec to the bookstore demo components.

## C.  Install Bookstore application (with quicsec integration)

Note that the steps below refer to a pull-secrets.yaml that provides access to the bookstore demo containers within the quicsec repository.

Deploy manifests to create the namespaces for the bookstore demo (bookwarehouse, bookstore, bookbuyer and bookthief), the pull secrets to pull the relevant demo images from the quicsec repository and the bookstore demo application manifests.

```
kubectl apply -f kubernetes-manifests/namespaces/
kubectl apply -f kubernetes-manifests/<pull-secrets.yaml>
kubectl apply -f kubernetes-manifests/bookstore-manifests/
```

## D. Access bookbuyer and bookthief microservices

The simplest way to access the UI for the bookbuyer and bookthief microservices is via kubectl port-foroward

```
kubectl port-forward -n bookbuyer deploy/bookbuyer-v3 8080:14001 &
kubectl port-forward -n bookthief deploy/bookthief-v3 8081:14001 &
```

Now you should be able to access bookbuyer and bookthief microservices by pointing your browser at localhost:8080 and localhost:8081, and see a UI similar to the screenshot below.

INSERT LINK TO BOOKBUYER AND BOOKTHIEF SCREENSHOTS HERE

You will notice the count of books purchased (or stolen) incrementing, indicating successful access of the bookstore microservice from bookbuyer/bookthief.

### OPTIONAL: Access bookbuyer and bookthief via Ingress

Optionally, if you prefer to not use kubectl port-forward, you can deploy an ingress to access the bookbuyer and bookthief microservices. Ingress examples are provided for the contour ingress controller below. 
```
# OPTIONAL - NOT REQUIRED IF YOU USE kubectl port-forward
#
# kubectl apply -f kubernetes-manifests/contour/
```

To access the bookbuyer and bookthief from your browser, create /etc/hosts entries in your desktop for bookbuyer.com and bookthief.com with an IP address output from the command below. Sometimes (e.g., with AWS Load Balancers), it might take a few minutes for the load balancer to create DNS entriess, so the command below might only return IP addresses after 2 or 3 minutes.

```
dig +noall +answer +short $(kubectl get services --namespace projectcontour envoy \
  --output jsonpath='{.status.loadBalancer.ingress[0].hostname}')
```

##  E. Demo Scenarios

### 1. Automatic Migration to HTTP/3

By virtue of building the bookstore app with QuicSec (quicsec.listenAndServe instead of http.listenAndServe), the application has been already transitioned to http/3 from http/1.


### 2. Connection Authentication and Authorization.

To enable mutual TLS (i.e., client authentication) instead of one-way TLS, update QUICSEC_MTLS_ENABLE to 1 in kubernetes-manifests/bookstore-manifests/43-bookstore-v3.yaml and reapply.

After reapplying, you will observe that the count of books in the bookthief UI will stop. Looking at the logs of the bookstore pod, you will observe that the auth errors are logged.

To change the permitted client identities allowed to access the bookstore service, update the spiffe uri's or dns names that are required in the presented client certificates.


### 3. Observability

If metrics (Prometheus, Grafana) are desired, then apply the manifests for these.

```
kubectl apply --server-side -f kubernetes-manifests/metrics/operator/
kubectl apply -f kubernetes-manifests/metrics/
```

To view the Prometheus or Grafana Dashboards, create a kubectl port-forward to access the services for those.

```
kubectl port-forward -n qs-monitoring svc/prometheus-operated 9090:9090 &
kubectl port-forward -n qs-monitoring svc/grafana 3000:3000 &
```

Point your browser to http://localhost:9090/ and http://localhost:3000/ respectively for Prometheus and Grafana respectively. Login to grafana initially using admin:admin credentials., and browse Dashboards under Default Dashboards.

