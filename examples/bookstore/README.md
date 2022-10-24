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

## D. Enable bookstore access to the outside world

Deploy contour ingress-gateway for bookstore access externally, or adapt the manifests below for access from your north-south gateway of choice
```
kubectl apply -f kubernetes-manifests/contour/
```

In case the ingress resource creation fails the first time, it's likely because the contour pods haven't yet started up. Rerun the "kubectl apply -f kubernetes-manifests/contour/ " command.

To access the bookbuyer and bookthief from your browser, create /etc/hosts entries in your desktop for bookbuyer.com and bookthief.com with an IP address output from the command below. Sometimes (e.g., with AWS Load Balancers), it might take a few minutes for the load balancer to create DNS entriess, so the command below might only return IP addresses after 2 or 3 minutes.

```
dig +noall +answer +short $(kubectl get services --namespace projectcontour envoy \
  --output jsonpath='{.status.loadBalancer.ingress[0].hostname}')
```
