# Bookstore Demo

This demo shows a simple bookstore app, copied over from the OSM demo.

## Building

To build the docker images, update Makefile with the desired container registry and tag.

```
make docker-build-demo
```


## Running the Demo

### 1. Deploy K8s


Ensure that cert-manager is running. If you don't already have cert-manager deployed, then run

```
DEPLOY cert-manager: INSTRUCTIONS TO BE PROVIDED
```


### 2. Deploy Contour ingress

```
kubectl apply -f contour/
```


### 3. Deploy Bookstore demo

Create kubernetes-manifests/10-secrets.yaml with pull secrets for pulling bookstore docker images

Apply the manifests.

```
kubectl apply -f kubernetes-manifests/
```
