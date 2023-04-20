
## Access Bookstore Demo app via Ingress

If you would prefer to access the bookbuyer/bookthief microservices of the Bookstore Demo app from your browser using an IngressGateway rather than via _kubectl port-forward_, then instructions are provided below for the Contour ingress gateway. Other ingress controllers can be used in a similar manner.

```
kubectl apply -f kubernetes-manifests/contour/
```

In case the ingress resource creation fails the first time, it's likely because the contour pods haven't yet started up. Rerun the "kubectl apply -f kubernetes-manifests/contour/ " command.

To access the bookbuyer and bookthief from your browser, create /etc/hosts entries in your desktop for bookbuyer.com and bookthief.com with an IP address output from the command below. Sometimes (e.g., with AWS Load Balancers), it might take a few minutes for the load balancer to create DNS entries, so the command below might only return IP addresses after 2 or 3 minutes.

```
dig +noall +answer +short $(kubectl get services --namespace projectcontour envoy \
  --output jsonpath='{.status.loadBalancer.ingress[0].hostname}')
```

You should now be able to access the Bookbuyer and Bookthief microservices from your browser by visiting bookbuyer.com and bookthief.com. Each should display a UI similar to the picture below.

![Bookbuyer microservice UI](https://quicsec.io/images/desktop/bookbuyer-screenshot.png)

The count of books indicates how many copies of books have been purchased (or stolen) from each version of the bookstore microservice. 





