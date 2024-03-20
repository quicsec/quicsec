# AppEdge Automatic Observability 

Automatic monitoring, logging, dashboarding and alerting is enabled for apps. Templates are generated for Prometheus, Loki, Alertmanager and Grafana to provide a simple batteries-included experience, but can be integrated with your organizational systems for observability.


# Observability Addon Deployment

Deploying the manifests below pulls down the standard upstream versions of Prometheus, Loki and Grafana from their upstream repositories.

```
kubectl apply -f --server-side kubernetes-manifests/metrics/operator
kubectl apply -f kubernetes-manifests/metrics/
```

Grafana, Prometheus and Loki can now be accessed via port-forward. Alternatively, an ingressgateway can be deployed for access (by **kubectl apply -f contour/60-ingress-grafana-prometheus-loki.yaml**)

```
kubectl port-forward -n qm-monitoring deploy/grafana 3000:3000 &
kubectl port-forward -n qm-monitoring deploy/loki 3100:3100 &
kubectl port-forward -n qm-monitoring prometheus-prometheus-0 9090 &
```
If an ingressgateway was used for these as mentioned above, then create a hosts (e.g., /etc/hosts) entry on your local system creating hostnames (qm-prometheus.com, qm-grafana.com) pointing to your gateway node IP. Then access Grafana and Prometheus from http://qm-grafana.com/ and http://qm-prometheus.com. 

If not, and you are using a port-forward, then the respective dashboards can be accessed at http://localhost:3000/, http://localhost:3100/ and https://localhost:9090/ - however, in this case the links within your grafana dashboard might not work.

## Logs (Loki)

![Loki logs](/images/desktop/quicmesh-loki-logs.png)

Accessing HTTP Logs on behalf of your app can be done by visiting grafana (localhost:3000 when using the port-forward step described above), and going to the Explore tab on the left bar. 



