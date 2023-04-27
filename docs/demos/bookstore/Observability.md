# Observability for QuicSec-enabled apps

QuicSec automatically generates HTTP logs and metrics on bewhalf of the applicaion using QuicSec. In addition, a sample Loki, Prometheus and Grafana deployment is provided by QuicSec to allow for simple out-of-the-box observability, although many organizations might consider integrating with their existing Observability platforms and dashboards instead.

Additional observability options can be constructed as wasm plugins and plugged into QuicSec. 

# Observability Addon Deployment

Deploying the provided Addons enable an instance of Prometheus and Grafana to be deployed for observing various relevant telemetry and logs.

```
kubectl apply -f --server-side kubernetes-manifests/metrics/operator
kubectl apply -f kubernetes-manifests/metrics/
```

Grafana, Prometheus and Loki can now be accessed via port-forward.

```
kubectl port-forward -n qm-monitoring deploy/grafana 3000:3000 &
kubectl port-forward -n qm-monitoring deploy/loki 3100:3100 &
kubectl port-forward -n qm-monitoring prometheus-prometheus-0 9090 &
```

Now the respective Grafana, Loki and Prometheus dashboards can be accessed at http://localhost:3000/, http://localhost:3100/ and https://localhost:9090/ - Grafana ought to be sufficient, and prometheus and loki are optional, since metrics and logs can be viewed from within Grafana.

## Dashboard (Grafana)

![QuicSec Grafana Service Map](/images/desktop/Quicsec-service-map.png)

The Dashboard can be accessed using the port specified in the port-forward above. Login using the admin:admin credentials, and browse available dashboards to find the QuicSec Dashboard as well as the QuicSec Service Map.

## Logs (Loki)

Logs can be viewed from the Grafana dashboard by clicking on the **Explore** option in Grafana, and selecting Loki as the source in the dropdown, and selecting the app or container name to view logs.

![Loki logs](/images/desktop/Quicsec-loki-logs.png)

Direct access to Loki can also be used if desired using the port-foward path above.

Logging verbosity and output location is configured via environment variables, QUICSEC_LOG_FILE_PATH and QUICSEC_LOG_DEBUG as outlined in the [configuration parameters](/docs/env-vars).


Accessing HTTP Logs on behalf of your app can be done by visiting grafana (localhost:3000 when using the port-forward step described above), and going to the Explore tab on the left bar. 

## Metrics (Prometheus)

Prometheus telemetry is collected automatically by QuicSec, and can be scraped by Prometheus or other telemetry collectors. The port on which metrics can be scraped is configured by QUICSEC_METRICS_ENABLE and QUICSEC_PROMETHEUS_BIND as outlined in the [configuration parameters](/docs/env-vars).





