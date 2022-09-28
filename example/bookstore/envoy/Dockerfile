FROM envoyproxy/envoy:v1.22.2

COPY envoy.yaml /etc/envoy/envoy.yaml

ENTRYPOINT ["envoy", "-c",  "/etc/envoy/envoy.yaml"]
