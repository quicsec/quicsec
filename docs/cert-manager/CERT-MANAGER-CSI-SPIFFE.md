
## Installing Cert-manager-CSI-SPIFFE

1. Install cert-manager with approver disabled in the controller.


Install cert-manager with approver disabled (as described in the cert-manager-csi-spiffe documentation).
```
helm repo add jetstack https://charts.jetstack.io --force-update

helm upgrade -i -n cert-manager cert-manager jetstack/cert-manager \
    --set extraArgs={--controllers='*\,-certificaterequests-approver'} --set installCRDs=true --create-namespace
```

2. Deploy clusterIssuer to issue certificates via cert-manager-csi-spiffe, and approve 

Install cert-manager-csi-spiffe clusterIssuer and approve certificateRequest. You might need to install [cmctl](https://cert-manager.io/docs/reference/cmctl/).
```
kubectl apply -f kubernetes-manifests/cert-manager-csi-spiffe/10-csi-spiffe-cluster-issuer.yaml
cmctl approve -n cert-manager $(kubectl get cr -n cert-manager -ojsonpath='{.items[0].metadata.name}')
```

3. **Optional** Install any optional components that might rely on cert-manager (e.g., aws-load-balancer-controller, etc.), and sign any created certificateRequests.

If you have any other optional components that rely on cert-manager, now is a good time to deploy them and approve cert-manager issuers/clusterissuers for them. For example, the step below illustrates the process to deploy the AWS Load Balancer Controller for Kubernetes, which relies on cert-manager.

```
kubectl apply -f infra/aws-load-balancer-controller-v2_4_4_full.yaml
kubectl cert-manager approve -n kube-system $(kubectl get cr -n kube-system -ojsonpath='{.items[0].metadata.name}')
```

4. Install cert-manager-csi-spiffe

If deploying on OpenShift, ensure that the appropriate security context constraints are mapped to the csi-driver-spiffe service account. For other kubernetes platforms besides OpenShift, simply deploy the csi-driver-spiffe as described below.


```
# OPENSHIFT ONLY
# Security Context Constraints required for serviceAccount used by cert-manager csi-driver-spiffe daemonset

oc adm policy add-scc-to-user privileged -n cert-manager -z cert-manager-csi-driver-spiffe

# ALL PLATFORMS - Deploy csi-driver-spiffe using helm chart

helm upgrade -i -n cert-manager cert-manager-csi-driver-spiffe jetstack/cert-manager-csi-driver-spiffe --wait \
    --set "app.logLevel=1" --set "app.trustDomain=cluster.local"  \
    --set "app.approver.signerName=clusterissuers.cert-manager.io/csi-driver-spiffe-ca"  \
    --set "app.issuer.name=csi-driver-spiffe-ca"  --set "app.issuer.kind=ClusterIssuer" \
    --set "app.issuer.group=cert-manager.io"  --set "app.driver.volumes[0].name=root-cas" \
    --set "app.driver.volumes[0].secret.secretName=csi-driver-spiffe-ca" \
    --set "app.driver.volumeMounts[0].name=root-cas" \
    --set "app.driver.volumeMounts[0].mountPath=/var/run/secrets/cert-manager-csi-driver-spiffe" \
    --set "app.driver.sourceCABundle=/var/run/secrets/cert-manager-csi-driver-spiffe/ca.crt"
```


5. (OpenShift ONLY) Label CSIDriver

```
oc label CSIDriver spiffe.csi.cert-manager.io security.openshift.io/csi-ephemeral-volume-profile=restricted
```

