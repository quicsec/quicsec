
## Installing Cert-Manager and Cert-manager-csi-spiffe

1. Install cert-manager with approver disabled in the controller.


Install cert-manager with approver disabled (as described in the cert-manager-csi-spiffe documentation).
```
helm repo add jetstack https://charts.jetstack.io --force-update

helm upgrade -i -n cert-manager cert-manager jetstack/cert-manager \
    --set extraArgs={--controllers='*\,-certificaterequests-approver'} --set installCRDs=true --create-namespace
```

2. Deploy clusterIssuer to issue certificates via cert-manager-csi-spiffe, and approve 

Install cert-manager-csi-spiffe clusterIssuer and approve. If you haven't previously integrated cert-manager with kubectl, you might need to [add](https://cert-manager.io/v1.5-docs/usage/kubectl-plugin/#installation) the cert-manager plugin to kubectl. Alternatively, install _cmctl_ according to cert-manager docs.
```
kubectl apply -f kubernetes-manifests/cert-manager/10-csi-spiffe-cluster-issuer.yaml
kubectl cert-manager approve -n cert-manager $(kubectl get cr -n cert-manager -ojsonpath='{.items[0].metadata.name}')
```

3. Sign Issuers for optional components that rely on cert-manager.

If you have any other optional components that rely on cert-manager, now is a good time to deploy them and approve cert-manager issuers/clusterissuers for them. For example, the step below illustrates the process to deploy the AWS Load Balancer Controller for Kubernetes, which relies on cert-manager.

```
# kubectl apply -f infra/aws-load-balancer-controller-v2_4_4_full.yaml
# kubectl cert-manager approve -n kube-system $(kubectl get cr -n kube-system -ojsonpath='{.items[0].metadata.name}')
```

4. Install cert-manager-csi-spiffe

Pay attention to the trust domain used below - this will be embedded within generated spiffeIDs and used within Auth rules.
```
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

