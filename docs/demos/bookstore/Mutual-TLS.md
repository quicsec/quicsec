# Mutual TLS for workloads with the built-in Policy Configurations

![Bookstore Microservices Example](https://quicsec.io/images/desktop/quicsec-kubernetes.png)

Mutual TLS can be enabled for a QuicSec-enabled service by setting the QUICSEC_MTLS_ENABLE environment variable to 1. 

When set, applications begin requesting client certifcates to authenticate client identity, and comparing the metadata contained within the client certificate SAN with the allowed Authz_rules specified in an external configmap, mounted at the path specified by QUICSEC_AUTHZ_RULES_PATH (/etc/quicsec/quicsec-config.json by default)

QuicSec clients _always_ verify that the certificate presented by the server matches the domain name of a given service, so it is not necessary to set MTLS_ENABLE for client workloads.

