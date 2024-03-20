

# QuickStart


QuicSec functions as middleware for your application. The steps involved in adoption quicsec are:

- [Porting](https://quicsec.io/docs/porting) your application to use QuicSec, typically with the one line change illustrated in the [Porting](/docs/porting) guide.

- Optionally, [Configuring](https://quicsec.io/docs/configure) non-default values for configuration if necessary.

- [Using](https://quicsec.io/docs/use) QuicSec and benefiting from it for various use cases. 


## [Demo Example](https://quicsec.io/docs/example-bookstore): Bookstore Microservice Applications

To illustrate the benefits of QuicSec, the bookstore microservice application has been ported to use QuicSec. 

Following the [example](https://quicsec.io/docs/example-bookstore) will provide a quick walkthrough of how QuicSec works to: 

* Migrate the microservices to http/3 (while maintaining http/1.1 compatibility for legacy transition). 

* Automatically taking care of identity and certificate management workflows

* Security with Identity-based TLS or mTLS policies. 

* Optionally other security features can be enabled via plugins, including client authentication (via Auth0/Okta or other OIDC platform integration) using JWT workflows, Policy Authorization (using OPA), WAAP/WAF for defense-in-depth, etc..

* QuicSec leverages the ext_authz framework to enable additional plugins (thereby allowing any of the security plugins enabled for the envoy proxy, but now natively into the app within the http layer and without needing a proxy).

* Observability for the application with automatic logs and metrics.


