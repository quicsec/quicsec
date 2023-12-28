# Filter Chain

In the realm of web development and network programming, implementing a Filter Chain for HTTP requests via middleware is a pivotal strategy for enhancing and securing web applications. Middleware provides a convenient mechanism to insert layers of processing, allowing for flexible and powerful manipulation of HTTP requests and responses. This approach enables developers to efficiently apply various filters, each performing distinct functions, in a seamless and integrated manner.

## The Role of Filter Chain in Middleware

A Filter Chain, when implemented in HTTP middleware, serves multiple purposes:

- **Sequential Processing**: Requests pass through a sequence of filters, each performing its operation, such as validating input, logging requests, or applying security checks.
- **Modularity**: Middleware allows for the modular insertion or removal of filters without disrupting the core application logic.
- **Interception and Transformation**: Filters can intercept and optionally transform HTTP requests and responses, enabling dynamic handling based on specific conditions.

## Current Support for Filters
- **WAF Filter**: Utilizes [Coraza](https://github.com/corazawaf/coraza), a robust WAF (Web Application Firewall), to apply security rules and protect against common web vulnerabilities. 
- **ExtAuth Filter**: Based on [Open Policy Agent (OPA)](https://www.openpolicyagent.org/), it facilitates external authentication processes, ensuring secure access control.
- **OAuth2 Filter**: Implements the OAuth2 [authorization code flow](https://auth0.com/docs/get-started/authentication-and-authorization-flow/authorization-code-flow), providing robust authentication and authorization mechanisms.

## Implementation and Usage
- The middleware initializes by loading the configuration and creating filter instances as per the setup.
- Each incoming HTTP request is passed through the filter chain where individual filters execute their designated tasks.
- The dynamic nature of middleware allows for easy updating and extending of the filter chain to adapt to new requirements or changing security landscapes.

## Filter Chain Configuration
The configuration of the Filter Chain is defined in JSON format, which specifies the filters to be applied to HTTP requests. The key component of this configuration is the **"filters"** attribute. Here's an example of how this attribute is structured:

```
{
    "filters": {
        "waf": {
            "coraza": [
                "SecRule REQUEST_URI \"@contains admin\" \"id:1,phase:1,deny,status:403,msg:'Access to admin area is restricted',log,auditlog\"",
                "SecRule REQUEST_URI \"@contains demo\" \"id:2,phase:1,deny,status:403,msg:'Access to demo area is restricted',log,auditlog\""
            ]
        },
        "ext_auth": {
            "opa": {
                "url": "http://localhost:8181/v1/data/httpapi/authz",
                "auth": "pod8",
                "pass_jwt_claims": "enabled",
                "pass_svc_identity": "enabled",
                "pass_cli_identity": "enabled"
            }
        },
        "oauth2": {
            "client_id": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
            "client_secret": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
            "authz_endpoint": "https://dev-xxxxxxxxxxxxxxxx.us.auth0.com/",
            "token_endpoint": "/oauth/token",
            "redirect_url": "https://localhost:8443/callback",
            "scopes": []
        }
    }
}
```

### Understanding the "filters" Attribute

- Purpose: The "filters" attribute contains the configuration for each filter that will be part of the Filter Chain.
- Flexibility: You can configure multiple filters, and each filter can have its unique settings.

#### Types of Filters

**WAF Filter (Coraza)**:

- Configured Under: "waf" key.
- Implementation: Utilizes Coraza, a robust WAF.

Settings: Array of directives for request filtering.
- Rule: "SecRule REQUEST_URI \"@contains admin\" \"id:1,phase:1,deny,status:403,msg:'Access to admin area is restricted',log,auditlog\"" specifies a security rule for the WAF that prevents access to the path /admin. For more detailed info regarding directives please go to [Coraza](https://coraza.io/docs/seclang/directives/) docs.
- Customization: Add or remove rules based on security requirements.

**External Authentication Filter (OPA)**:

- Configured Under: "ext_auth" key.
- Implementation: Based on Open Policy Agent (OPA).

Settings:
- url: The URL of the OPA server for authorization decisions.
- auth: Authentication method or identifier. (not implemented yet)
- pass_jwt_claims: Option to enable passing JWT claims. (not implemented yet)
- pass_svc_identity: Enable passing service identity. (not implemented yet)
- pass_cli_identity: Enable passing client identity. (not implemented yet)
- Customization: Modify these settings to match the external authentication requirements.

**OAuth2 Filter**:

- Configured Under: "oauth2" key.
- Implementation: Manages OAuth2 authorization code flow.

Settings:
- client_id: The OAuth2 client identifier.
- client_secret: A secret key used for client authentication.
- authz_endpoint: Authorization server's endpoint URL.
- token_endpoint: Endpoint URL to obtain tokens.
- redirect_url: URL to redirect users after authentication.
- scopes: An array of scopes for OAuth2.


##  Config Sample With Filters

```
{
    "version": "v1alpha2",
    "service_conf": [
        {
            "conf_selector": "127.0.0.1",
            "policy": {
                "spiffe://anotherdomain.foo.bar/foo/bar": {
                    "authz": "allow",
                    "filters": {
                        "waf": {
                            "coraza": [
                                "SecRule REQUEST_URI \"@contains admin\" \"id:1,phase:1,deny,status:403,msg:'Access to admin area is restricted',log,auditlog\"",
                                "SecRule REQUEST_URI \"@contains demo\" \"id:2,phase:1,deny,status:403,msg:'Access to demo area is restricted',log,auditlog\""
                            ]
                        },
                        "ext_auth": {
                            "opa": {
                                "url": "http://localhost:8181/v1/data/httpapi/authz",
                                "auth": "pod8",
                                "pass_jwt_claims": "enabled",
                                "pass_svc_identity": "enabled",
                                "pass_cli_identity": "enabled"
                            }
                        },
                        "oauth2": {
                            "client_id": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
                            "client_secret": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
                            "authz_endpoint": "https://dev-xxxxxxxxxxxxxxxx.us.auth0.com/",
                            "token_endpoint": "/oauth/token",
                            "redirect_url": "https://localhost:8443/callback",
                            "scopes": []
                        }
                    }
                }
            },
            "mtls": {
                "client_cert": true
            }
        }
    ]
}

```