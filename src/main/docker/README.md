# ADIdentity (A minimal JWT layer for AD)

This image starts a simple JWT token generator and verifier for successful login operations with an AD server as a backend.

## How to use this image

### Start an instance

```
$ docker run -p 8080:8080 5005:5005 deibynahuat/adidentity:<tag>
```
This will start a server with all default parameters. To configure check the variables below.

## Environment variables (AD Server)

To configure this image you can configure the following variables:

| Variable | Type | Default | Description |
| -------- | ---- | ------- | ----------- |
| ADIDENTITY_ADSERVER_DOMAIN | String | mydomain | An AD domain |
| ADIDENTITY_ADSERVER_HOST | String | myhost | An AD server without protocol |
| ADIDENTITY_ADSERVER_PORT | Integer | 389 | An AD server port |
| ADIDENTITY_ADSERVER_ORGUNIT | String | Users | Organizational unit assigned to users |
| ADIDENTITY_ADSERVER_USERNAME | String | aduser | An user used to query the AD server |
| ADIDENTITY_ADSERVER_PASSWORD | String | secret | Password used to query the AD server |

## Environment variables (Security)

| Variable | Type | Default | Description |
| -------- | ---- | ------- | ----------- |
| SECURITY_JWT_PRIVATEKEY | String | DEFAULT | A PEM encoded valid RSA key in PCKS8 format |
| SECURITY_JWT_SIGNATUREID | String | bacokey | A key identifier |
| MP_JWT_VERIFY_PUBLICKEY | String | DEFAULT | A PEM encoded public key. Must be a pair with the private key |
| MP_JWT_VERIFY_ISSUER | String | baco.adidentity | Issuer organization identifier |

