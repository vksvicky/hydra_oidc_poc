# Proof of concept OpenID Connect / OAuth server with ORY Hydra

This repository contains a proof of concept implementation for an identity
provider and an application using OIDC. [ORY Hydra](https://www.ory.sh/hydra/)
is used for the actual OAuth2 / OpenID Connect operations. The implementation
in this repository provides the UI components that are required by Hydra.

## Setup

- create certificates for the IDP, the application and Hydra. You can use the
  testca from the [CAcert developer setup](https://git.dittberner.info/jan/cacert-devsetup)
  like this:

  1. create signing requests

     ```
     mkdir certs
     cd certs
     openssl req -new -newkey rsa:3072 -nodes \
       -keyout hydra.cacert.localhost.key \
       -out hydra.cacert.localhost.csr.pem \
       -subj /CN=hydra.cacert.localhost \
       -addext subjectAltName=DNS:hydra.cacert.localhost,DNS:auth.cacert.localhost
     openssl req -new -newkey rsa:3072 -nodes \
       -keyout idp.cacert.localhost.key \
       -out idp.cacert.localhost.csr.pem \
       -subj /CN=idp.cacert.localhost \
       -addext subjectAltName=DNS:idp.cacert.localhost,DNS:login.cacert.localhost,DNS:register.cacert.localhost
     openssl req -new -newkey rsa:3072 -nodes \
       -keyout app.cacert.localhost.key \
       -out app.cacert.localhost.csr.pem \
       -subj /CN=app.cacert.localhost \
       -addext subjectAltName=DNS:app.cacert.localhost
     cp *.csr.pem $PATH_TO_DEVSETUP_TESTCA/
     ```

  2. Use the CA to sign the certificates

     ```
     pushd $PATH_TO_DEVSETUP_TESTCA/
     for csr in hydra idp app; do
         openssl ca -config ca.cnf -name class3_ca -extensions server_ext \
         -in ${csr}.cacert.localhost.csr.pem \
         -out ${csr}.cacert.localhost.crt.pem -days 365
     done
     popd
     cp $PATH_TO_DEVSETUP_TESTCA/{hydra,idp,app}.cacert.localhost.crt.pem .
     ```

- install Hydra according to their documentation

- setup the Hydra database

  ```
  sudo -i -u postgres psql
  > CREATE DATABASE hydra_local ENCODING utf-8;
  > CREATE USER hydra_local WITH PASSWORD '${YOUR_POSTGRESQL_PASSWORD}';
  > GRANT CONNECT, CREATE ON DATABASE hydra_local TO hydra_local;

  hydra migrate sql "postgres://hydra_local:${YOUR_POSTGRESQL_PASSWORD}@localhost:5432/hydra_local"
  ```

- create a configuration file for Hydra i.e. hydra.yaml:

  ```
  serve:
    admin:
      host: hydra.cacert.localhost
    public:
      host: auth.cacert.localhost
    tls:
      cert:
        path: certs/hydra.cacert.localhost.crt.pem
      key:
        path: certs/hydra.cacert.localhost.key
  dsn: 'postgres://hydra_local:${YOUR_POSTGRESQL_PASSWORD}@localhost:5432/hydra_local'

  webfinger:
    oidc_discovery:
      supported_claims:
        - email
        - email_verified
        - given_name
        - family_name
        - middle_name
        - name
        - birthdate
        - zoneinfo
        - locale
        - https://cacert.localhost/groups
      supported_scope:
        - profile
        - email

  oauth2:
    expose_internal_errors: false

  urls:
    login: https://login.cacert.localhost:3000/login
    consent: https://login.cacert.localhost:3000/consent
    logout: https://login.cacert.localhost:3000/logout
    error: https://login.cacert.localhost:3000/error
    post_logout_redirect: https://login.cacert.localhost:3000/logout-successful
    self:
      public: https://auth.cacert.localhost:4444/
      issuer: https://auth.cacert.localhost:4444/

  secrets:
    system:
      - "${YOUR SECRET FOR HYDRA}"
  ```

- add entries for auth.cacert.localhost and hydra.cacert.localhost to /etc/hosts

  ```
  ::1 auth.cacert.localhost hydra.cacert.localhost
  ```

  This is required to allow Hydra to start properly

- create an OIDC client configuration for the demo application

  ```
  hydra clients create --endpoint https://hydra.cacert.localhost:4445/ \
    --callbacks https://app.cacert.localhost:4000/callback \
    --logo-uri https://register.cacert.localhost:3000/images/app.png \
    --name "Client App Demo" \
    --scope "openid offline_access profile email" \
    --post-logout-callbacks https://app.cacert.localhost:4000/after-logout \
    --client-uri https://register.cacert.localhost:3000/info/app
  ```

  the command returns a client id and a client secret that you need to
  configure for the demo application

- create a configuration for the IDP

  The IDP requires a strong random key for its CSRF cookie. You can generate
  such a key using the following openssl command:

  ```
  openssl rand -base64 32
  ```

  Use this value and create `idp.toml`:

  ```
  [security]
  csrf.key = "<32 bytes of base64 encoded data>"
  ```

- create a configuration for the Demo application

  You will need a 32 byte and a 64 byte random secret for the session
  authentication and encryption keys:

  ```
  openssl rand -base64 64
  openssl rand -base64 32
  ```

  ```
  [oidc]
  client-id = "<client id from hydra clients invocation>"
  client-secret = "<client secret from hydra clients invocation>"
  
  [session]
  auth-key = "<64 bytes of base64 encoded data>"
  enc-key = "<32 bytes of base64 encoded data>"
  ```

Now you can start Hydra, the IDP and the demo app in 3 terminal windows:

  ```
  hydra serve all --config hydra.yaml
  ```

  ```
  go run cmd/idp/main.go
  ```

  ```
  go run cmd/app/main.go
  ```

Visit https://app.cacert.localhost:4000/ in a Browser and you will be directed
through the OpenID connect authorization code flow.

