# Mutual TLS Tests

Trying to create certificates for server + client to perform mutual TLS.
For eventual use with a personal media server to keep out gremlins.

> `https://www.golinuxcloud.com/openssl-create-client-server-certificate/#OpenSSL_create_client_certificate`
>> `https://www.openssl.org/docs/manmaster/man5/x509v3_config.html`
>>> `https://gerrit.openbmc-project.xyz/plugins/gitiles/openbmc/docs/+/919a7b6816a5f16aa72d298e81e0756d95d5031e/security/TLS-configuration.md`


HINT FROM https://stackoverflow.com/questions/45628601/client-authentication-using-self-signed-ssl-certificate-for-nginx
```
    # Create the CA Key and Certificate for signing Client Certs
    openssl genrsa -des3 -out ca.key 4096                     # produces ca.key
    openssl req -new -x509 -days 365 -key ca.key -out ca.crt  # produces ca.crt

    # Create the Client Key and CSR
    openssl genrsa -des3 -out client.key 4096         # produces client.key
    openssl req -new -key client.key \
        -extfile client_cert_ext.cnf -out client.csr  # produces client.csr (requires client.key password)

    # Sign the client certificate with our CA cert
    openssl x509 -req -days 365 -in client.csr -CA ca.crt \
        -CAkey ca.key -set_serial 01 -out client.crt  # produces client.crt

    # Convert to .p12 so import in OSX works
    openssl pkcs12 -export -clcerts -inkey client.key \
      -in client.crt -out client.p12 \
      -name "<person>'s <service> Client Cert p12"  # produces client.p12 (combines client.crt and client.key)
```

Outputs:
- ca.key password
- client.key password
- client.csr challenge password (optional)
- client.p12 export password (optional?)

1) Add to keychain (`login` is fine)
2) Trust SSL always
    By here, Chrome will use it
3) Add identity --> hostname or IP (e.g. 10.0.1.7)
    By here, Safari will use it
    By here, Opera will use it

Utilities:
```
    # check if .p12 (client info) was signed with .crt (server info)
    ...

    # view .csr file
    openssl req -text -noout -verify -in <filepath.csr>

    # view .crt file
    openssl x509 -in <filepath.crt> -text -noout

    # view .p12 file
    # (requires client.key password)
    # (requires client.p12 export password)
    openssl pkcs12 -info -in <filepath>

    # check website certificate chain
    openssl s_client -connect www.paypal.com:443
    openssl s_client -connect www.paypal.com:443 -state -debug
    openssl s_client -connect www.paypal.com:443 -state -debug -cert <filepath.crt> -key <filepath.key>

    # load website with client certificate
    curl <url> \
        --insecure --user <username>:<password> \
        --cert <filepath.crt> --key <filepath.key>
```
