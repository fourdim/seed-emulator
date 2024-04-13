# Public Key Infrastructure

This is an example that demonstrates how to use the public key infrastructure (PKI) in the emulator.

In this example we create a PKI infrastructure on node `ca` with ACME support. All the nodes in the emulator will have this private CA root certificate installed. We will also create a web server on node `web` and request a certificate from the CA. The CA will sign the certificate and send it to the web server. The web server will then use this certificate to serve HTTPS requests.

## Key Components

### DNS Infrastructure

Same as examples/B02-mini-internet-with-dns.

DNS infrastructure is required for the PKI infrastructure to work. The PKI infrastructure will consult the DNS infrastructure to resolve the domain names and verify the target node's control of domain in ACME challenges.

ETC hosts file can also be served as DNS infrastructure alternative.

### PKI Infrastructure

To create a PKI infrastructure, we need to prepare the Root CA store. The Root CA store is abstracted as a class but it is essentially a folder living in the host machine's `/tmp` directory. The Root CA store is used to generate the corresponding Root CA certificate and private key in the build time. It is also possible to supply your own Root CA certificate and private key.

```python
from seedemu.services import RootCAStore
caStore = RootCAStore(caDomain='ca.internal')
```

After creating the Root CA store, we can create a PKI infrastructure.

```python
from seedemu.services import CAService
ca = CAService(caStore)
ca.install('ca-vnode')
ca.installCACert()
# ca.installCACert(Filter(asn=160))
emu.addLayer(ca)
```

The CA service here uses a private certificate authority program `smallstep` to serve the PKI infrastructure.
For now, the CA service only supports ACME protocol, but it can be easily extended to support X.509 & SSH certificates if needed.

`ca.installCACert()` will by default install the Root CA certificate to all the nodes in the emulator.
It accepts a `Filter` as parameter to install the certificate to specific nodes.
Since the filter logic is implemented inside
the `CAService` rather than the `Filter` object, the `Filter` object might perform
differently in the `CAService` than in other parts.

For example, the allowBound filter is not supported in the `CAService`.

Moreover, inside the `CAService`, the prefix filter is implemented in a portable way that
supports both IPv4 and IPv6 via IPv4-mapped IPv6 addresses. This might not be the case in other
parts.

### Web Server

It's a simple web server that serves a static page. The web server will request a certificate from the CA and use it to serve HTTPS requests.

```python
webServer: WebServer = web.install('web-vnode')
webServer.setServerNames(['user.internal'])
webServer.getCertificatesFrom(ca).enableHTTPS()
```

Server names are required for the web server to request a certificate from the CA. The ACME client will use the server names to determine which nginx configuration to use.

After enabling HTTPS, the web server will serve HTTPS requests.
