from __future__ import annotations
import tempfile
from typing import Dict, TYPE_CHECKING
if TYPE_CHECKING:
    from seedemu.core import Node
from seedemu.core import Service, Server

CaFileTemplates: Dict[str, str] = {}

class CAServer(Server):
    def __init__(self, caFolder: str, caDomain: str, duration: str):
        super().__init__()
        self.__caFolder = caFolder
        self.__caDomain = caDomain
        self.__duration = duration

    def install(self, node: Node):
        if '/certs' in node.getSharedFolders().keys():
            raise ValueError('The /certs folder is already shared with the node.\nDo not install the CA certificate on the CA server.')
        node.addSoftware('ca-certificates')
        node.addBuildCommand('\
if uname -m | grep x86_64 > /dev/null; then \
curl -O -L https://github.com/smallstep/certificates/releases/download/v0.25.2/step-ca_0.25.2_amd64.deb && \
apt install -y ./step-ca_0.25.2_amd64.deb; \
else \
curl -O -L https://github.com/smallstep/certificates/releases/download/v0.25.2/step-ca_0.25.2_arm64.deb && \
apt install -y ./step-ca_0.25.2_arm64.deb; \
fi')
        node.addBuildCommand('\
if uname -m | grep x86_64 > /dev/null; then \
curl -O -L https://github.com/smallstep/cli/releases/download/v0.25.2/step-cli_0.25.2_amd64.deb && \
apt install -y ./step-cli_0.25.2_amd64.deb; \
else \
curl -O -L https://github.com/smallstep/cli/releases/download/v0.25.2/step-cli_0.25.2_arm64.deb && \
apt install -y ./step-cli_0.25.2_arm64.deb; \
fi')
        node.addBuildCommand('tr -dc "A-Za-z0-9" < /dev/urandom | head -c 64 > password.txt')
        node.addBuildCommand(f'step ca init --deployment-type "standalone" --name "SEEDEMU Internal" \
--dns "{self.__caDomain}" --address ":443" --provisioner "admin" --with-ca-url "https://{self.__caDomain}" \
--password-file password.txt --provisioner-password-file password.txt --acme')
        node.addBuildCommand(f'jq \'.authority.claims.defaultTLSCertDuration |= "{self.__duration}"\' $(step path)/config/ca.json > $(step path)/config/ca.json.tmp && mv $(step path)/config/ca.json.tmp $(step path)/config/ca.json')
        node.addSharedFolder('/certs', self.__caFolder)
        node.appendStartCommand('cp $(step path)/certs/root_ca.crt /certs/SEEDEMU_Internal_Root_CA.crt')
        node.appendStartCommand('step-ca --password-file password.txt $(step path)/config/ca.json > /var/step-ca.log 2> /var/step-ca.log', fork=True)
        node.appendStartCommand('cp /certs/SEEDEMU_Internal_Root_CA.crt /usr/local/share/ca-certificates/SEEDEMU_Internal_Root_CA.crt && \
update-ca-certificates')



class CAService(Service):
    """!
    @brief The Certificate Authority (CA) service.

    This service helps setting up a Certificate Authority (CA). It works by
    generating a self-signed root certificate and then signing the server
    certificate with the root certificate.
    """

    def __init__(self, domain: str):
        """!
        @brief create a new CA layer.

        @param domain CA domain name.
        """
        super().__init__()
        self.addDependency('DomainNameService', False, False)
        self.addDependency('Routing', False, False)
        self.__caDomain = domain
        self.__caFolder = tempfile.mkdtemp(prefix='seedemu-ca-')
        self.__duration = '24h'

    def setCertDuration(self, duration: str) -> CAService:
        """!
        @brief Set the certificate duration.

        @param duration. For example, '24h', '48h', '720h'. The duration must no less than 12h.

        @returns self, for chaining API calls.
        """
        if not duration.endswith('h'):
            raise ValueError('The duration must end with "h".')
        if int(duration.rstrip('h')) < 12:
            raise ValueError('The duration must no less than 12h.')
        self.__duration = duration
        return self

    def getName(self):
        return 'CertificateAuthority'
    
    def getCAFolder(self) -> str:
        return self.__caFolder
    
    def getCADomain(self) -> str:
        return self.__caDomain
    
    def _createServer(self) -> Server:
        return CAServer(self.__caFolder, self.__caDomain, self.__duration)

    def installCACertOn(self, node: Node):
        node.addSoftware('ca-certificates')
        node.addSharedFolder('/certs', self.__caFolder)
        node.appendStartCommand('\
until [ -f /certs/SEEDEMU_Internal_Root_CA.crt ] ; do sleep 2; done && \
cp /certs/SEEDEMU_Internal_Root_CA.crt /usr/local/share/ca-certificates/SEEDEMU_Internal_Root_CA.crt && \
update-ca-certificates')
 
