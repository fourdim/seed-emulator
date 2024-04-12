from __future__ import annotations
from contextlib import contextmanager
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network, ip_address, ip_network
import os
import re
import secrets
import string
import subprocess
import tempfile
from typing import Dict, TYPE_CHECKING, Iterable

from seedemu.core.Emulator import Emulator

if TYPE_CHECKING:
    from seedemu.services.WebService import WebServer
    from seedemu.core import Node, Filter
from seedemu.core import Service, Server

CaFileTemplates: Dict[str, str] = {}

CaFileTemplates["certbot_renew_cron"] = """\
# /etc/cron.d/certbot: crontab entries for the certbot package
#
# Upstream recommends attempting renewal
#
# Eventually, this will be an opportunity to validate certificates
# haven't been revoked, etc.  Renewal will only occur if expiration
# is within 8 hours.
#
# Important Note!  This cronjob will NOT be executed if you are
# running systemd as your init system.  If you are running systemd,
# the cronjob.timer function takes precedence over this cronjob.  For
# more details, see the systemd.timer manpage, or use systemctl show
# certbot.timer.
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

* */1 * * * root test -x /usr/bin/certbot -a \! -d /run/systemd/system && perl -e 'sleep int(rand(3600))' && REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt certbot -q renew
"""

def ipsInNetwork(ips: Iterable, network: str) -> bool:
    """!
    @brief Check if any of the IPs in the iterable is in the network.
    This function supports both IPv4 and IPv6 via IPv4-Mapped IPv6 Address.
    @param ips The iterable of IPs.
    @param network The network.
    @return True if any of the IPs is in the network, False otherwise.
    """
    net = ip_network(network)
    map6to4 = int(IPv6Address('::ffff:0:0'))
    if isinstance(net, IPv4Network):
        net = IPv6Network(
            # convert to IPv4-Mapped IPv6 Address for computation
            #   ::ffff:V4ADDR
            # 80 + 16 +  32
            # https://datatracker.ietf.org/doc/html/rfc4291#section-2.5.5.2
            f'{IPv6Address(map6to4 | int(net.network_address))}/{96 + net.prefixlen}'
        )
    for ip in ips:
        ip = ip_address(ip)
        if isinstance(ip, IPv4Address):
            ip = IPv6Address(map6to4 | int(ip))
        if ip in net:
            return True
    return False

class CAServer(Server):
    def __init__(self, duration: str, caStore: RootCAStore):
        super().__init__()
        self.__duration = duration
        self.__caStore = caStore

    def install(self, node: Node):
        node.addSoftware("ca-certificates")
        node.addBuildCommand(
            "\
if uname -m | grep x86_64 > /dev/null; then \
curl -O -L https://github.com/smallstep/certificates/releases/download/v0.25.2/step-ca_0.25.2_amd64.deb && \
apt install -y ./step-ca_0.25.2_amd64.deb; \
else \
curl -O -L https://github.com/smallstep/certificates/releases/download/v0.25.2/step-ca_0.25.2_arm64.deb && \
apt install -y ./step-ca_0.25.2_arm64.deb; \
fi"
        )
        node.addBuildCommand(
            "\
if uname -m | grep x86_64 > /dev/null; then \
curl -O -L https://github.com/smallstep/cli/releases/download/v0.25.2/step-cli_0.25.2_amd64.deb && \
apt install -y ./step-cli_0.25.2_amd64.deb; \
else \
curl -O -L https://github.com/smallstep/cli/releases/download/v0.25.2/step-cli_0.25.2_arm64.deb && \
apt install -y ./step-cli_0.25.2_arm64.deb; \
fi"
        )
        self.__caDir = self.__caStore.getStorePath()
        for root, _, files in os.walk(self.__caDir):
            for file in files:
                node.importFile(
                    os.path.join(root, file),
                    os.path.join(
                        "/root",
                        os.path.relpath(os.path.join(root, file), self.__caDir),
                    ),
                )
        node.appendStartCommand(
            "cp $(step path)/certs/root_ca.crt /usr/local/share/ca-certificates/SEEDEMU_Internal_Root_CA.crt && \
update-ca-certificates"
        )
        node.appendStartCommand(
            f"jq '.authority.claims.defaultTLSCertDuration |= \"{self.__duration}\"' $(step path)/config/ca.json > $(step path)/config/ca.json.tmp && mv $(step path)/config/ca.json.tmp $(step path)/config/ca.json"
        )
        node.appendStartCommand(
            "step-ca --password-file /root/password.txt $(step path)/config/ca.json > /var/step-ca.log 2> /var/step-ca.log",
            fork=True,
        )


class CAService(Service):
    """!
    @brief The Certificate Authority (CA) service.

    This service helps setting up a Certificate Authority (CA). It works by
    generating a self-signed root certificate and then signing the server
    certificate with the root certificate.
    """

    def __init__(self, caStore: RootCAStore):
        """!
        @brief create a new CA layer.

        @param domain CA domain name.
        """
        super().__init__()
        self.addDependency("DomainNameService", False, False)
        self.addDependency("Routing", False, False)
        self.__caStore = caStore
        self.__caStore.initialize()
        self.__caDomain = self.__caStore._caDomain
        self.__duration = "24h"
        self.__filter = None

    def setCertDuration(self, duration: str) -> CAService:
        """!
        @brief Set the certificate duration.

        @param duration. For example, '24h', '48h', '720h'. The duration must no less than 12h.

        @returns self, for chaining API calls.
        """
        if not duration.endswith("h"):
            raise ValueError('The duration must end with "h".')
        if int(duration.rstrip("h")) < 12:
            raise ValueError("The duration must no less than 12h.")
        self.__duration = duration
        return self

    def getName(self):
        return "CertificateAuthority"

    def getCADomain(self) -> str:
        return self.__caDomain

    def _createServer(self) -> Server:
        return CAServer(self.__duration, self.__caStore)

    def enableHTTPSFunc(self, node: Node, web: WebServer):
        node.addSoftware("certbot").addSoftware("python3-certbot-nginx").addSoftware(
            "cron"
        )
        # wait for the name server
        node.setFile("/etc/cron.d/certbot", CaFileTemplates["certbot_renew_cron"])
        node.appendStartCommand(
            'until curl https://{}/acme/acme/directory > /dev/null ; do echo "Network retry in 2 s" && sleep 2; done'.format(
                self.__caDomain
            )
        )

        node.appendStartCommand(
            'REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt \
certbot --server https://{caDomain}/acme/acme/directory --non-interactive --nginx --no-redirect --agree-tos --email example@example.com \
-d {serverName} > /dev/null && echo "ACME: cert issued"'.format(
                serverName=" -d ".join(web._server_name), caDomain=self.__caDomain
            )
        )
        node.appendStartCommand(
            "sed 's/^#\? \?renew_before_expiry = .*$/renew_before_expiry = 8hours/' -i /etc/letsencrypt/renewal/*.conf"
        )
        node.appendStartCommand("crontab /etc/cron.d/certbot && service cron start")

    def installCACert(self, filter: Filter = None):   
        # This is possible to do it in runtime
        if filter:
            assert (
                not filter.allowBound
            ), 'allowBound filter is not supported in the global layer.'
        self.__filter = filter
    
    def configure(self, emulator: Emulator):
        super().configure(emulator)
        allNodesItems = emulator.getRegistry().getAll().items()
        for (_, type, name), obj in allNodesItems:
            if type not in ['rs', 'rnode', 'hnode', 'csnode']:
                continue
            node: Node = obj
            if self.__filter:
                if self.__filter.asn and self.__filter.asn != node.getAsn():
                    continue
                if self.__filter.nodeName and not re.compile(self.__filter.nodeName).match(name):
                    continue
                if self.__filter.ip and self.__filter.ip not in map(
                    lambda x: x.getAddress(), node.getInterfaces()
                ):
                    continue
                if self.__filter.prefix:
                    ips = {
                        host
                        for host in map(
                            lambda x: x.getAddress(), node.getInterfaces()
                        )
                    }
                    if not ipsInNetwork(ips, self.__filter.prefix):
                        continue
                if self.__filter.custom and not self.__filter.custom(node.getName(), node):
                    continue
            node.addSoftware('ca-certificates')
            node.importFile(os.path.join(self.__caStore.getStorePath(), '.step/certs/root_ca.crt'), '/usr/local/share/ca-certificates/SEEDEMU_Internal_Root_CA.crt')
            node.appendStartCommand('update-ca-certificates')


@contextmanager
def cd(path):
    """@private"""
    old_cwd = os.getcwd()
    os.chdir(path)
    try:
        yield
    finally:
        os.chdir(old_cwd)


def sh(command, input=None):
    try:
        if isinstance(command, list):
            command = " ".join(command)
        p = subprocess.run(
            command,
            shell=True,
            input=input,
        )
        return p.returncode
    except subprocess.CalledProcessError as e:
        return e.returncode

def createCARootCert(caDir: str, caDomain: str = "ca.internal"):
    """!
    @brief Create a CA directory.
    @deprecated Use RootCAStore instead.

    @param caDir The absolute path to the directory to create.
    """
    if not os.path.exists(caDir):
        os.makedirs(caDir)
    with cd(caDir):
        sh('tr -dc "A-Za-z0-9" < /dev/urandom | head -c 64 > password.txt')
        sh(f'docker run -it --rm -v {caDir}:/root -e STEPPATH=/root/.step --entrypoint step smallstep/step-ca ca init --deployment-type "standalone" --name "SEEDEMU Internal" \
--dns "{caDomain}" --address ":443" --provisioner "admin" --with-ca-url "https://{caDomain}" \
--password-file password.txt --provisioner-password-file password.txt --acme')


class RuntimeDockerFile:
    def __init__(self, content: str):
        self.__content = content

    def getContent(self) -> str:
        return self.__content


class RuntimeDockerImage:
    def __init__(self, imageName: str):
        self.__imageName = imageName

    def build(
        self,
        dockerfile: RuntimeDockerFile,
        context: str = None,
        args: Dict[str, str] = None,
    ):
        if not context:
            context = tempfile.mkdtemp(prefix="seedemu-docker-")
        with cd(context):
            build_command = f"docker build -t {self.__imageName}"
            for arg, value in args.items():
                build_command += f" --build-arg {arg}={value}"
            sh(build_command + " -", input=dockerfile.getContent())
        return self

    def container(self):
        return BuildtimeDockerContainer(self.__imageName)


class BuildtimeDockerContainer:
    def __init__(self, imageName: str):
        self.__imageName = imageName
        self.__volumes = []
        self.__env = []
        self.__entrypoint = None
        self.__workdir = None

    def mountVolume(self, source: str, target: str):
        self.__volumes.append((source, target))
        return self

    def env(self, envName: str, envValue: str):
        self.__env.append((envName, envValue))
        return self

    def workdir(self, workdir: str):
        self.__workdir = workdir
        return self

    def entrypoint(self, entrypoint: str):
        self.__entrypoint = entrypoint
        return self

    def run(self, command: str = None):
        run_command = "docker run -it --rm"
        if self.__workdir:
            run_command += f" -w {self.__workdir}"
        for key, value in self.__env:
            run_command += f" -e {key}={value}"
        if self.__entrypoint:
            run_command += f" --entrypoint {self.__entrypoint}"
        for source, target in self.__volumes:
            run_command += f" -v {source}:{target}"
        run_command += f" {self.__imageName}"
        if command:
            run_command += f" {command}"
        sh(run_command)


class RootCAStore:
    def __init__(self, caDomain: str = "ca.internal"):
        self._caDomain = caDomain
        self.__caDir = tempfile.mkdtemp(prefix="seedemu-ca-")
        self.__password = "".join(
            secrets.choice(string.ascii_letters + string.digits) for _ in range(64)
        )
        self.__initialized = False
        self.__pendingRootCertAndKey = None
        with cd(self.__caDir):
            self.__container = RuntimeDockerImage("smallstep/step-ca").container()
            self.__container.mountVolume(self.__caDir, "/root").env(
                "STEPPATH", "/root/.step"
            ).entrypoint(
                "step"
            )

    def getStorePath(self) -> str: 
        return self.__caDir
    
    def setPassword(self, password: str):
        if self.__initialized:
            raise RuntimeError("The CA store is already initialized.")
        self.__password = password

    def setRootCertAndKey(self, rootCertPath: str, rootKeyPath: str):
        if self.__initialized:
            raise RuntimeError("The CA store is already initialized.")
        with cd(self.__caDir):
            sh(f"cp {rootCertPath} root_ca.crt")
            sh(f"cp {rootKeyPath} root_ca_key")
        self.__pendingRootCertAndKey = (f"{self.__caDir}/root_ca.crt", f"{self.__caDir}/root_ca_key")
    
    def initialize(self):
        if self.__initialized:
            return
        with cd(self.__caDir):
            with open("password.txt", "w") as f:
                f.write(self.__password)
            initialize_command = "ca init"
            if self.__pendingRootCertAndKey:
                initialize_command += ' --root /root/root_ca.crt --key /root/root_ca_key'
            initialize_command += f' --deployment-type "standalone" --name "SEEDEMU Internal" \
--dns "{self._caDomain}" --address ":443" --provisioner "admin" --with-ca-url "https://{self._caDomain}" \
--password-file /root/password.txt --provisioner-password-file /root/password.txt --acme'
            self.__container.run(initialize_command)
        self.__initialized = True
    
    def save(self, path: str):
        if not self.__initialized:
            raise RuntimeError("The CA store is not initialized.")
        with cd(self.__caDir):
            sh(f"cp -r . {path}")




if __name__ == "__main__":
    print(RootCAStore().getStorePath())
