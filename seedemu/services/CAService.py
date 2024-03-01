from __future__ import annotations
import os
import tempfile
from typing import Dict, TYPE_CHECKING

from seedemu.utilities import getProjectRoot

if TYPE_CHECKING:
    from seedemu.services.WebService import WebServer
    from seedemu.core import Node
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


class CAServer(Server):
    def __init__(self, caDomain: str, duration: str):
        super().__init__()
        self.__caDomain = caDomain
        self.__duration = duration

    def install(self, node: Node):
        if "/certs" in node.getSharedFolders().keys():
            raise ValueError(
                "The /certs folder is already shared with the node.\nDo not install the CA certificate on the CA server."
            )
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
        caDir = os.path.join(getProjectRoot(), "misc/CA/.step")
        for root, _, files in os.walk(caDir):
            for file in files:
                node.importFile(
                    os.path.join(root, file),
                    os.path.join(
                        "/root/.step", os.path.relpath(os.path.join(root, file), caDir)
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
            "step-ca --password-file $(step path)/password.txt $(step path)/config/ca.json > /var/step-ca.log 2> /var/step-ca.log",
            fork=True,
        )


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
        self.addDependency("DomainNameService", False, False)
        self.addDependency("Routing", False, False)
        self.__caDomain = domain
        self.__duration = "24h"

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
        return CAServer(self.__caDomain, self.__duration)

    def enableHTTPSFunc(self, node: Node, web: WebServer):
        node.addSoftware("certbot").addSoftware("python3-certbot-nginx").addSoftware(
            "cron"
        )
        # wait for the name server
        node.setFile("/etc/cron.d/certbot", CaFileTemplates["certbot_renew_cron"])
        node.appendStartCommand(
            'until dig {} | grep "status: NOERROR" > /dev/null ; do echo "DNS status: SERVFAIL Retry in 2 sec" && sleep 2; done'.format(
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
