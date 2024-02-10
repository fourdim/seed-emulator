from __future__ import annotations
from seedemu.core import Node, Service, Server
from typing import Dict, List

WebServerFileTemplates: Dict[str, str] = {}

WebServerFileTemplates['nginx_site'] = '''\
server {{
    listen {port};
    root /var/www/html;
    index index.html;
    server_name {serverName};
    location / {{
        try_files $uri $uri/ =404;
    }}
}}
'''

WebServerFileTemplates['certbot_renew_cron'] = '''\
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
'''

class WebServer(Server):
    """!
    @brief The WebServer class.
    """

    __port: int
    __index: str

    def __init__(self):
        """!
        @brief WebServer constructor.
        """
        super().__init__()
        self.__port = 80
        self.__https = False
        self.__serverName = ['_']
        self.__index = '<h1>{nodeName} at {asn}</h1>'
        

    def setPort(self, port: int) -> WebServer:
        """!
        @brief Set HTTP port.

        @param port port.

        @returns self, for chaining API calls.
        """
        self.__port = port

        return self

    def setIndexContent(self, content: str) -> WebServer:
        """!
        @brief Set content of index.html.

        @param content content. {nodeName} and {asn} are available and will be
        filled in.

        @returns self, for chaining API calls.
        """
        self.__index = content

        return self
    
    def enableHttps(self, serverNames: List[str], caDomain: str = 'ca.internal') -> WebServer:
        """!
        @brief Enable HTTPS.

        @returns self, for chaining API calls.
        """
        self.__https = True
        self.__serverName = serverNames
        self.__caDomain = caDomain
        return self
    
    def install(self, node: Node):
        """!
        @brief Install the service.
        """
        node.addSoftware('nginx-light')
        node.setFile('/var/www/html/index.html', self.__index.format(asn = node.getAsn(), nodeName = node.getName()))
        node.setFile('/etc/nginx/sites-available/default', WebServerFileTemplates['nginx_site'].format(port = self.__port, serverName = ' '.join(self.__serverName)))
        node.appendStartCommand('service nginx start')
        node.appendClassName("WebService")
        if self.__https:
            node.addSoftware('certbot').addSoftware('python3-certbot-nginx').addSoftware('cron')
            # wait for the name server
            node.setFile('/etc/cron.d/certbot', WebServerFileTemplates['certbot_renew_cron'])
            node.appendStartCommand('until dig {} | grep "status: NOERROR" > /dev/null ; do echo "DNS status: SERVFAIL Retry in 2 sec" && sleep 2; done'.format(self.__caDomain))
            node.appendStartCommand('REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt \
certbot --server https://{caDomain}/acme/acme/directory --non-interactive --nginx --no-redirect --agree-tos --email example@example.com \
-d {serverName} > /dev/null && echo "ACME: cert issued"'.format(serverName = ' -d '.join(self.__serverName), caDomain = self.__caDomain))
            node.appendStartCommand('sed \'s/^#\? \?renew_before_expiry = .*$/renew_before_expiry = 8hours/\' -i /etc/letsencrypt/renewal/*.conf')
            node.appendStartCommand('crontab /etc/cron.d/certbot && service cron start')

    def print(self, indent: int) -> str:
        out = ' ' * indent
        out += 'Web server object.\n'

        return out

class WebService(Service):
    """!
    @brief The WebService class.
    """

    def __init__(self):
        """!
        @brief WebService constructor.
        """
        super().__init__()
        self.addDependency('Base', False, False)
        self.addDependency('Routing', False, False)

    def _createServer(self) -> Server:
        return WebServer()

    def getName(self) -> str:
        return 'WebService'

    def print(self, indent: int) -> str:
        out = ' ' * indent
        out += 'WebServiceLayer\n'

        return out