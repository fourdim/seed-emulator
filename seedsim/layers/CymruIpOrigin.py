from .Service import Service, Server
from .DomainNameService import DomainNameService, DomainNameServer, Zone
from .Reality import Reality
from seedsim.core import Node, ScopedRegistry, Registry, Network, Simulator
from typing import List, Tuple
from ipaddress import IPv4Network

class CymruIpOriginServer(Server):
    """!
    @brief Cymru's IP info service server.
    """

    def install(self, node: Node):
        pass

class CymruIpOriginService(Service):
    """!
    @brief Cymru's IP info service.

    Cymru's IP info service is used by various traceroute utilities to map IP
    address to ASN (using DNS). This service loads the prefix list within the
    simulation and creates ASN mappings for them, so with proper local DNS
    configured, nodes can see the ASN when doing traceroute. 

    This layer hosts the domain cymru.com.
    """

    __records: List[str]

    def __init__(self, simulator: Simulator):
        """!
        @brief CymruIpOriginService constructor

        @param simulator simulator.
        """
        Service.__init__(self, simulator)
        self.__records = []
        self.addDependency('DomainNameService', True, True)
        self.addDependency('Base', False, False)

    def getName(self) -> str:
        return 'CymruIpOriginService'

    def addMapping(self, prefix: str, asn: int):
        """!
        @brief Add new prefix -> asn mapping.

        @param prefix prefix.
        @param asn asn.

        @throws AssertionError if prefix invalid.
        """
        [pfx, cidr] = prefix.split('/')
        cidr = int(cidr)
        assert cidr <= 24, 'Invalid prefix.'
        prefix = IPv4Network(prefix)

        sub_cidr = 24
        num_8s = 3

        if cidr >= 0:
            sub_cidr = 8
            num_8s = 1

        if cidr >= 9:
            sub_cidr = 16
            num_8s = 2

        if cidr >= 17:
            sub_cidr = 24
            num_8s = 3

        for net in prefix.subnets(new_prefix = sub_cidr):
            record = '*.'
            record += '.'.join(reversed(str(net).split('.')[0:3]))
            record += '.origin.asn TXT "{} | {} | ZZ | SEED | 0000-00-00"'.format(asn, net)
            self.__records.append(record)

    def _doInstall(self, node: Node, server: Server): 
        self._log('setting up "cymru.com." server node on as{}/{}...'.format(node.getAsn(), node.getName()))
        dns_s: DomainNameServer = self.__dns.installByName(node.getAsn(), node.getName())
        dns_s.addZone(self.__dns.getZone('cymru.com.'))

    def configure(self, simulator: Simulator):
        reg = simulator.getRegistry()

        mappings: List[Tuple[str, str]] = []

        if reg.has('seedsim', 'layer', 'Reality'):
            real: Reality = reg.get('seedsim', 'layer', 'Reality')
            for router in real.getRealWorldRouters():
                (asn, _, name) = router.getRegistryInfo()
                asn = int(asn)
                self._log('Collecting real-world route info on as{}/{}...'.format(asn, name))
                for prefix in router.getRealWorldRoutes():
                    mappings.append((prefix, asn))
        
        self._log('Collecting all networks in the simulation...')
        for regobj in self._getReg().getAll().items():
            [(asn, type, name), obj] = regobj
            if type != 'net': continue
            net: Network = obj
            if asn == 'ix': asn = name.replace('ix', '')
            mappings.append((net.getPrefix(), int(asn)))

        for mapping in mappings:
            (prefix, asn) = mapping
            self.addMapping(str(prefix), asn)

        self._log('Creating "cymru.com." zone...')
        dns: DomainNameService = reg.get('seedsim', 'layer', 'DomainNameService')
        zone = dns.getZone('cymru.com.')

        self._log('Adding mappings...')
        for record in self.__records:
            zone.addRecord(record)

        return super().configure(simulator)        

    def print(self, indent: int) -> str:
        out = ' ' * indent
        out += 'CymruIpOriginService\n'

        return out

