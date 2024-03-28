from __future__ import annotations
import re

from .Filter import Filter
from .Node import Node
from .Printable import Printable
from .Registry import Registrable
from .Emulator import Emulator
from .Configurable import Configurable
from .Merger import Mergeable

from ipaddress import (
    IPv4Network,
    IPv6Network,
    IPv4Address,
    IPv6Address,
    ip_address,
    ip_network,
)
from sys import stderr
from typing import Callable, Iterable, List, Set, Dict, Tuple

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

class Layer(Printable, Registrable, Configurable, Mergeable):
    """!
    @brief The layer interface.
    """

    __dependencies: Dict[str, Set[Tuple[str, bool]]]
    _applyFunctionsWithFilters: List[Tuple[Callable[[Node], None], Filter]] = []

    def __init__(self):
        """!
        @brief create a new layer.
        """

        super().__init__()
        self.__dependencies = {}

    def _apply(self, func: Callable[[Node], None], filter: Filter = None):
        """!
        @brief Apply a function to nodes that matches the filter.
        Calling the `apply` method multiple times will apply the configurations
        in the order they are called.

        @param func The function to be applied. It takes a node as its argument.
        If you want to add a function that takes more than one argument,
        you can use a lambda function to wrap it.
        e.g. world.apply(lambda node: ldns.setNameServers(node, ["1.14.5.14"]))

        @param filter The filter to filter nodes that satisfy the requirement.
        If None, apply to all nodes.
        """
        if filter:
            assert (
                not filter.allowBound
            ), 'allowBound filter is not supported in the global layer.'
        self._applyFunctionsWithFilters.append((func, filter))

    def getTypeName(self) -> str:
        """!
        @brief get typename of this layer.

        @returns type name.
        """
        return '{}Layer'.format(self.getName())

    def shouldMerge(self, other: Layer) -> bool:
        """!
        @brief test if this layer should be merged with another layer.

        @param other the other layer.

        @returns true if yes; will be true if the layer is the same layer.
        """

        return self.getName() == other.getName()

    def addDependency(self, layerName: str, reverse: bool, optional: bool):
        """!
        @brief add layer dependency.

        @param layerName name of the layer.
        @param reverse add as reverse dependency. Regular dependency requires
        the given layer to be rendered before the current layer. Reverse
        dependency requires the given layer to be rendered after the current
        layer. 
        @param optional continue render even if the given layer does not exist.
        Does not work for reverse dependencies.
        """

        _current = layerName if reverse else self.getName()
        _target = self.getName() if reverse else layerName

        if _current not in self.__dependencies:
            self.__dependencies[_current] = set()

        self.__dependencies[_current].add((_target, optional))

    def getDependencies(self) -> Dict[str, Set[Tuple[str, bool]]]:
        """!
        @brief Get dependencies.

        @return dependencies.
        """

        return self.__dependencies
    
    def configure(self, emulator: Emulator):
        if len(self._applyFunctionsWithFilters) == 0:
            return
        allNodesItems = emulator.getRegistry().getAll().items()
        for func, filter in self._applyFunctionsWithFilters:
            for (_, type, name), obj in allNodesItems:
                if type not in ['rs', 'rnode', 'hnode', 'csnode']:
                    continue
                node: Node = obj
                if filter:
                    if filter.asn and filter.asn != node.getAsn():
                        continue
                    if filter.nodeName and not re.compile(filter.nodeName).match(name):
                        continue
                    if filter.ip and filter.ip not in map(
                        lambda x: x.getAddress(), node.getInterfaces()
                    ):
                        continue
                    if filter.prefix:
                        ips = {
                            host
                            for host in map(
                                lambda x: x.getAddress(), node.getInterfaces()
                            )
                        }
                        if not ipsInNetwork(ips, filter.prefix):
                            continue
                    if filter.custom and not filter.custom(node.getName(), node):
                        continue
                func(node)
        self._applyFunctionsWithFilters.clear()
        self._log('configured globally applicable functions.')

    def getName(self) -> str:
        """!
        @brief Get name of this layer.

        This method should return a unique name for this layer. This will be
        used by the renderer to resolve dependencies relationships.

        @returns name of the layer.
        """
        raise NotImplementedError('getName not implemented')

    def render(self, emulator: Emulator) -> None:
        """!
        @brief Handle rendering.
        """
        raise NotImplementedError('render not implemented')

    def _log(self, message: str) -> None:
        """!
        @brief Log to stderr.
        """
        print("==== {}Layer: {}".format(self.getName(), message), file=stderr)
