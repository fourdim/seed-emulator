
from typing import Callable, List, Tuple
from seedemu.core import Filter, Graphable, Layer, Node
from seedemu.core.Emulator import Emulator


class Global(Layer, Graphable):
    """!
    @brief The global layer.
    """

    applyFunctionsWithFilters: List[Tuple[Callable[[Node], None], Filter]] = []

    def __init__(self):
        """!
        @brief The constructor of the Global layer.
        Example Usage: world = Global()
        Do not use `global` as the variable name because it is a reserved keyword in Python.
        """
        super().__init__()
        self.addDependency('Base', False, False)

    def getName(self) -> str:
        return 'Global'

    def apply(self, func: Callable[[Node], None], filter: Filter = None):
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
        self._apply(func, filter)

    def configure(self, emulator: Emulator):
        super().configure(emulator)

    def render(self, emulator: Emulator) -> None:
        pass
