# Desenvolvedor: Jose R F Junior
# web2ajax@gmail.com
# joseribamar.junior@inss.gov.br

"""heraclitusdb — cliente Python para o HeraclitusDB.

    import heraclitusdb
    db = heraclitusdb.connect("127.0.0.1:7474")
"""
from .client import Client, connect, HeraclitusError

__version__ = "0.1.0"
__all__ = ["Client", "connect", "HeraclitusError", "__version__"]
