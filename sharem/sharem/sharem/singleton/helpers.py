from abc import ABCMeta
from typing import Any


class Singleton(ABCMeta):
    """
    
    This class is a standard implementation of the Single Pattern
    (Note: Has not been tested for Thread Saftey)

    """

    _instances = {}

    def __call__(cls, *args, **kwargs) -> Any:
        if cls not in cls._instances:
            cls._instances[cls] = super(Singleton, cls).__call__(*args, **kwargs)
        return cls._instances[cls]