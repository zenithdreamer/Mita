"""
Transport Interface Definition
Abstract base class for all transport layer implementations
"""

from abc import ABC, abstractmethod
from typing import Dict, Any


class TransportInterface(ABC):
    """Abstract interface for transport layers"""
    
    @abstractmethod
    def start(self) -> bool:
        """Start the transport layer"""
        pass
    
    @abstractmethod
    def stop(self) -> None:
        """Stop the transport layer"""
        pass
    
    @abstractmethod
    def is_running(self) -> bool:
        """Check if transport is running"""
        pass
    
    @abstractmethod
    def get_connected_devices(self) -> Dict[str, Any]:
        """Get list of connected devices"""
        pass