"""
Statistics Service
Collects and provides router performance and usage statistics
"""

import threading
import time
from typing import Dict, Any
from dataclasses import dataclass, field

from core.logger import get_logger


@dataclass
class RouterStatistics:
    """Router statistics data structure"""
    packets_routed: int = 0
    packets_dropped: int = 0
    bytes_transferred: int = 0
    handshakes_completed: int = 0
    handshakes_failed: int = 0
    errors: int = 0
    start_time: float = field(default_factory=time.time)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert statistics to dictionary"""
        return {
            'packets_routed': self.packets_routed,
            'packets_dropped': self.packets_dropped,
            'bytes_transferred': self.bytes_transferred,
            'handshakes_completed': self.handshakes_completed,
            'handshakes_failed': self.handshakes_failed,
            'errors': self.errors,
            'uptime_seconds': time.time() - self.start_time
        }


class StatisticsService:
    """
    Service for collecting and managing router statistics
    """
    
    def __init__(self):
        self.logger = get_logger(__name__)
        self.stats = RouterStatistics()
        self.lock = threading.Lock()
        
        # Additional metrics
        self.interface_stats: Dict[str, RouterStatistics] = {}
        self.device_stats: Dict[str, Dict[str, int]] = {}
        
        self.logger.info("Statistics service initialized")
    
    def increment_packets_routed(self, bytes_count: int = 0, interface: str = None):
        """Increment packets routed counter"""
        with self.lock:
            self.stats.packets_routed += 1
            self.stats.bytes_transferred += bytes_count
            
            if interface:
                if interface not in self.interface_stats:
                    self.interface_stats[interface] = RouterStatistics()
                
                self.interface_stats[interface].packets_routed += 1
                self.interface_stats[interface].bytes_transferred += bytes_count
    
    def increment_packets_dropped(self, interface: str = None):
        """Increment packets dropped counter"""
        with self.lock:
            self.stats.packets_dropped += 1
            
            if interface:
                if interface not in self.interface_stats:
                    self.interface_stats[interface] = RouterStatistics()
                
                self.interface_stats[interface].packets_dropped += 1
    
    def increment_handshakes_completed(self, interface: str = None):
        """Increment successful handshakes counter"""
        with self.lock:
            self.stats.handshakes_completed += 1
            
            if interface:
                if interface not in self.interface_stats:
                    self.interface_stats[interface] = RouterStatistics()
                
                self.interface_stats[interface].handshakes_completed += 1
    
    def increment_handshakes_failed(self, interface: str = None):
        """Increment failed handshakes counter"""
        with self.lock:
            self.stats.handshakes_failed += 1
            
            if interface:
                if interface not in self.interface_stats:
                    self.interface_stats[interface] = RouterStatistics()
                
                self.interface_stats[interface].handshakes_failed += 1
    
    def increment_errors(self, interface: str = None):
        """Increment errors counter"""
        with self.lock:
            self.stats.errors += 1
            
            if interface:
                if interface not in self.interface_stats:
                    self.interface_stats[interface] = RouterStatistics()
                
                self.interface_stats[interface].errors += 1
    
    def update_device_stats(self, device_id: str, packets_sent: int = 0, 
                          packets_received: int = 0, bytes_transferred: int = 0):
        """Update per-device statistics"""
        with self.lock:
            if device_id not in self.device_stats:
                self.device_stats[device_id] = {
                    'packets_sent': 0,
                    'packets_received': 0,
                    'bytes_transferred': 0,
                    'last_activity': time.time()
                }
            
            device_stat = self.device_stats[device_id]
            device_stat['packets_sent'] += packets_sent
            device_stat['packets_received'] += packets_received
            device_stat['bytes_transferred'] += bytes_transferred
            device_stat['last_activity'] = time.time()
    
    def remove_device_stats(self, device_id: str):
        """Remove statistics for a device"""
        with self.lock:
            self.device_stats.pop(device_id, None)
    
    def get_stats(self) -> RouterStatistics:
        """Get current router statistics (copy)"""
        with self.lock:
            # Create a copy to avoid concurrent modification issues
            stats_copy = RouterStatistics(
                packets_routed=self.stats.packets_routed,
                packets_dropped=self.stats.packets_dropped,
                bytes_transferred=self.stats.bytes_transferred,
                handshakes_completed=self.stats.handshakes_completed,
                handshakes_failed=self.stats.handshakes_failed,
                errors=self.stats.errors,
                start_time=self.stats.start_time
            )
            return stats_copy
    
    def get_interface_stats(self, interface: str) -> RouterStatistics:
        """Get statistics for a specific interface"""
        with self.lock:
            if interface not in self.interface_stats:
                return RouterStatistics()
            
            stats = self.interface_stats[interface]
            return RouterStatistics(
                packets_routed=stats.packets_routed,
                packets_dropped=stats.packets_dropped,
                bytes_transferred=stats.bytes_transferred,
                handshakes_completed=stats.handshakes_completed,
                handshakes_failed=stats.handshakes_failed,
                errors=stats.errors,
                start_time=stats.start_time
            )
    
    def get_device_stats(self, device_id: str) -> Dict[str, Any]:
        """Get statistics for a specific device"""
        with self.lock:
            return self.device_stats.get(device_id, {}).copy()
    
    def get_all_device_stats(self) -> Dict[str, Dict[str, Any]]:
        """Get statistics for all devices"""
        with self.lock:
            return {device_id: stats.copy() 
                   for device_id, stats in self.device_stats.items()}
    
    def get_uptime(self) -> float:
        """Get router uptime in seconds"""
        return time.time() - self.stats.start_time
    
    def reset_stats(self):
        """Reset all statistics"""
        with self.lock:
            self.stats = RouterStatistics()
            self.interface_stats.clear()
            self.device_stats.clear()
            
            self.logger.info("Statistics reset")
    
    def get_comprehensive_stats(self) -> Dict[str, Any]:
        """Get comprehensive statistics including all interfaces and devices"""
        with self.lock:
            return {
                'total': self.stats.to_dict(),
                'interfaces': {
                    interface: stats.to_dict() 
                    for interface, stats in self.interface_stats.items()
                },
                'devices': self.get_all_device_stats(),
                'summary': {
                    'total_devices': len(self.device_stats),
                    'active_interfaces': len(self.interface_stats),
                    'uptime_seconds': self.get_uptime(),
                    'avg_packets_per_second': (
                        self.stats.packets_routed / max(1, self.get_uptime())
                    ),
                    'success_rate': (
                        self.stats.handshakes_completed / 
                        max(1, self.stats.handshakes_completed + self.stats.handshakes_failed)
                    ) * 100 if (self.stats.handshakes_completed + self.stats.handshakes_failed) > 0 else 0
                }
            }
    
    def update_periodic_stats(self):
        """Update statistics that are calculated periodically"""
        # This method can be called periodically to update derived statistics
        # Currently no periodic calculations needed, but reserved for future use
        pass
    
    def log_summary(self):
        """Log a summary of current statistics"""
        stats = self.get_stats()
        uptime = self.get_uptime()
        
        self.logger.info(
            "Statistics Summary",
            uptime_hours=f"{uptime / 3600:.2f}",
            packets_routed=stats.packets_routed,
            packets_dropped=stats.packets_dropped,
            bytes_transferred=stats.bytes_transferred,
            handshakes_completed=stats.handshakes_completed,
            errors=stats.errors,
            success_rate=f"{(stats.handshakes_completed / max(1, stats.handshakes_completed + stats.handshakes_failed)) * 100:.1f}%"
        )