"""
Configuration management for Multi-Protocol IoT Router
Handles loading, validation, and type-safe access to configuration
"""

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Any, Optional
import logging

logger = logging.getLogger(__name__)


@dataclass
class WiFiConfig:
    """WiFi transport configuration"""
    enabled: bool = True
    server_host: str = "192.168.50.1"
    server_port: int = 8000
    channel: int = 6
    max_connections: int = 10
    ap_timeout: int = 30


@dataclass
class BLEConfig:
    """BLE transport configuration"""
    enabled: bool = True
    scan_interval: float = 5.0
    scan_pause: float = 2.0
    service_uuid: str = "12345678-1234-1234-1234-123456789abc"
    characteristic_uuid: str = "12345678-1234-1234-1234-123456789abd"
    device_name: str = "IoT_Router"
    max_connections: int = 7


@dataclass
class RoutingConfig:
    """Routing configuration"""
    cleanup_interval: int = 60
    device_timeout: int = 300
    max_devices: int = 100
    auto_assign_addresses: bool = True


@dataclass
class SecurityConfig:
    """Security configuration"""
    encryption_enabled: bool = True
    handshake_timeout: int = 30
    session_timeout: int = 3600
    max_handshake_attempts: int = 3


@dataclass
class LoggingConfig:
    """Logging configuration"""
    status_interval: int = 30
    log_level: str = "INFO"
    log_file: Optional[str] = None


@dataclass
class DevelopmentConfig:
    """Development and testing configuration"""
    skip_ap_setup: bool = False
    debug_packets: bool = False
    mock_interfaces: bool = False


@dataclass
class RouterConfig:
    """Complete router configuration"""
    router_id: str
    shared_secret: str
    wifi: WiFiConfig = field(default_factory=WiFiConfig)
    ble: BLEConfig = field(default_factory=BLEConfig)
    routing: RoutingConfig = field(default_factory=RoutingConfig)
    security: SecurityConfig = field(default_factory=SecurityConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    development: DevelopmentConfig = field(default_factory=DevelopmentConfig)
    
    @classmethod
    def from_file(cls, config_path: Path) -> 'RouterConfig':
        """Load configuration from JSON file"""
        try:
            with open(config_path, 'r') as f:
                data = json.load(f)
            logger.info(f"Loaded configuration from {config_path}")
            return cls.from_dict(data)
        except FileNotFoundError:
            logger.error(f"Configuration file not found: {config_path}")
            raise
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in configuration file: {e}")
            raise
        except Exception as e:
            logger.error(f"Error loading configuration: {e}")
            raise
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'RouterConfig':
        """Create configuration from dictionary"""
        # Extract required fields
        router_id = data.get('router_id')
        shared_secret = data.get('shared_secret')
        
        if not router_id:
            raise ValueError("router_id is required")
        if not shared_secret:
            raise ValueError("shared_secret is required")
        
        # Create sub-configurations
        wifi_config = WiFiConfig(**data.get('wifi', {}))
        ble_config = BLEConfig(**data.get('ble', {}))
        routing_config = RoutingConfig(**data.get('routing', {}))
        security_config = SecurityConfig(**data.get('security', {}))
        logging_config = LoggingConfig(**data.get('logging', {}))
        development_config = DevelopmentConfig(**data.get('development', {}))
        
        # Update BLE device name with router ID if not set
        if ble_config.device_name == "IoT_Router":
            ble_config.device_name = f"{router_id}_Router"
        
        return cls(
            router_id=router_id,
            shared_secret=shared_secret,
            wifi=wifi_config,
            ble=ble_config,
            routing=routing_config,
            security=security_config,
            logging=logging_config,
            development=development_config
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary"""
        return {
            'router_id': self.router_id,
            'shared_secret': self.shared_secret,
            'wifi': {
                'enabled': self.wifi.enabled,
                'server_host': self.wifi.server_host,
                'server_port': self.wifi.server_port,
                'channel': self.wifi.channel,
                'max_connections': self.wifi.max_connections,
                'ap_timeout': self.wifi.ap_timeout
            },
            'ble': {
                'enabled': self.ble.enabled,
                'scan_interval': self.ble.scan_interval,
                'scan_pause': self.ble.scan_pause,
                'service_uuid': self.ble.service_uuid,
                'characteristic_uuid': self.ble.characteristic_uuid,
                'device_name': self.ble.device_name,
                'max_connections': self.ble.max_connections
            },
            'routing': {
                'cleanup_interval': self.routing.cleanup_interval,
                'device_timeout': self.routing.device_timeout,
                'max_devices': self.routing.max_devices,
                'auto_assign_addresses': self.routing.auto_assign_addresses
            },
            'security': {
                'encryption_enabled': self.security.encryption_enabled,
                'handshake_timeout': self.security.handshake_timeout,
                'session_timeout': self.security.session_timeout,
                'max_handshake_attempts': self.security.max_handshake_attempts
            },
            'logging': {
                'status_interval': self.logging.status_interval,
                'log_level': self.logging.log_level,
                'log_file': self.logging.log_file
            },
            'development': {
                'skip_ap_setup': self.development.skip_ap_setup,
                'debug_packets': self.development.debug_packets,
                'mock_interfaces': self.development.mock_interfaces
            }
        }
    
    def save_to_file(self, config_path: Path):
        """Save configuration to JSON file"""
        try:
            with open(config_path, 'w') as f:
                json.dump(self.to_dict(), f, indent=4)
            logger.info(f"Configuration saved to {config_path}")
        except Exception as e:
            logger.error(f"Error saving configuration: {e}")
            raise
    
    def validate(self) -> bool:
        """Validate configuration values"""
        errors = []
        
        # Validate router_id
        if not self.router_id.strip():
            errors.append("router_id cannot be empty")
        
        # Validate shared_secret
        if len(self.shared_secret) < 8:
            errors.append("shared_secret must be at least 8 characters")
        
        # Validate WiFi config
        if self.wifi.server_port < 1 or self.wifi.server_port > 65535:
            errors.append("wifi.server_port must be between 1 and 65535")
        
        # Validate BLE config
        if self.ble.scan_interval <= 0:
            errors.append("ble.scan_interval must be positive")
        
        # Validate timeouts
        if self.routing.device_timeout <= 0:
            errors.append("routing.device_timeout must be positive")
        
        if self.security.handshake_timeout <= 0:
            errors.append("security.handshake_timeout must be positive")
        
        # Log errors
        for error in errors:
            logger.error(f"Configuration validation error: {error}")
        
        return len(errors) == 0


def create_default_config(router_id: str, shared_secret: str) -> RouterConfig:
    """Create a default configuration"""
    return RouterConfig(
        router_id=router_id,
        shared_secret=shared_secret
    )