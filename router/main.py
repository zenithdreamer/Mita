#!/usr/bin/env python3
"""
Multi-Protocol IoT Network Router
Main entry point for the IoT router application with proper CLI interface
"""

import argparse
import logging
import os
import sys
import signal
import time
from pathlib import Path

from core.router import IoTRouter
from core.config import RouterConfig
from core.logger import setup_logging


def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="Multi-Protocol IoT Network Router",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                          # Run with default config
  %(prog)s -c custom_config.json    # Use custom configuration
  %(prog)s -v                       # Verbose logging
  %(prog)s -vv                      # Debug logging
  %(prog)s --wifi-only               # Enable only WiFi transport
  %(prog)s --ble-only                # Enable only BLE transport
        """
    )
    
    # Configuration
    parser.add_argument('-c', '--config', 
                       default='router_config.json',
                       help='Configuration file path (default: router_config.json)')
    
    # Logging options
    parser.add_argument('-v', '--verbose', 
                       action='count', 
                       default=0,
                       help='Increase verbosity (-v for INFO, -vv for DEBUG)')
    
    parser.add_argument('--log-file',
                       help='Log to file instead of console')
    
    # Transport options
    parser.add_argument('--wifi-only', 
                       action='store_true',
                       help='Enable only WiFi transport')
    
    parser.add_argument('--ble-only', 
                       action='store_true',
                       help='Enable only BLE transport')
    
    # Development options
    parser.add_argument('--no-setup', 
                       action='store_true',
                       help='Skip WiFi AP setup (for development)')
    
    parser.add_argument('--status-interval',
                       type=int,
                       help='Status reporting interval in seconds')
    
    return parser.parse_args()


def check_root_privileges():
    """Check if running with required privileges"""
    if os.name == 'posix' and os.geteuid() != 0:
        print("ERROR: This router must be run as root to create WiFi Access Points.")
        print("Please run with: sudo python3 main.py")
        return False
    return True


def setup_signal_handlers(router):
    """Setup signal handlers for graceful shutdown"""
    def signal_handler(signum, frame):
        logger = logging.getLogger(__name__)
        logger.info(f"Received signal {signum}, shutting down gracefully...")
        router.stop()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)


def main():
    """Main entry point"""
    try:
        # Parse arguments
        args = parse_arguments()
        
        # Setup logging based on verbosity
        log_level = logging.WARNING
        if args.verbose == 1:
            log_level = logging.INFO
        elif args.verbose >= 2:
            log_level = logging.DEBUG
            
        setup_logging(level=log_level, log_file=args.log_file)
        logger = logging.getLogger(__name__)
        
        # Check privileges
        if not args.no_setup and not check_root_privileges():
            sys.exit(1)
        
        # Load configuration
        config_path = Path(args.config)
        if not config_path.exists():
            logger.error(f"Configuration file not found: {config_path}")
            sys.exit(1)
            
        config = RouterConfig.from_file(config_path)
        
        # Apply command-line overrides
        if args.wifi_only:
            config.wifi.enabled = True
            config.ble.enabled = False
            logger.info("WiFi-only mode enabled")
            
        if args.ble_only:
            config.wifi.enabled = False
            config.ble.enabled = True
            logger.info("BLE-only mode enabled")
            
        if args.no_setup:
            config.development.skip_ap_setup = True
            logger.info("Skipping WiFi AP setup (development mode)")
            
        if args.status_interval:
            config.logging.status_interval = args.status_interval
        
        # Create and start router
        logger.info("Starting Multi-Protocol IoT Router...")
        logger.info(f"Router ID: {config.router_id}")
        logger.info(f"Configuration: {config_path}")
        
        router = IoTRouter(config)
        setup_signal_handlers(router)
        
        # Start router (this will block)
        router.start()
        
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()