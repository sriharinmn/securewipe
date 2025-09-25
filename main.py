# =============================================================================
# main.py - Main Application Entry Point with Dry-Run Support
# =============================================================================

import sys
import os
import argparse
import logging
from gui.interface import SecureWiperGUI
from core.wiper import DataWiper
from core.detector import DeviceDetector

def setup_logging():
    """Setup logging configuration"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('secure_wiper.log'),
            logging.StreamHandler()
        ]
    )

def simulate_wipe(device, method, passes=3):
    """Simulate a wipe without writing to disk"""
    logger = logging.getLogger("DryRun")
    logger.info(f"[DRY-RUN] Would wipe {device} using {method.upper()} method")
    for i in range(1, passes + 1):
        logger.info(f"[DRY-RUN] Starting pass {i}/{passes}")
    logger.info("[DRY-RUN] Wipe simulation completed. Certificate ID: DRYRUN-0000-0000")

def main():
    """Main application entry point"""
    setup_logging()
    logger = logging.getLogger(__name__)
    
    parser = argparse.ArgumentParser(description='Secure Data Wiping Tool')
    parser.add_argument('--cli', action='store_true', help='Run in CLI mode')
    parser.add_argument('--device', help='Target device path')
    parser.add_argument('--method', default='dod', choices=['dod', 'nist'], 
                        help='Wiping method')
    parser.add_argument('--dry-run', action='store_true', help='Simulate wipe without writing')
    
    args = parser.parse_args()
    
    if args.cli:
        # CLI Mode
        if not args.device:
            logger.error("Device path required for CLI mode")
            sys.exit(1)
        
        wiper = DataWiper()
        try:
            if args.dry_run:
                simulate_wipe(args.device, args.method)
            else:
                wiper.wipe_device(args.device, args.method)
                logger.info("Wiping completed successfully")
        except Exception as e:
            logger.error(f"Wiping failed: {e}")
            sys.exit(1)
    else:
        # GUI Mode
        try:
            app = SecureWiperGUI()
            app.run()
        except Exception as e:
            logger.error(f"GUI startup failed: {e}")
            sys.exit(1)

if __name__ == "__main__":
    main()
