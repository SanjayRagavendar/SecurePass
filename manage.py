#!/usr/bin/env python3
"""
SecurePass Manager
A command-line utility to manage the SecurePass password manager system.
Supports both CLI and Web API server modes.
"""
import os
import sys
import argparse
import subprocess
import signal
import logging
from pathlib import Path

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger("securepass-manager")

def setup_environment():
    """Add the current directory to the Python path."""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    if script_dir not in sys.path:
        sys.path.insert(0, script_dir)
    
    # Create necessary directories
    from app.config import APP_Data, BACKUP_DIR, USERS_DIR, LOG_DIR
    for directory in [APP_Data, BACKUP_DIR, USERS_DIR, LOG_DIR]:
        os.makedirs(directory, exist_ok=True)
        logger.debug(f"Ensured directory exists: {directory}")

def run_cli():
    """Run the SecurePass CLI application."""
    from app.cli.cli import main as cli_main
    logger.info("Starting SecurePass CLI application")
    return cli_main()

def run_api_dev():
    """Run the SecurePass API in development mode with Flask's built-in server."""
    from api import create_app
    logger.info("Starting SecurePass API server in development mode")
    app = create_app(testing=True)
    app.run(
        host=os.environ.get('HOST', '127.0.0.1'),
        port=int(os.environ.get('PORT', 5000)),
        debug=True
    )
    return 0

def run_api_prod():
    """Run the SecurePass API in production mode with Gunicorn."""
    try:
        # Check if gunicorn is available
        import gunicorn
    except ImportError:
        logger.error("Gunicorn is not installed. Please install it with 'pip install gunicorn'")
        return 1
    
    logger.info("Starting SecurePass API server in production mode with Gunicorn")
    
    # Default configuration
    workers = os.environ.get('GUNICORN_WORKERS', '4')
    bind_address = os.environ.get('GUNICORN_BIND', '0.0.0.0:5000')
    
    # Build the command
    cmd = [
        sys.executable, '-m', 'gunicorn',
        '--workers', workers,
        '--bind', bind_address,
        '--log-level', 'info',
        'api:create_app()'
    ]
    
    # Start gunicorn as a subprocess
    try:
        process = subprocess.Popen(cmd)
        logger.info(f"Gunicorn started with PID {process.pid}")
        
        # Handle signals for graceful shutdown
        def signal_handler(sig, frame):
            logger.info("Shutting down Gunicorn server...")
            process.terminate()
            process.wait()
            sys.exit(0)
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        
        # Wait for the process to complete
        process.wait()
        return process.returncode
    except KeyboardInterrupt:
        logger.info("Received keyboard interrupt, shutting down...")
        if 'process' in locals():
            process.terminate()
            process.wait()
        return 0
    except Exception as e:
        logger.error(f"Error starting Gunicorn: {e}")
        return 1

def main():
    """Main entry point for the SecurePass Manager."""
    parser = argparse.ArgumentParser(
        description="SecurePass Manager - Secure Password Management System",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    # Create subparsers for different commands
    subparsers = parser.add_subparsers(dest='command', help='Command to run')
    
    # CLI command
    cli_parser = subparsers.add_parser('cli', help='Run the CLI application')
    
    # API server commands
    api_parser = subparsers.add_parser('api', help='Run the API server')
    api_parser.add_argument(
        '--mode', 
        choices=['dev', 'prod'], 
        default='prod',
        help='Server mode: development or production (default: prod)'
    )
    
    # Parse arguments
    args = parser.parse_args()
    
    # Setup environment
    setup_environment()
    
    # Execute the appropriate command
    if args.command == 'cli':
        return run_cli()
    elif args.command == 'api':
        if args.mode == 'dev':
            return run_api_dev()
        else:  # prod mode
            return run_api_prod()
    else:
        # If no command is provided, show help
        parser.print_help()
        return 0

if __name__ == "__main__":
    sys.exit(main())
