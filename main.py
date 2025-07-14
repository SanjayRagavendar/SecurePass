#!/usr/bin/env python3
"""
Password Manager CLI
A secure password management application with encrypted storage.
"""
import os
import sys

def setup_environment():
    """Add the current directory to the Python path."""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    if script_dir not in sys.path:
        sys.path.insert(0, script_dir)

def main():
    """Main entry point for the Password Manager CLI application."""
    setup_environment()
    
    try:
        from app.cli.cli import PasswordManagerCLI
        
        # Start the CLI
        cli = PasswordManagerCLI()
        cli.run()
        return 0
    except ImportError as e:
        print(f"Error importing required modules: {e}")
        print("Make sure all dependencies are installed.")
        return 1
    except Exception as e:
        print(f"Unexpected error: {e}")
        return 1

if __name__ == "__main__":
    # For backwards compatibility, direct execution still works
    print("Note: It's recommended to use 'python manage.py cli' instead.")
    sys.exit(main())