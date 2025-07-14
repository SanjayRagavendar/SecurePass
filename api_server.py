#!/usr/bin/env python3
"""
Password Manager Server API
A secure password management API with encrypted storage.

Note: This file is maintained for backwards compatibility.
It's recommended to use 'python manage.py api' instead.
"""
import os
import sys

def setup_environment():
    """Add the current directory to the Python path."""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    if script_dir not in sys.path:
        sys.path.insert(0, script_dir)

def main():
    """Main entry point for the Password Manager API server."""
    setup_environment()
    
    try:
        from api import create_app
        
        # Create and run the Flask application
        app = create_app(testing=os.environ.get('FLASK_ENV') == 'development')
        app.run(
            host=os.environ.get('HOST', '0.0.0.0'),
            port=int(os.environ.get('PORT', 5000)),
            debug=os.environ.get('FLASK_ENV') == 'development'
        )
    except ImportError as e:
        print(f"Error importing required modules: {e}")
        print("Make sure all dependencies are installed.")
        return 1
    except Exception as e:
        print(f"Unexpected error: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    print("Note: It's recommended to use 'python manage.py api' instead.")
    sys.exit(main())
