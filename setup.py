#!/usr/bin/env python3
"""
SecurePass Setup Script
Initializes the database and creates required directories for the SecurePass application.
"""
import os
import sys
import logging
from pathlib import Path

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger("securepass-setup")

def setup_environment():
    """Add the current directory to the Python path."""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    if script_dir not in sys.path:
        sys.path.insert(0, script_dir)

def initialize_directories():
    """Create all required directories for the application."""
    from app.config import APP_Data, BACKUP_DIR, USERS_DIR, LOG_DIR
    
    directories = {
        "Application Data": APP_Data,
        "Backup Directory": BACKUP_DIR,
        "Users Directory": USERS_DIR,
        "Log Directory": LOG_DIR
    }
    
    for name, directory in directories.items():
        path = Path(directory)
        if not path.exists():
            path.mkdir(parents=True)
            logger.info(f"Created {name}: {directory}")
        else:
            logger.info(f"{name} already exists: {directory}")

def initialize_database():
    """Initialize the database tables."""
    try:
        from app.db.user_model import Base as UserBase
        from app.db.vault_model import Base as VaultBase
        from sqlalchemy import create_engine
        from app.config import DB_FILE
        
        # Ensure parent directory exists
        os.makedirs(os.path.dirname(DB_FILE), exist_ok=True)
        
        # Create main database
        db_uri = f"sqlite:///{DB_FILE}"
        engine = create_engine(db_uri)
        logger.info(f"Initializing main database at {DB_FILE}")
        UserBase.metadata.create_all(engine)
        logger.info("User database tables created successfully")
        
        # We don't initialize vault databases here as they are created per user
        logger.info("Setup complete. The system is ready to use.")
        
        return True
    except Exception as e:
        logger.error(f"Error initializing database: {e}")
        return False

def main():
    """Main entry point for the setup script."""
    logger.info("Starting SecurePass setup...")
    
    setup_environment()
    initialize_directories()
    if initialize_database():
        logger.info("Setup completed successfully!")
        return 0
    else:
        logger.error("Setup failed. Please check the logs for details.")
        return 1

if __name__ == "__main__":
    sys.exit(main())
