## This file contains the configuration for the application.
import os

# File paths and directories
APP_Data = os.path.expanduser("~/.securepass")
DB_FILE = os.path.join(APP_Data, "users.db")
BACKUP_DIR = os.path.join(APP_Data, "backups")
USERS_DIR = os.path.join(APP_Data, "users")
LOG_DIR = os.path.join(APP_Data, "logs")
LOG_FILE = os.path.join(LOG_DIR, "app.log")


# Cryptography settings
PBKDF_ITERATIONS = 100000
KEYLENGTH = 32  # 256 bits
SALT_LENGTH = 16  # 128 bits

# BACKUP SETTINGS
MAX_BACKUP_SIZE = 104857600  # 100 MB

# DB Settings
DB_TIMEOUT = 30
CIPHER_MEMORY_SECURITY = True