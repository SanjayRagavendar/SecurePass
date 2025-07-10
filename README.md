# Secure Password Manager

A secure password management system with encrypted storage and CLI interface.

## Features

- User authentication with secure password storage
- Encrypted password vault for each user
- Command-line interface for managing passwords
- Backup and recovery functionality
- Support for notes and additional metadata

## Installation

1. Clone the repository
2. Install dependencies:
   ```
   pip install -r requirements.txt
   ```
3. Run the application:
   ```
   python main.py
   ```

## Usage

After running the application, you'll be presented with a command-line interface.
Use the `help` command to see all available options:

```
securePass> help
```

### Getting Started

1. Initialize the application directories:
   ```
   securePass> init
   ```

2. Create a user:
   ```
   securePass> create-user
   ```

3. Login with your credentials:
   ```
   securePass> login
   ```

4. Add a password:
   ```
   securePass> add-password
   ```

5. View your passwords:
   ```
   securePass> list-passwords
   ```

## Security

- All passwords are encrypted using AES-256
- Master password is never stored, only used for key derivation
- Secure key derivation using PBKDF2 with a high iteration count
- Each user has their own isolated vault database


