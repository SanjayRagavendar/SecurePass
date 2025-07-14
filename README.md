# Secure Password Manager

A secure password management system with encrypted storage, CLI interface, and REST API.

## Features

- User authentication with secure password storage
- Encrypted password vault for each user
- Command-line interface for managing passwords
- REST API with Swagger documentation
- Web server support with Gunicorn for production
- Backup and recovery functionality
- Support for notes and additional metadata

## Installation

1. Clone the repository
2. Install dependencies:
   ```
   pip install -r requirements.txt
   ```
3. Initialize the system:
   ```
   python setup.py
   ```

## Usage

### CLI Application

To use the command-line interface:

```
python manage.py cli
```

After running the application, you'll be presented with a command-line interface.
Use the `help` command to see all available options:

```
securePass> help
```

### Web API Server

#### Development Mode

For development and testing:

```
python manage.py api --mode dev
```

#### Production Mode with Gunicorn

For production deployment:

```
python manage.py api --mode prod
```

Access the Swagger API documentation at:
```
http://localhost:5000/docs/
```

### Getting Started with CLI

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

## Deployment

For production deployment instructions, see the [Deployment Guide](deployment/README.md).

## Security

- All passwords are encrypted using AES-256
- Master password is never stored, only used for key derivation
- Secure key derivation using PBKDF2 with a high iteration count
- Each user has their own isolated vault database
- JWT-based authentication for the API




