# SecurePass Deployment Guide

This guide provides instructions for deploying SecurePass in a production environment.

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/SanjayRagavendar/SecurePass.git
   cd SecurePass
   ```

2. Create a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install the required packages:
   ```bash
   pip install -r requirements.txt
   ```

4. Initialize the database and required directories:
   ```bash
   python setup.py
   ```

## Running the Application

### CLI Mode

To run the password manager in CLI mode:

```bash
python manage.py cli
```

### API Server

#### Development Mode

To run the API server in development mode (not recommended for production):

```bash
python manage.py api --mode dev
```

#### Production Mode with Gunicorn

To run the API server in production mode with Gunicorn:

```bash
python manage.py api --mode prod
```

You can configure Gunicorn through environment variables:
- `GUNICORN_WORKERS`: Number of worker processes (default: 4)
- `GUNICORN_BIND`: Bind address (default: 0.0.0.0:5000)
- `JWT_SECRET_KEY`: Secret key for JWT tokens (default: a development key)

Example:
```bash
export GUNICORN_WORKERS=8
export GUNICORN_BIND=127.0.0.1:8000
export JWT_SECRET_KEY=your_secure_random_key
python manage.py api
```

## Deploying as a System Service

For Linux systems using systemd:

1. Copy the service file to the systemd directory:
   ```bash
   sudo cp deployment/securepass-api.service /etc/systemd/system/
   ```

2. Edit the service file to match your environment:
   ```bash
   sudo nano /etc/systemd/system/securepass-api.service
   ```

3. Create a dedicated user (recommended):
   ```bash
   sudo useradd -r securepass
   sudo chown -R securepass:securepass /opt/securepass
   ```

4. Reload systemd, enable and start the service:
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable securepass-api
   sudo systemctl start securepass-api
   ```

5. Check the status:
   ```bash
   sudo systemctl status securepass-api
   ```

## Configuring Nginx as a Reverse Proxy

For better security and performance, it's recommended to use Nginx as a reverse proxy:

1. Install Nginx:
   ```bash
   sudo apt-get install nginx
   ```

2. Create a site configuration:
   ```bash
   sudo nano /etc/nginx/sites-available/securepass
   ```

3. Add the following configuration:
   ```nginx
   server {
       listen 80;
       server_name securepass.yourdomain.com;

       location / {
           proxy_pass http://127.0.0.1:5000;
           proxy_set_header Host $host;
           proxy_set_header X-Real-IP $remote_addr;
           proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
           proxy_set_header X-Forwarded-Proto $scheme;
       }
   }
   ```

4. Enable the site and restart Nginx:
   ```bash
   sudo ln -s /etc/nginx/sites-available/securepass /etc/nginx/sites-enabled/
   sudo systemctl restart nginx
   ```

5. Secure with SSL using Let's Encrypt:
   ```bash
   sudo apt-get install certbot python3-certbot-nginx
   sudo certbot --nginx -d securepass.yourdomain.com
   ```

## Backup and Maintenance

1. Regular database backups:
   ```bash
   python manage.py cli
   ```
   Then use the `backup` command within the CLI.

2. System logs are located in the configured LOG_DIR from the application config.
