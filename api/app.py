from flask import Flask
from flask_jwt_extended import JWTManager
from flasgger import Swagger
from flask_cors import CORS
from datetime import timedelta
import os
import logging
from app.config import APP_Data, LOG_DIR
from api.auth.blacklist import is_token_blacklisted, add_token_to_blacklist

# Import blueprints
from api.blueprints import api, vault

# Set up logging
os.makedirs(LOG_DIR, exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s in %(module)s: %(message)s',
    filename=os.path.join(LOG_DIR, 'api.log'),
)

def create_app(testing=False):
    """Create and configure the Flask application."""
    app = Flask(__name__)
    
    # Configure app
    app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'dev-secret-key')
    app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)
    app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(days=30)
    app.config['JWT_TOKEN_LOCATION'] = ['cookies', 'headers']  # Allow both cookies and headers
    app.config['JWT_COOKIE_SECURE'] = not testing  # True in production
    app.config['JWT_COOKIE_CSRF_PROTECT'] = False  # Disable CSRF for API usage
    app.config['JWT_CSRF_IN_COOKIES'] = False
    app.config['JWT_COOKIE_SAMESITE'] = 'Lax'  # Less restrictive for API usage
    app.config['JWT_COOKIE_DOMAIN'] = None  # Restrict to same domain
    app.config['JWT_HEADER_NAME'] = 'Authorization'
    app.config['JWT_HEADER_TYPE'] = 'Bearer'
    
    # Initialize extensions
    jwt = JWTManager(app)
    CORS(app)
    
    # Token validity check
    @jwt.token_in_blocklist_loader
    def check_if_token_in_blacklist(jwt_header, jwt_payload):
        jti = jwt_payload["jti"]
        return is_token_blacklisted(jti)
    
    # Handle revoked tokens
    @jwt.revoked_token_loader
    def handle_revoked_token(jwt_header, jwt_payload):
        return {
            "error": "Token has been revoked",
            "code": "token_revoked"
        }, 401
    
    # Configure Swagger
    swagger_config = {
        "headers": [],
        "specs": [
            {
                "endpoint": 'apispec',
                "route": '/apispec.json',
                "rule_filter": lambda rule: True,
                "model_filter": lambda tag: True,
            }
        ],
        "static_url_path": "/flasgger_static",
        "swagger_ui": True,
        "specs_route": "/docs/"
    }
    
    swagger_template = {
        "swagger": "2.0",
        "info": {
            "title": "Password Manager API",
            "description": "API for securely managing passwords",
            "version": "1.0.0"
        },
        "securityDefinitions": {
            "Bearer": {
                "type": "apiKey",
                "name": "Authorization",
                "in": "header",
                "description": "JWT Authorization header using the Bearer scheme. Example: 'Authorization: Bearer {token}'"
            }
        },
    }
    
    swagger = Swagger(app, config=swagger_config, template=swagger_template)
    
    # Register blueprints
    app.register_blueprint(api, url_prefix='/api')
    app.register_blueprint(vault, url_prefix='/api/vault')
    
    # Initialize directories
    @app.before_request
    def initialize_directories():
        """Create required directories if they don't exist."""
        os.makedirs(APP_Data, exist_ok=True)
    
    # Simple index route
    @app.route('/')
    def index():
        return {
            "application": "SecurePass Password Manager API",
            "documentation": "/docs/",
            "status": "running"
        }
    
    return app
