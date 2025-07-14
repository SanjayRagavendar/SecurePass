from flask import Flask
from flask_jwt_extended import JWTManager
from flasgger import Swagger
from flask_cors import CORS
from datetime import timedelta
import os
import logging
from app.config import APP_Data, LOG_DIR

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
    app.config['JWT_TOKEN_LOCATION'] = ['cookies']
    app.config['JWT_COOKIE_SECURE'] = not testing  # True in production
    app.config['JWT_COOKIE_CSRF_PROTECT'] = not testing  # True in production
    
    # Initialize extensions
    jwt = JWTManager(app)
    CORS(app)
    
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
            "jwt": {
                "type": "apiKey",
                "name": "Authorization",
                "in": "header"
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
