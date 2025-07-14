from flask import Blueprint, jsonify, request
from app.db.db_users import UserDB
from app.crypto import CryptoManager
from app.db.db_vault import VaultDB
from flask_jwt_extended import jwt_required, get_jwt_identity, set_access_cookies, unset_access_cookies, create_access_token
import logging
from flasgger import swag_from

api = Blueprint('api', __name__)
logging.basicConfig(
    level=logging.DEBUG,  
    format='[%(asctime)s] %(levelname)s in %(module)s: %(message)s',
    filename='app.log', 
)

@api.route('/health', methods=['GET'])
@swag_from({
    'responses': {
        200: {
            'description': 'API is working correctly',
            'schema': {
                'type': 'object',
                'properties': {
                    'status': {'type': 'string'}
                }
            }
        }
    }
})
def health_check():
    """Health check endpoint to verify the API is running."""
    return jsonify({"status": "ok"}), 200

@api.route('/login', methods=['POST'])
@swag_from({
    'parameters': [
        {
            'name': 'body',
            'in': 'body',
            'required': True,
            'schema': {
                'type': 'object',
                'properties': {
                    'username': {'type': 'string'},
                    'password': {'type': 'string'}
                },
                'required': ['username', 'password']
            }
        }
    ],
    'responses': {
        200: {
            'description': 'Login successful',
            'schema': {
                'type': 'object',
                'properties': {
                    'message': {'type': 'string'}
                }
            }
        },
        400: {
            'description': 'Missing username or password'
        },
        401: {
            'description': 'Invalid credentials'
        }
    }
})
def login():
    """Login endpoint to authenticate users."""
    try:
        userDB = UserDB()
        data = request.json
        username = data.get('username')
        password = data.get('password')
        if not username or not password:
            return jsonify({"error": "Username and password are required"}), 400
        if user := userDB.verify_user(username, password):
            logging.info(f"User {username} logged in successfully.")
            access_token = create_access_token(identity=user.id)
            response = jsonify({"message": "Login successful"})
            set_access_cookies(response, access_token)
            return response, 200
        else:
            return jsonify({"error": "Invalid username or password"}), 401
    except Exception as e:
        logging.error(f"Login error: {str(e)}")
        return jsonify({"error": "Internal Server Error"}), 500

@api.route('/logout', methods=['POST'])
@jwt_required()
@swag_from({
    'responses': {
        200: {
            'description': 'Logout successful',
            'schema': {
                'type': 'object',
                'properties': {
                    'message': {'type': 'string'}
                }
            }
        },
        401: {
            'description': 'Not authenticated'
        }
    },
    'security': [
        {'jwt': []}
    ]
})
def logout():
    """Logout endpoint to invalidate the user's session."""
    try:
        logging.info(f"User {get_jwt_identity()} logged out successfully.")
        response = jsonify({"message": "Logout successful"})
        unset_access_cookies(response)
        return response, 200
    except Exception as e:
        logging.error(f"Logout error: {str(e)}")
        return jsonify({"error": "Internal Server Error"}), 500
    
@api.route('/register', methods=['POST'])
@swag_from({
    'parameters': [
        {
            'name': 'body',
            'in': 'body',
            'required': True,
            'schema': {
                'type': 'object',
                'properties': {
                    'username': {'type': 'string'},
                    'password': {'type': 'string'}
                },
                'required': ['username', 'password']
            }
        }
    ],
    'responses': {
        201: {
            'description': 'User created successfully',
            'schema': {
                'type': 'object',
                'properties': {
                    'message': {'type': 'string'},
                    'recovery_key': {'type': 'string'}
                }
            }
        },
        400: {
            'description': 'Missing data or user already exists'
        },
        500: {
            'description': 'Internal server error'
        }
    }
})
def register():
    """Register a new user."""
    try:
        data = request.json
        username = data.get('username')
        password = data.get('password')
        
        if not username or not password:
            return jsonify({"error": "Username and password are required"}), 400
            
        user_db = UserDB()
        if user_db.user_exists(username):
            return jsonify({"error": f"User '{username}' already exists"}), 400
            
        # Generate a salt for this user
        salt = CryptoManager.generate_salt()
        
        # Create a crypto manager instance for this user
        crypto = CryptoManager(password, salt)
        
        # Create an encrypted verification token
        # We'll use username as the verification data
        encrypted_text = crypto.encrypt(username.encode())
        
        # Generate a recovery key 
        recovery_key = CryptoManager.generate_recovery_key()
        recovery_key_hash = crypto.encrypt(recovery_key)
        
        # Register the user
        user_db.register_user(
            username=username,
            salt=salt,
            encrypted_text=encrypted_text,
            recovery_key_hash=recovery_key_hash
        )
        
        # Create a vault DB for this user
        vault_db = VaultDB(username)
        
        logging.info(f"User {username} registered successfully")
        return jsonify({
            "message": "User registered successfully",
            "recovery_key": recovery_key.decode()
        }), 201
    except Exception as e:
        logging.error(f"Registration error: {str(e)}")
        return jsonify({"error": "Internal Server Error"}), 500
