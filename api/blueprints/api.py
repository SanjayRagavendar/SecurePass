from flask import Blueprint, jsonify, request
from app.db.db_users import UserDB
from app.crypto import CryptoManager
from app.db.db_vault import VaultDB
from flask_jwt_extended import (
    jwt_required, get_jwt_identity, set_access_cookies, unset_access_cookies, 
    create_access_token, create_refresh_token, set_refresh_cookies, 
    get_jwt, unset_refresh_cookies
)
import logging
from flasgger import swag_from
from datetime import datetime, timezone, timedelta
from api.auth.blacklist import add_token_to_blacklist
from api.auth.middleware import generate_csrf_token, csrf_protection

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
            
        # Try to log in the user
        user = userDB.login_user(username, password)
        if user:
            logging.info(f"User {username} logged in successfully.")
            
            # Create access and refresh tokens
            access_token = create_access_token(identity=user.id)
            refresh_token = create_refresh_token(identity=user.id)
            
            # Create response with tokens for API usage
            response = jsonify({
                "message": "Login successful",
                "access_token": access_token,
                "refresh_token": refresh_token,
                "token_type": "Bearer",
                "expires_in": 3600  # 1 hour in seconds
            })
            
            # Set cookies for both tokens (optional, for browser clients)
            set_access_cookies(response, access_token)
            set_refresh_cookies(response, refresh_token)
            
            return response, 200
        else:
            logging.warning(f"Failed login attempt for user: {username}")
            return jsonify({"error": "Invalid username or password"}), 401
    except Exception as e:
        logging.error(f"Login error: {str(e)}")
        return jsonify({"error": "Internal Server Error"}), 500

@api.route('/logout', methods=['POST'])
@jwt_required()
@csrf_protection(enabled=False)
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
        {'Bearer': []}
    ]
})
def logout():
    """Logout endpoint to invalidate the user's session."""
    try:
        user_id = get_jwt_identity()
        jwt_data = get_jwt()
        
        # Get the token JTI (JWT ID) and expiration
        jti = jwt_data["jti"]
        exp = jwt_data["exp"]
        
        # Add the token to the blacklist
        add_token_to_blacklist(jti, exp)
        
        logging.info(f"User {user_id} logged out successfully.")
        
        # Create response and unset both access and refresh cookies
        response = jsonify({"message": "Logout successful"})
        unset_access_cookies(response)
        unset_refresh_cookies(response)
        
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

def verify_decrypted_text(request, user_id, decrypted_text):
    """Middleware function to verify decrypted text for extra security."""
    user_db = UserDB()
    user = user_db.get_user_by_id(user_id)
    
    if not user:
        return False
    
    # Check the decrypted text if available
    if user.decrypted_text:
        return user.check_decrypted_text(decrypted_text)
    
    # Fall back to basic authentication if decrypted text isn't available
    return True

@api.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
@csrf_protection(enabled=False)
@swag_from({
    'responses': {
        200: {
            'description': 'Token refreshed successfully',
            'schema': {
                'type': 'object',
                'properties': {
                    'message': {'type': 'string'},
                    'access_token': {'type': 'string'}
                }
            }
        },
        401: {
            'description': 'Invalid or expired refresh token'
        }
    },
    'security': [
        {'Bearer': []}
    ]
})
def refresh():
    """Refresh access token using a valid refresh token."""
    try:
        # Get user identity from refresh token
        user_id = get_jwt_identity()
        
        # Create new access token
        access_token = create_access_token(identity=user_id)
        
        # Create response with new access token
        response = jsonify({
            "message": "Token refreshed successfully",
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": 3600  # 1 hour in seconds
        })
        
        # Set access cookie
        set_access_cookies(response, access_token)
        
        return response, 200
    except Exception as e:
        logging.error(f"Token refresh error: {str(e)}")
        return jsonify({"error": "Invalid refresh token"}), 401

@api.route('/check-auth', methods=['GET'])
@jwt_required(optional=True)
@swag_from({
    'responses': {
        200: {
            'description': 'Authentication status',
            'schema': {
                'type': 'object',
                'properties': {
                    'authenticated': {'type': 'boolean'},
                    'user_id': {'type': 'string'}
                }
            }
        }
    }
})
def check_auth():
    """Check if the user is authenticated without requiring authentication."""
    current_user = get_jwt_identity()
    if current_user:
        return jsonify({
            "authenticated": True,
            "user_id": current_user
        }), 200
    else:
        return jsonify({
            "authenticated": False
        }), 200

@api.route('/token-status', methods=['GET'])
@jwt_required()
@swag_from({
    'responses': {
        200: {
            'description': 'Token information',
            'schema': {
                'type': 'object',
                'properties': {
                    'user_id': {'type': 'string'},
                    'expires_at': {'type': 'string', 'format': 'date-time'}
                }
            }
        },
        401: {
            'description': 'Not authenticated'
        }
    },
    'security': [
        {'Bearer': []}
    ]
})
def token_status():
    """Get information about the current authentication token."""
    try:
        # Get JWT claims and identity
        jwt_data = get_jwt()
        user_id = get_jwt_identity()
        
        # Get expiration information
        exp_timestamp = jwt_data.get('exp')
        expires_at = datetime.fromtimestamp(exp_timestamp, tz=timezone.utc)
        
        return jsonify({
            "user_id": user_id,
            "expires_at": expires_at.isoformat()
        }), 200
    except Exception as e:
        logging.error(f"Token status error: {str(e)}")
        return jsonify({"error": "Error retrieving token information"}), 500

@api.route('/auth-info', methods=['GET'])
@swag_from({
    'responses': {
        200: {
            'description': 'Authentication information',
            'schema': {
                'type': 'object',
                'properties': {
                    'message': {'type': 'string'},
                    'usage': {'type': 'string'}
                }
            }
        }
    }
})
def auth_info():
    """Get information about how to use authentication with this API."""
    return jsonify({
        "message": "API Authentication Information",
        "usage": """
This API supports two authentication methods:

1. JWT Bearer Token (recommended for API clients):
   - Login: POST to /api/login with username and password
   - Use the returned access_token in the Authorization header:
     Authorization: Bearer your_access_token_here
   - Refresh token: POST to /api/refresh with the refresh_token
   - Logout: POST to /api/logout

2. Cookie-based Authentication (for browser clients):
   - JWT tokens are automatically stored as HttpOnly cookies
   - No additional steps needed, just make requests
   - Works with same-origin browser requests

For security best practices:
- Store tokens securely
- Refresh tokens when they expire
- Log out when done to invalidate tokens
        """
    }), 200

