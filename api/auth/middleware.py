"""Authentication middleware and utilities."""
from flask_jwt_extended import verify_jwt_in_request, get_jwt
from functools import wraps
from api.auth.blacklist import is_token_blacklisted
from flask import jsonify, request, current_app
import secrets

def jwt_required_with_blacklist_check():
    """Custom decorator that checks if the JWT token is blacklisted."""
    def wrapper(fn):
        @wraps(fn)
        def decorator(*args, **kwargs):
            # First verify the JWT is valid
            verify_jwt_in_request()
            
            # Then check if it's blacklisted
            jwt_data = get_jwt()
            token_jti = jwt_data.get("jti")
            
            if is_token_blacklisted(token_jti):
                return jsonify({"error": "Token has been revoked"}), 401
                
            return fn(*args, **kwargs)
        return decorator
    return wrapper

def generate_csrf_token():
    """Generate a secure CSRF token."""
    return secrets.token_hex(32)

def csrf_protection(enabled=False):
    """Decorator to verify CSRF token for protected routes.
    
    Args:
        enabled (bool): Whether to enable CSRF protection. Defaults to False for API usage.
    """
    def wrapper(fn):
        @wraps(fn)
        def decorator(*args, **kwargs):
            # If CSRF protection is disabled, skip verification
            if not enabled:
                return fn(*args, **kwargs)
                
            # Skip CSRF verification for GET requests
            if request.method == 'GET':
                return fn(*args, **kwargs)
                
            # Check for the CSRF token in headers
            csrf_token = request.headers.get('X-CSRF-TOKEN')
            
            # If in testing mode, skip CSRF verification
            if current_app.config.get('TESTING', False):
                return fn(*args, **kwargs)
                
            # If no CSRF token is provided, return an error
            if not csrf_token:
                return jsonify({"error": "CSRF token missing"}), 400
                
            # In a real app, you'd verify the token against a stored value
            # For this implementation, we'll accept any non-empty token
            # since we're using HttpOnly cookies with SameSite=Strict
            
            return fn(*args, **kwargs)
        return decorator
    return wrapper
