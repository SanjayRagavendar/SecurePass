"""JWT token blacklist implementation."""
from datetime import datetime
from flask_jwt_extended import get_jti

# In-memory blacklist (in production, use Redis or database)
_token_blacklist = set()

def add_token_to_blacklist(token_jti, expires_at):
    """Add a token to the blacklist."""
    _token_blacklist.add(token_jti)

def is_token_blacklisted(token_jti):
    """Check if a token is blacklisted."""
    return token_jti in _token_blacklist

def cleanup_blacklist():
    """Remove expired tokens from the blacklist.
    
    In a real production system, you would use Redis with expirations
    or a database with scheduled cleanup.
    """
    # This is a no-op for our simple in-memory implementation
    # In a real system, you would implement token cleanup logic here
    pass
