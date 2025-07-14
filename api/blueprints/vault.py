from flask import Blueprint, jsonify, request
from app.db.db_users import UserDB
from app.crypto import CryptoManager
from app.db.db_vault import VaultDB
from flask_jwt_extended import jwt_required, get_jwt_identity
import logging
from flasgger import swag_from
from api.auth.middleware import csrf_protection

vault = Blueprint('vault', __name__)

@vault.route('/passwords', methods=['GET'])
@jwt_required()
@swag_from({
    'responses': {
        200: {
            'description': 'List of passwords',
            'schema': {
                'type': 'object',
                'properties': {
                    'passwords': {
                        'type': 'array',
                        'items': {
                            'type': 'object',
                            'properties': {
                                'id': {'type': 'integer'},
                                'website': {'type': 'string'},
                                'username': {'type': 'string'},
                                'created_at': {'type': 'string', 'format': 'date-time'},
                                'updated_at': {'type': 'string', 'format': 'date-time'}
                            }
                        }
                    }
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
def get_passwords():
    """Get all passwords for the authenticated user."""
    try:
        user_id = get_jwt_identity()
        user_db = UserDB()
        user = user_db.get_user_by_id(user_id)
        
        if not user:
            return jsonify({"error": "User not found"}), 404
        
        # Initialize vault DB for this user
        vault_db = VaultDB(user.username)
        
        # Get all passwords
        passwords = vault_db.get_all_passwords()
        
        # Format response (don't include actual passwords)
        password_list = []
        for pwd in passwords:
            password_list.append({
                'id': pwd.id,
                'website': pwd.website,
                'username': pwd.username,
                'created_at': pwd.created_at.isoformat(),
                'updated_at': pwd.updated_at.isoformat()
            })
        
        return jsonify({"passwords": password_list}), 200
    except Exception as e:
        logging.error(f"Error listing passwords: {str(e)}")
        return jsonify({"error": "Internal Server Error"}), 500


@vault.route('/passwords', methods=['POST'])
@jwt_required()
@csrf_protection(enabled=False)
@swag_from({
    'parameters': [
        {
            'name': 'body',
            'in': 'body',
            'required': True,
            'schema': {
                'type': 'object',
                'properties': {
                    'website': {'type': 'string'},
                    'username': {'type': 'string'},
                    'password': {'type': 'string'},
                    'notes': {'type': 'string'}
                },
                'required': ['website', 'username', 'password']
            }
        }
    ],
    'responses': {
        201: {
            'description': 'Password created successfully',
            'schema': {
                'type': 'object',
                'properties': {
                    'message': {'type': 'string'}
                }
            }
        },
        400: {
            'description': 'Missing required fields'
        },
        401: {
            'description': 'Not authenticated'
        }
    },
    'security': [
        {'Bearer': []}
    ]
})
def add_password():
    """Add a new password entry."""
    try:
        user_id = get_jwt_identity()
        user_db = UserDB()
        user = user_db.get_user_by_id(user_id)
        
        if not user:
            return jsonify({"error": "User not found"}), 404
        
        data = request.json
        website = data.get('website')
        username = data.get('username')
        password = data.get('password')
        notes = data.get('notes')
        
        if not all([website, username, password]):
            return jsonify({"error": "Website, username, and password are required"}), 400
        
        # Get user's password for crypto manager
        # In a real scenario, you would need a temporary session token or re-authenticate
        # This is a simplification for demo purposes
        user_data = user_db.get_user(user.username)
        password_input = request.headers.get('X-Master-Password')
        
        if not password_input:
            return jsonify({"error": "Master password required in X-Master-Password header"}), 400
        
        # Create crypto manager
        crypto = CryptoManager(password_input, user_data.salt)
        
        # Encrypt the password
        encrypted_password = crypto.encrypt(password.encode())
        
        # Encrypt notes if provided
        encrypted_notes = None
        if notes:
            encrypted_notes = crypto.encrypt(notes.encode())
        
        # Initialize vault DB and add password
        vault_db = VaultDB(user.username)
        vault_db.add_password(
            user_id=user_id,
            website=website,
            username=username,
            password=encrypted_password,
            notes=encrypted_notes
        )
        
        return jsonify({"message": "Password added successfully"}), 201
    except Exception as e:
        logging.error(f"Error adding password: {str(e)}")
        return jsonify({"error": "Internal Server Error"}), 500

@vault.route('/passwords/<int:password_id>', methods=['GET'])
@jwt_required()
@swag_from({
    'parameters': [
        {
            'name': 'password_id',
            'in': 'path',
            'required': True,
            'type': 'integer',
            'description': 'ID of the password to retrieve'
        }
    ],
    'responses': {
        200: {
            'description': 'Password details',
            'schema': {
                'type': 'object',
                'properties': {
                    'id': {'type': 'integer'},
                    'website': {'type': 'string'},
                    'username': {'type': 'string'},
                    'password': {'type': 'string'},
                    'notes': {'type': 'string'},
                    'created_at': {'type': 'string', 'format': 'date-time'},
                    'updated_at': {'type': 'string', 'format': 'date-time'}
                }
            }
        },
        401: {
            'description': 'Not authenticated'
        },
        404: {
            'description': 'Password not found'
        }
    },
    'security': [
        {'Bearer': []}
    ]
})
def get_password(password_id):
    """Get a specific password entry."""
    try:
        user_id = get_jwt_identity()
        user_db = UserDB()
        user = user_db.get_user_by_id(user_id)
        
        if not user:
            return jsonify({"error": "User not found"}), 404
        
        # Initialize vault DB
        vault_db = VaultDB(user.username)
        
        # Get the password entry
        password = vault_db.get_password_by_id(password_id)
        if not password:
            return jsonify({"error": "Password not found"}), 404
        
        # Verify the password belongs to the user
        if str(password.user_id) != str(user_id):
            return jsonify({"error": "Unauthorized access"}), 403
        
        # Get user's password for crypto manager
        password_input = request.headers.get('X-Master-Password')
        
        if not password_input:
            return jsonify({"error": "Master password required in X-Master-Password header"}), 400
        
        # Create crypto manager
        user_data = user_db.get_user(user.username)
        crypto = CryptoManager(password_input, user_data.salt)
        
        # Decrypt password and notes
        try:
            decrypted_password = crypto.decrypt(password.password).decode()
            
            notes = None
            if password.notes:
                notes = crypto.decrypt(password.notes).decode()
                
            return jsonify({
                'id': password.id,
                'website': password.website,
                'username': password.username,
                'password': decrypted_password,
                'notes': notes,
                'created_at': password.created_at.isoformat(),
                'updated_at': password.updated_at.isoformat()
            }), 200
        except Exception:
            return jsonify({"error": "Could not decrypt password. Invalid master password."}), 400
    except Exception as e:
        logging.error(f"Error retrieving password: {str(e)}")
        return jsonify({"error": "Internal Server Error"}), 500


@vault.route('/passwords/<int:password_id>', methods=['PUT'])
@jwt_required()
@csrf_protection(enabled=False)
@swag_from({
    'parameters': [
        {
            'name': 'password_id',
            'in': 'path',
            'required': True,
            'type': 'integer',
            'description': 'ID of the password to update'
        },
        {
            'name': 'body',
            'in': 'body',
            'required': True,
            'schema': {
                'type': 'object',
                'properties': {
                    'website': {'type': 'string'},
                    'username': {'type': 'string'},
                    'password': {'type': 'string'},
                    'notes': {'type': 'string'}
                }
            }
        }
    ],
    'responses': {
        200: {
            'description': 'Password updated successfully',
            'schema': {
                'type': 'object',
                'properties': {
                    'message': {'type': 'string'}
                }
            }
        },
        401: {
            'description': 'Not authenticated'
        },
        404: {
            'description': 'Password not found'
        }
    },
    'security': [
        {'Bearer': []}
    ]
})
def update_password(password_id):
    """Update a password entry."""
    try:
        user_id = get_jwt_identity()
        user_db = UserDB()
        user = user_db.get_user_by_id(user_id)
        
        if not user:
            return jsonify({"error": "User not found"}), 404
        
        # Initialize vault DB
        vault_db = VaultDB(user.username)
        
        # Get the password entry
        password = vault_db.get_password_by_id(password_id)
        if not password:
            return jsonify({"error": "Password not found"}), 404
        
        # Verify the password belongs to the user
        if str(password.user_id) != str(user_id):
            return jsonify({"error": "Unauthorized access"}), 403
        
        data = request.json
        if not data:
            return jsonify({"error": "No update data provided"}), 400
        
        # Get user's password for crypto manager
        password_input = request.headers.get('X-Master-Password')
        
        if not password_input:
            return jsonify({"error": "Master password required in X-Master-Password header"}), 400
        
        # Create crypto manager
        user_data = user_db.get_user(user.username)
        crypto = CryptoManager(password_input, user_data.salt)
        
        # Update fields
        update_data = {}
        
        if 'website' in data:
            update_data['website'] = data['website']
            
        if 'username' in data:
            update_data['username'] = data['username']
            
        if 'password' in data:
            try:
                encrypted_password = crypto.encrypt(data['password'].encode())
                update_data['password'] = encrypted_password
            except Exception:
                return jsonify({"error": "Could not encrypt password. Invalid master password."}), 400
                
        if 'notes' in data:
            try:
                encrypted_notes = crypto.encrypt(data['notes'].encode()) if data['notes'] else None
                update_data['notes'] = encrypted_notes
            except Exception:
                return jsonify({"error": "Could not encrypt notes. Invalid master password."}), 400
        
        # Update the password
        vault_db.update_password(password_id, update_data)
        
        return jsonify({"message": "Password updated successfully"}), 200
    except Exception as e:
        logging.error(f"Error updating password: {str(e)}")
        return jsonify({"error": "Internal Server Error"}), 500


@vault.route('/passwords/<int:password_id>', methods=['DELETE'])
@jwt_required()
@csrf_protection(enabled=False)
@swag_from({
    'parameters': [
        {
            'name': 'password_id',
            'in': 'path',
            'required': True,
            'type': 'integer',
            'description': 'ID of the password to delete'
        }
    ],
    'responses': {
        200: {
            'description': 'Password deleted successfully',
            'schema': {
                'type': 'object',
                'properties': {
                    'message': {'type': 'string'}
                }
            }
        },
        401: {
            'description': 'Not authenticated'
        },
        404: {
            'description': 'Password not found'
        }
    },
    'security': [
        {'Bearer': []}
    ]
})
def delete_password(password_id):
    """Delete a password entry."""
    try:
        user_id = get_jwt_identity()
        user_db = UserDB()
        user = user_db.get_user_by_id(user_id)
        
        if not user:
            return jsonify({"error": "User not found"}), 404
        
        # Initialize vault DB
        vault_db = VaultDB(user.username)
        
        # Get the password entry
        password = vault_db.get_password_by_id(password_id)
        if not password:
            return jsonify({"error": "Password not found"}), 404
        
        # Verify the password belongs to the user
        if str(password.user_id) != str(user_id):
            return jsonify({"error": "Unauthorized access"}), 403
        
        # Delete the password
        vault_db.delete_password(password_id)
        
        return jsonify({"message": "Password deleted successfully"}), 200
    except Exception as e:
        logging.error(f"Error deleting password: {str(e)}")
        return jsonify({"error": "Internal Server Error"}), 500


