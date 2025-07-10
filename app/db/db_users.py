import os
import hashlib
from app.config import DB_FILE, USERS_DIR
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.db.user_model import Base, User
from app.crypto import CryptoManager

DB_URI = f"sqlite:///{DB_FILE}"

class UserDB:
    def __init__(self):
        os.makedirs(os.path.dirname(DB_FILE), exist_ok=True)
        os.makedirs(USERS_DIR, exist_ok=True)
        self.engine = create_engine(DB_URI)
        Base.metadata.create_all(self.engine)
        self.Session = sessionmaker(bind=self.engine)

    def register_user(self, username, salt, encrypted_text, recovery_key_hash):
        session = self.Session()
        try:
            new_user = User(username=username, salt=salt, encrypted_text=encrypted_text, 
                           recovery_key_hash=recovery_key_hash)
            session.add(new_user)
            session.commit()
            return True
        except Exception as e:
            session.rollback()
            raise e
        finally:
            session.close()
    
    def user_exists(self, username):
        session = self.Session()
        try:
            user = session.query(User).filter_by(username=username).first()
            return user is not None
        except Exception as e:
            raise e
        finally:
            session.close()
            
    def get_user(self, username):
        session = self.Session()
        try:
            user = session.query(User).filter_by(username=username).first()
            return user
        except Exception as e:
            raise e
        finally:
            session.close()
    
    def get_all_users(self):
        session = self.Session()
        try:
            users = session.query(User.username).all()
            return [user[0] for user in users]
        except Exception as e:
            raise e
        finally:
            session.close()
    
    def verify_user(self, username, password):
        user = self.get_user(username)
        if not user:
            return False
        
        try:
            # Create a crypto manager with the provided password and stored salt
            crypto_manager = CryptoManager(password, user.salt)
            
            # The encrypted_text acts as a verification token
            decrypted = crypto_manager.decrypt(user.encrypted_text.encode())
            
            # If decryption succeeds, the password is correct
            return True
        except:
            return False
        
    def update_user(self, username, encrypted_text):
        session = self.Session()
        try:
            user = session.query(User).filter_by(username=username).first()
            if user:
                user.encrypted_text = encrypted_text
                session.commit()
            else:
                raise ValueError("User not found")
        except Exception as e:
            session.rollback()
            raise e
        finally:
            session.close()

    def delete_user(self, username):
        session = self.Session()
        try:
            vault_db_path = os.path.join(USERS_DIR, f"{username}_vault.db")
            if os.path.exists(vault_db_path):
                os.remove(vault_db_path)
                
            user = session.query(User).filter_by(username=username).first()
            if user:
                session.delete(user)
                session.commit()
            else:
                raise ValueError("User not found")
        except Exception as e:
            session.rollback()
            raise e
        finally:
            session.close()