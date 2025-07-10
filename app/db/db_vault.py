import os
from app.db.vault_model import PasswordVault, Base
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.config import USERS_DIR, CIPHER_MEMORY_SECURITY

class VaultDB:
    def __init__(self, username=None):
        if username:
            os.makedirs(USERS_DIR, exist_ok=True)
            self.uri = f"sqlite:///{USERS_DIR}/{username}_vault.db"
            self.engine = create_engine(self.uri)
            Base.metadata.create_all(self.engine)
            self.Session = sessionmaker(bind=self.engine)
        else:
            self.Session = None

    def add_password(self, user_id, website, username, password, notes=None):
        if not self.Session:
            return False
            
        session = self.Session()
        try:
            password_vault = PasswordVault(
                user_id=user_id,
                website=website,
                username=username,
                password=password,
                notes=notes
            )
            session.add(password_vault)
            session.commit()
            return True
        except Exception as e:
            session.rollback()
            return False
        finally:
            session.close()

    def get_password(self, website):
        if not self.Session:
            return None
            
        session = self.Session()
        try:
            password = session.query(PasswordVault).filter_by(website=website).first()
            return password
        except Exception as e:
            return None
        finally:
            session.close()
        
    def get_all_passwords(self):
        if not self.Session:
            return []
            
        session = self.Session()
        try:
            passwords = session.query(PasswordVault).all()
            return passwords
        except Exception as e:
            return []
        finally:
            session.close()

    def update_password(self, website, new_password):
        if not self.Session:
            return False
            
        session = self.Session()
        try:
            password_vault = session.query(PasswordVault).filter_by(website=website).first()
            if not password_vault:
                return False
            password_vault.password = new_password
            session.commit()
            return True
        except Exception as e:
            session.rollback()
            return False
        finally:
            session.close()
            
    def delete_password(self, website):
        if not self.Session:
            return False
            
        session = self.Session()
        try:
            password_vault = session.query(PasswordVault).filter_by(website=website).first()
            if not password_vault:
                return False
            session.delete(password_vault)
            session.commit()
            return True
        except Exception as e:
            session.rollback()
            return False
        finally:
            session.close()
