from sqlalchemy import Column, Integer, String, LargeBinary, DateTime
from sqlalchemy.ext.declarative import declarative_base
from datetime import datetime
import uuid

Base = declarative_base()

class User(Base):
    __tablename__ = 'users'
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    username = Column(String(50), unique=True, nullable=False)
    encrypted_text = Column(String(255), nullable=False)
    decrypted_text = Column(String(255), nullable=True)  
    salt = Column(LargeBinary(16), nullable=False)
    recovery_key_hash = Column(LargeBinary(50), nullable=False)
    created_at = Column(DateTime, default=datetime.now())
    last_access_at = Column(DateTime, default=datetime.now(), onupdate=datetime.now())
    
    def check_encrypted_text(self, encrypted_text: str) -> bool:
        """Check if the provided encrypted text matches the stored one."""
        return self.encrypted_text == encrypted_text
        
    def check_decrypted_text(self, decrypted_text: str) -> bool:
        """Check if the provided decrypted text matches the stored one."""
        if self.decrypted_text is None:
            return False
        return self.decrypted_text == decrypted_text