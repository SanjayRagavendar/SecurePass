from sqlalchemy import Column, Integer, String, LargeBinary, DateTime
from sqlalchemy.ext.declarative import declarative_base
from datetime import datetime

Base = declarative_base()

class PasswordVault(Base):
    __tablename__ = 'password_vaults'

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, nullable=False)
    website = Column(String(100), nullable=False)
    username = Column(String(100), nullable=False)
    password = Column(LargeBinary, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    notes = Column(String(255), nullable=True)
