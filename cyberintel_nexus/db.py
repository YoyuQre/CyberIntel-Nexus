import os
import datetime
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Boolean, ForeignKey, Text
from sqlalchemy.orm import declarative_base, sessionmaker

DATABASE_URL = os.environ.get("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL environment variable is not set")

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

class Session(Base):
    __tablename__ = "sessions"
    session_id = Column(String, primary_key=True, index=True)
    current_phase = Column(String)
    status_message = Column(String)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)

class RuleArtifact(Base):
    __tablename__ = "rule_artifacts"
    id = Column(String, primary_key=True, index=True)
    session_id = Column(String, ForeignKey("sessions.session_id"))
    rule_type = Column(String)
    rule_name = Column(String)
    content = Column(Text)
    target_platform = Column(String)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    committed = Column(Boolean, default=False)
    commit_id = Column(String, nullable=True)
    approved_by = Column(String, nullable=True)
    approval_timestamp = Column(DateTime, nullable=True)

def init_db():
    Base.metadata.create_all(bind=engine)
