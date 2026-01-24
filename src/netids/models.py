# src/netids/models.py
from sqlalchemy import Column, Integer, String, DateTime, Text, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import datetime
import os

# Database URL (SQLite for now)
BASE_DIR = os.path.dirname(os.path.dirname(__file__))  # Go up from src/netids to project root
DATABASE_URL = os.getenv("DATABASE_URL", f"sqlite:///{os.path.join(BASE_DIR, 'smartfarm_ids.db')}")


Base = declarative_base()
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine)

class Alert(Base):
    __tablename__ = "alerts"
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    src_ip = Column(String(50))
    dst_ip = Column(String(50))
    alert_type = Column(String(100))
    severity = Column(Integer, default=1)
    description = Column(Text)

def init_db():
    Base.metadata.create_all(bind=engine)

if __name__ == "__main__":
    init_db()
    print("✅ Database initialized successfully!")
