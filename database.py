import os
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

DATABASE_URL = os.getenv("postgresql://postgres:T-jEZ5h*@!w9FBj@db.pfzwlbpgcoosxiqoavhn.supabase.co:5432/postgres")

# FastAPI on Vercel runs in serverless execution environments; use pooled connection settings
engine = create_engine(
    DATABASE_URL, 
    pool_pre_ping=True, 
    pool_size=5, 
    max_overflow=10
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
