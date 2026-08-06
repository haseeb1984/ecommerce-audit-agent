import os
from fastapi import FastAPI, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import text
from database import get_db

app = FastAPI()

@app.get("/health-check")
def health_check(db: Session = Depends(get_db)):
    try:
        # Simple ping query to confirm connection
        result = db.execute(text("SELECT 1")).fetchone()
        return {"status": "success", "db_connected": True}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
