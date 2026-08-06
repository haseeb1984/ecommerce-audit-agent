from fastapi import FastAPI, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text
from database import get_async_db

app = FastAPI()

@app.get("/health-check")
async def health_check(db: AsyncSession = Depends(get_async_db)):
    try:
        # Non-blocking async execution
        result = await db.execute(text("SELECT 1"))
        return {"status": "success", "db_connected": True}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
