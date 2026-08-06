import os
from urllib.parse import urlparse, urlunparse

def get_async_db_url(use_pooler: bool = True) -> str:
    raw_url = os.getenv("DATABASE_URL", "")
    
    if not raw_url:
        raise ValueError("DATABASE_URL environment variable is not set.")
    
    # 1. Ensure the driver prefix is postgresql+asyncpg://
    if raw_url.startswith("postgresql://"):
        raw_url = raw_url.replace("postgresql://", "postgresql+asyncpg://", 1)
    elif raw_url.startswith("postgres://"):
        raw_url = raw_url.replace("postgres://", "postgresql+asyncpg://", 1)

    # 2. Automatically change port to 6543 if pooler is enabled
    parsed = urlparse(raw_url)
    if use_pooler and (parsed.port == 5432 or parsed.port is None):
        # Reconstruct network location with port 6543
        hostname = parsed.hostname
        user_pass = f"{parsed.username}:{parsed.password}" if parsed.username else ""
        new_netloc = f"{user_pass}@{hostname}:6543" if user_pass else f"{hostname}:6543"
        
        parsed = parsed._replace(netloc=new_netloc)
    
    return urlunparse(parsed)

# Initialize Engine with dynamically updated URL
DATABASE_URL = get_async_db_url(use_pooler=os.getenv("VERCEL") == "1") # Auto-enables pooler on Vercel
