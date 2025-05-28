from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import sqlite3
import uuid
from datetime import datetime, timedelta

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

DB_FILE = "keys.db"

def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    # Create table with expires_at column (ISO datetime string)
    c.execute("""
        CREATE TABLE IF NOT EXISTS license_keys (
            key TEXT PRIMARY KEY,
            hwid TEXT,
            expires_at TEXT
        )
    """)
    conn.commit()
    conn.close()

init_db()

class KeyGenRequest(BaseModel):
    count: int
    expire_days: int

@app.get("/keys")
def get_keys():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT key, hwid, expires_at FROM license_keys")
    rows = c.fetchall()
    conn.close()
    keys = []
    for key, hwid, expires_at in rows:
        keys.append({
            "key": key,
            "hwid": hwid,
            "expires_at": expires_at
        })
    return keys

@app.post("/generate")
def generate_keys(data: KeyGenRequest):
    if data.count < 1 or data.expire_days < 1:
        raise HTTPException(status_code=400, detail="count and expire_days must be positive integers")
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    new_keys = []
    expires_at = (datetime.utcnow() + timedelta(days=data.expire_days)).isoformat()
    for _ in range(data.count):
        new_key = str(uuid.uuid4())
        c.execute("INSERT INTO license_keys (key, hwid, expires_at) VALUES (?, ?, ?)", (new_key, None, expires_at))
        new_keys.append(new_key)
    conn.commit()
    conn.close()
    return {"new_keys": new_keys}

@app.delete("/keys/{key_to_delete}")
def delete_key(key_to_delete: str):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("DELETE FROM license_keys WHERE key = ?", (key_to_delete,))
    deleted = c.rowcount
    conn.commit()
    conn.close()
    if deleted == 0:
        raise HTTPException(status_code=404, detail="Key not found")
    return {"detail": "Key deleted"}
