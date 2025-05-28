from fastapi import FastAPI, Request, HTTPException
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

def init_db():
    conn = sqlite3.connect("keys.db")
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS license_keys (
        key TEXT PRIMARY KEY,
        hwid TEXT UNIQUE,
        expires_at TEXT
    )""")
    conn.commit()
    conn.close()

init_db()

@app.get("/keys")
def get_keys():
    conn = sqlite3.connect("keys.db")
    c = conn.cursor()
    c.execute("SELECT key, hwid, expires_at FROM license_keys")
    keys = c.fetchall()
    conn.close()
    return [{"key": k, "hwid": h, "expires_at": e} for k, h, e in keys]

class KeyGenRequest(BaseModel):
    count: int
    valid_days: int = 1

@app.post("/generate")
def generate_keys(data: KeyGenRequest):
    conn = sqlite3.connect("keys.db")
    c = conn.cursor()
    new_keys = []
    expiration = (datetime.utcnow() + timedelta(days=data.valid_days)).isoformat()
    for _ in range(data.count):
        new_key = str(uuid.uuid4())
        c.execute("INSERT INTO license_keys (key, hwid, expires_at) VALUES (?, NULL, ?)", (new_key, expiration))
        new_keys.append(new_key)
    conn.commit()
    conn.close()
    return {"new_keys": new_keys}

@app.post("/validate")
async def validate_license(request: Request):
    data = await request.json()
    key = data.get("key")
    hwid = data.get("hwid")
    if not key or not hwid:
        return {"status": "error", "message": "Missing key or hwid"}
    conn = sqlite3.connect("keys.db")
    c = conn.cursor()
    c.execute("SELECT hwid, expires_at FROM license_keys WHERE key = ?", (key,))
    row = c.fetchone()
    if not row:
        conn.close()
        return {"status": "error", "message": "Invalid license key"}
    bound_hwid, expires_at_str = row
    if expires_at_str:
        expires_at = datetime.fromisoformat(expires_at_str)
        if datetime.utcnow() > expires_at:
            conn.close()
            return {"status": "error", "message": "License key expired"}
    if bound_hwid is None:
        c.execute("UPDATE license_keys SET hwid = ? WHERE key = ?", (hwid, key))
        conn.commit()
        conn.close()
        return {"status": "success", "message": "License key bound to HWID"}
    elif bound_hwid == hwid:
        conn.close()
        return {"status": "success", "message": "License key validated"}
    else:
        conn.close()
        return {"status": "error", "message": "License key bound to another HWID"}

@app.post("/auto-login")
async def auto_login(request: Request):
    data = await request.json()
    hwid = data.get("hwid")
    if not hwid:
        return {"status": "error", "message": "Missing hwid"}
    conn = sqlite3.connect("keys.db")
    c = conn.cursor()
    c.execute("SELECT key, expires_at FROM license_keys WHERE hwid = ?", (hwid,))
    row = c.fetchone()
    if row:
        key, expires_at_str = row
        if expires_at_str:
            expires_at = datetime.fromisoformat(expires_at_str)
            if datetime.utcnow() > expires_at:
                conn.close()
                return {"status": "error", "message": "License key expired"}
        conn.close()
        return {"status": "success", "key": key, "message": "Auto-login successful"}
    else:
        conn.close()
        return {"status": "error", "message": "No key bound to this HWID"}

@app.delete("/keys/{license_key}")
def delete_key(license_key: str):
    conn = sqlite3.connect("keys.db")
    c = conn.cursor()
    c.execute("SELECT key FROM license_keys WHERE key = ?", (license_key,))
    if not c.fetchone():
        conn.close()
        raise HTTPException(status_code=404, detail="Key not found")
    c.execute("DELETE FROM license_keys WHERE key = ?", (license_key,))
    conn.commit()
    conn.close()
    return {"status": "success", "message": f"Key {license_key} deleted"}
