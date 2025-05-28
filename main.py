from fastapi import FastAPI
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
    c.execute("""
    CREATE TABLE IF NOT EXISTS license_keys (
        key TEXT PRIMARY KEY,
        hwid TEXT UNIQUE,
        expiry DATE,
        active INTEGER DEFAULT 1,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)
    conn.commit()
    conn.close()

init_db()

# Schemas
class KeyGenRequest(BaseModel):
    count: int
    days: int

class ValidateRequest(BaseModel):
    key: str
    hwid: str

class HWIDRequest(BaseModel):
    hwid: str

# Routes

@app.get("/keys")
def get_keys():
    conn = sqlite3.connect("keys.db")
    c = conn.cursor()
    c.execute("SELECT key, hwid, expiry, active FROM license_keys")
    keys = c.fetchall()
    conn.close()
    return [{"key": k, "hwid": h, "expiry": e, "active": bool(a)} for k, h, e, a in keys]

@app.post("/generate")
def generate_keys(data: KeyGenRequest):
    conn = sqlite3.connect("keys.db")
    c = conn.cursor()
    new_keys = []
    expiry_date = (datetime.now() + timedelta(days=data.days)).strftime("%Y-%m-%d")
    for _ in range(data.count):
        new_key = str(uuid.uuid4())
        c.execute("INSERT INTO license_keys (key, hwid, expiry, active) VALUES (?, NULL, ?, 1)", (new_key, expiry_date))
        new_keys.append(new_key)
    conn.commit()
    conn.close()
    return {"new_keys": new_keys}

@app.post("/validate")
def validate_license(data: ValidateRequest):
    key = data.key.strip()
    hwid = data.hwid.strip()
    conn = sqlite3.connect("keys.db")
    c = conn.cursor()
    c.execute("SELECT hwid, expiry, active FROM license_keys WHERE key = ?", (key,))
    row = c.fetchone()
    if not row:
        conn.close()
        return {"status": "error", "message": "Invalid license key"}
    bound_hwid, expiry, active = row
    if not active:
        conn.close()
        return {"status": "error", "message": "Key is disabled"}
    if expiry and datetime.strptime(expiry, "%Y-%m-%d") < datetime.now():
        conn.close()
        return {"status": "error", "message": "License key has expired"}

    c.execute("SELECT key FROM license_keys WHERE hwid = ?", (hwid,))
    hwid_bound_key = c.fetchone()

    if bound_hwid is None:
        if hwid_bound_key and hwid_bound_key[0] != key:
            conn.close()
            return {"status": "error", "message": "This HWID is already bound to a different key"}
        c.execute("UPDATE license_keys SET hwid = ? WHERE key = ?", (hwid, key))
        conn.commit()
        conn.close()
        return {"status": "success", "message": "License key validated and HWID bound"}
    else:
        if bound_hwid != hwid:
            conn.close()
            return {"status": "error", "message": "HWID does not match the license key"}
        else:
            conn.close()
            return {"status": "success", "message": "License key and HWID validated"}

@app.post("/auto-login")
def auto_login(data: HWIDRequest):
    hwid = data.hwid.strip()
    conn = sqlite3.connect("keys.db")
    c = conn.cursor()
    c.execute("SELECT key FROM license_keys WHERE hwid = ?", (hwid,))
    row = c.fetchone()
    conn.close()
    if row:
        return {"status": "success", "key": row[0], "message": "Auto-login successful"}
    else:
        return {"status": "error", "message": "No key bound to this HWID"}

@app.post("/disable")
def disable_key(data: ValidateRequest):
    conn = sqlite3.connect("keys.db")
    c = conn.cursor()
    c.execute("UPDATE license_keys SET active = 0 WHERE key = ?", (data.key,))
    conn.commit()
    conn.close()
    return {"status": "success", "message": "Key disabled"}

@app.post("/enable")
def enable_key(data: ValidateRequest):
    conn = sqlite3.connect("keys.db")
    c = conn.cursor()
    c.execute("UPDATE license_keys SET active = 1 WHERE key = ?", (data.key,))
    conn.commit()
    conn.close()
    return {"status": "success", "message": "Key enabled"}

@app.post("/delete")
def delete_key(data: ValidateRequest):
    conn = sqlite3.connect("keys.db")
    c = conn.cursor()
    c.execute("DELETE FROM license_keys WHERE key = ?", (data.key,))
    conn.commit()
    conn.close()
    return {"status": "success", "message": "Key deleted"}
