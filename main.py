from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import sqlite3
import uuid

app = FastAPI()

# Allow frontend to access API (adjust origins in production)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize SQLite DB and table if not exists
def init_db():
    conn = sqlite3.connect("keys.db")
    c = conn.cursor()
    c.execute("""
    CREATE TABLE IF NOT EXISTS license_keys (
        key TEXT PRIMARY KEY,
        hwid TEXT UNIQUE
    )
    """)
    conn.commit()
    conn.close()

init_db()

# Schemas for requests
class KeyGenRequest(BaseModel):
    count: int

class ValidateRequest(BaseModel):
    key: str
    hwid: str

class HWIDRequest(BaseModel):
    hwid: str

# GET /keys - list all keys and their HWIDs
@app.get("/keys")
def get_keys():
    conn = sqlite3.connect("keys.db")
    c = conn.cursor()
    c.execute("SELECT key, hwid FROM license_keys")
    keys = c.fetchall()
    conn.close()
    return [{"key": k, "hwid": h} for k, h in keys]

# POST /generate - generate new license keys
@app.post("/generate")
def generate_keys(data: KeyGenRequest):
    conn = sqlite3.connect("keys.db")
    c = conn.cursor()
    new_keys = []
    for _ in range(data.count):
        new_key = str(uuid.uuid4())
        c.execute("INSERT INTO license_keys (key, hwid) VALUES (?, NULL)", (new_key,))
        new_keys.append(new_key)
    conn.commit()
    conn.close()
    return {"new_keys": new_keys}

# POST /validate - validate key + hwid, bind hwid if unbound, enforce rules
@app.post("/validate")
def validate_license(data: ValidateRequest):
    key = data.key.strip()
    hwid = data.hwid.strip()

    conn = sqlite3.connect("keys.db")
    c = conn.cursor()

    # Check if key exists
    c.execute("SELECT hwid FROM license_keys WHERE key = ?", (key,))
    row = c.fetchone()
    if not row:
        conn.close()
        return {"status": "error", "message": "Invalid license key"}

    bound_hwid = row[0]

    # Check if this HWID is already bound to a different key
    c.execute("SELECT key FROM license_keys WHERE hwid = ?", (hwid,))
    hwid_bound_key = c.fetchone()

    if bound_hwid is None:
        # Key not bound yet, check if HWID is already bound to a different key
        if hwid_bound_key and hwid_bound_key[0] != key:
            conn.close()
            return {"status": "error", "message": "This HWID is already bound to a different key"}

        # Bind HWID to the key
        c.execute("UPDATE license_keys SET hwid = ? WHERE key = ?", (hwid, key))
        conn.commit()
        conn.close()
        return {"status": "success", "message": "License key validated and HWID bound"}

    else:
        # Key already bound, verify HWID matches
        if bound_hwid != hwid:
            conn.close()
            return {"status": "error", "message": "HWID does not match the license key"}
        else:
            conn.close()
            return {"status": "success", "message": "License key and HWID validated"}

# POST /auto-login - auto login user by HWID only (no key input)
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
