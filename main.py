from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import sqlite3
import uuid

app = FastAPI()

# Allow frontend to access
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # For dev, make secure in prod
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize DB
def init_db():
    conn = sqlite3.connect("keys.db")
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS license_keys (
        key TEXT PRIMARY KEY,
        hwid TEXT
    )""")
    conn.commit()
    conn.close()

init_db()

# Get all keys
@app.get("/keys")
def get_keys():
    conn = sqlite3.connect("keys.db")
    c = conn.cursor()
    c.execute("SELECT key, hwid FROM license_keys")
    keys = c.fetchall()
    conn.close()
    return [{"key": k, "hwid": h} for k, h in keys]

# Generate new keys
class KeyGenRequest(BaseModel):
    count: int

@app.post("/generate")
def generate_keys(data: KeyGenRequest):
    conn = sqlite3.connect("keys.db")
    c = conn.cursor()
    new_keys = []
    for _ in range(data.count):
        new_key = str(uuid.uuid4())
        c.execute("INSERT INTO license_keys (key, hwid) VALUES (?, ?)", (new_key, None))
        new_keys.append(new_key)
    conn.commit()
    conn.close()
    return {"new_keys": new_keys}

# Validation request schema
class ValidateRequest(BaseModel):
    key: str
    hwid: str

# Validate license key + HWID
@app.post("/validate")
def validate_key(data: ValidateRequest):
    conn = sqlite3.connect("keys.db")
    c = conn.cursor()

    # Check if key exists
    c.execute("SELECT hwid FROM license_keys WHERE key = ?", (data.key,))
    result = c.fetchone()
    if not result:
        conn.close()
        return {"status": "error", "message": "Invalid key"}

    stored_hwid = result[0]

    # If no HWID bound, bind this one
    if stored_hwid is None:
        c.execute("UPDATE license_keys SET hwid = ? WHERE key = ?", (data.hwid, data.key))
        conn.commit()
        conn.close()
        return {"status": "success", "message": "Key validated and HWID bound"}

    # If HWID matches, success
    if stored_hwid == data.hwid:
        conn.close()
        return {"status": "success", "message": "Key validated"}

    # Otherwise, HWID mismatch
    conn.close()
    return {"status": "error", "message": "HWID does not match"}
