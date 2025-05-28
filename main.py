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
        name TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)
    conn.commit()
    conn.close()

init_db()

class KeyGenRequest(BaseModel):
    count: int
    days: int  # 0 = infinite

class ValidateRequest(BaseModel):
    key: str
    hwid: str
    name: str = None  # optional name for setting on redeem

class KeyActionRequest(BaseModel):
    key: str

class KeyExtendRequest(BaseModel):
    key: str
    days: int

class CompensateRequest(BaseModel):
    days: int

class HWIDRequest(BaseModel):
    hwid: str

class SetNameRequest(BaseModel):
    key: str
    name: str

@app.get("/keys")
def get_keys():
    conn = sqlite3.connect("keys.db")
    c = conn.cursor()
    c.execute("SELECT key, hwid, expiry, active, name FROM license_keys")
    keys = c.fetchall()
    conn.close()
    return [{"key": k, "hwid": h, "expiry": e, "active": bool(a), "name": n} for k, h, e, a, n in keys]

@app.post("/generate")
def generate_keys(data: KeyGenRequest):
    conn = sqlite3.connect("keys.db")
    c = conn.cursor()
    new_keys = []
    expiry_date = None if data.days == 0 else (datetime.now() + timedelta(days=data.days)).strftime("%Y-%m-%d")
    for _ in range(data.count):
        new_key = str(uuid.uuid4())
        c.execute("INSERT INTO license_keys (key, hwid, expiry, active, name) VALUES (?, NULL, ?, 1, NULL)", (new_key, expiry_date))
        new_keys.append(new_key)
    conn.commit()
    conn.close()
    return {"new_keys": new_keys}

@app.post("/validate")
def validate_license(data: ValidateRequest):
    key = data.key.strip()
    hwid = data.hwid.strip()
    name = data.name.strip() if data.name else None

    conn = sqlite3.connect("keys.db")
    c = conn.cursor()
    c.execute("SELECT hwid, expiry, active, name FROM license_keys WHERE key = ?", (key,))
    row = c.fetchone()
    if not row:
        conn.close()
        return {"status": "error", "message": "Invalid license key"}

    bound_hwid, expiry, active, current_name = row

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
        # bind HWID
        c.execute("UPDATE license_keys SET hwid = ? WHERE key = ?", (hwid, key))
        conn.commit()

        # set name if provided and empty
        if name and not current_name:
            c.execute("UPDATE license_keys SET name = ? WHERE key = ?", (name, key))
            conn.commit()

        conn.close()
        return {"status": "success", "message": "License key validated and HWID bound"}

    else:
        if bound_hwid != hwid:
            conn.close()
            return {"status": "error", "message": "HWID does not match the license key"}
        else:
            # set name if provided and empty
            if name and not current_name:
                c.execute("UPDATE license_keys SET name = ? WHERE key = ?", (name, key))
                conn.commit()
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
def disable_key(data: KeyActionRequest):
    conn = sqlite3.connect("keys.db")
    c = conn.cursor()
    c.execute("UPDATE license_keys SET active = 0 WHERE key = ?", (data.key,))
    conn.commit()
    conn.close()
    return {"status": "success", "message": "Key disabled"}

@app.post("/enable")
def enable_key(data: KeyActionRequest):
    conn = sqlite3.connect("keys.db")
    c = conn.cursor()
    c.execute("UPDATE license_keys SET active = 1 WHERE key = ?", (data.key,))
    conn.commit()
    conn.close()
    return {"status": "success", "message": "Key enabled"}

@app.post("/delete")
def delete_key(data: KeyActionRequest):
    conn = sqlite3.connect("keys.db")
    c = conn.cursor()
    c.execute("DELETE FROM license_keys WHERE key = ?", (data.key,))
    conn.commit()
    conn.close()
    return {"status": "success", "message": "Key deleted"}

@app.post("/extend")
def extend_key(data: KeyExtendRequest):
    conn = sqlite3.connect("keys.db")
    c = conn.cursor()
    c.execute("SELECT expiry FROM license_keys WHERE key = ?", (data.key,))
    row = c.fetchone()
    if not row:
        conn.close()
        return {"status": "error", "message": "Key not found"}

    expiry = row[0]
    if expiry:
        new_expiry = datetime.strptime(expiry, "%Y-%m-%d") + timedelta(days=data.days)
    else:
        new_expiry = datetime.now() + timedelta(days=data.days)

    c.execute("UPDATE license_keys SET expiry = ? WHERE key = ?", (new_expiry.strftime("%Y-%m-%d"), data.key))
    conn.commit()
    conn.close()
    return {"status": "success", "message": f"Expiry extended to {new_expiry.date()}"}

@app.post("/compensate")
def compensate_all(data: CompensateRequest):
    conn = sqlite3.connect("keys.db")
    c = conn.cursor()
    c.execute("SELECT key, expiry FROM license_keys WHERE active = 1")
    all_keys = c.fetchall()

    for key, expiry in all_keys:
        if expiry:
            new_expiry = datetime.strptime(expiry, "%Y-%m-%d") + timedelta(days=data.days)
        else:
            # infinity keys remain infinite; don't change expiry for them
            continue
        c.execute("UPDATE license_keys SET expiry = ? WHERE key = ?", (new_expiry.strftime("%Y-%m-%d"), key))

    conn.commit()
    conn.close()
    return {"status": "success", "message": f"All keys extended by {data.days} days"}

@app.post("/set-name")
def set_name(data: SetNameRequest):
    conn = sqlite3.connect("keys.db")
    c = conn.cursor()
    c.execute("SELECT key FROM license_keys WHERE key = ?", (data.key,))
    if not c.fetchone():
        conn.close()
        return {"status": "error", "message": "Key not found"}

    c.execute("UPDATE license_keys SET name = ? WHERE key = ?", (data.name, data.key))
    conn.commit()
    conn.close()
    return {"status": "success", "message": f"Name set to {data.name}"}
