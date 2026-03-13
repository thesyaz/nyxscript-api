from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from typing import Optional, List
import sqlite3, hashlib, jwt, datetime, os, uuid

app = FastAPI(title="NyxScript API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

SECRET_KEY = "nyxscript-secret-2025-change-this-in-prod"
ALGORITHM = "HS256"
DB_PATH = "nyxscript.db"
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "nyxadmin2025"  # Change this !

security = HTTPBearer()

# ── DB SETUP ──────────────────────────────────────
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            is_admin INTEGER DEFAULT 0,
            is_banned INTEGER DEFAULT 0,
            xp INTEGER DEFAULT 0,
            level INTEGER DEFAULT 1,
            completed_chapters TEXT DEFAULT '[]',
            completed_challenges TEXT DEFAULT '[]',
            earned_badges TEXT DEFAULT '[]',
            license_type TEXT DEFAULT 'free',
            created_at TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            bio TEXT DEFAULT ''
        )
    """)
    # Create admin if not exists
    admin_hash = hashlib.sha256(ADMIN_PASSWORD.encode()).hexdigest()
    try:
        c.execute("""
            INSERT INTO users (id, username, email, password_hash, is_admin, xp, level, license_type, created_at, last_seen)
            VALUES (?, ?, ?, ?, 1, 999999, 99, 'pro', ?, ?)
        """, (str(uuid.uuid4()), ADMIN_USERNAME, "admin@nyxscript.com", admin_hash,
              datetime.datetime.utcnow().isoformat(), datetime.datetime.utcnow().isoformat()))
        conn.commit()
    except:
        pass
    conn.close()

init_db()

# ── JWT ───────────────────────────────────────────
def create_token(user_id: str, is_admin: bool) -> str:
    payload = {
        "sub": user_id,
        "admin": is_admin,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(days=30)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except:
        raise HTTPException(status_code=401, detail="Token invalide ou expiré")

def get_current_user(payload=Depends(verify_token)):
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE id = ?", (payload["sub"],)).fetchone()
    conn.close()
    if not user:
        raise HTTPException(status_code=404, detail="Utilisateur introuvable")
    if user["is_banned"]:
        raise HTTPException(status_code=403, detail="Compte banni")
    return dict(user)

def require_admin(user=Depends(get_current_user)):
    if not user["is_admin"]:
        raise HTTPException(status_code=403, detail="Accès admin requis")
    return user

# ── MODELS ───────────────────────────────────────
class RegisterModel(BaseModel):
    username: str
    email: str
    password: str

class LoginModel(BaseModel):
    username: str
    password: str

class UpdateXPModel(BaseModel):
    user_id: str
    xp: int

class UpdateProgressModel(BaseModel):
    completed_chapters: List[int]
    completed_challenges: List[int]
    earned_badges: List[str]
    xp: int
    level: int

class AdminUpdateUser(BaseModel):
    user_id: str
    xp: Optional[int] = None
    level: Optional[int] = None
    is_banned: Optional[bool] = None
    license_type: Optional[str] = None
    bio: Optional[str] = None

class UpdateBioModel(BaseModel):
    bio: str

# ── AUTH ROUTES ───────────────────────────────────
@app.post("/auth/register")
def register(data: RegisterModel):
    if len(data.username) < 3:
        raise HTTPException(400, "Pseudo trop court (min 3 caractères)")
    if len(data.password) < 6:
        raise HTTPException(400, "Mot de passe trop court (min 6 caractères)")
    
    conn = get_db()
    pw_hash = hashlib.sha256(data.password.encode()).hexdigest()
    user_id = str(uuid.uuid4())
    now = datetime.datetime.utcnow().isoformat()
    try:
        conn.execute("""
            INSERT INTO users (id, username, email, password_hash, created_at, last_seen)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (user_id, data.username, data.email, pw_hash, now, now))
        conn.commit()
    except sqlite3.IntegrityError as e:
        conn.close()
        if "username" in str(e):
            raise HTTPException(400, "Ce pseudo est déjà pris")
        raise HTTPException(400, "Cet email est déjà utilisé")
    
    user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()
    token = create_token(user_id, False)
    return {"token": token, "user": format_user(dict(user))}

@app.post("/auth/login")
def login(data: LoginModel):
    conn = get_db()
    pw_hash = hashlib.sha256(data.password.encode()).hexdigest()
    user = conn.execute(
        "SELECT * FROM users WHERE username = ? AND password_hash = ?",
        (data.username, pw_hash)
    ).fetchone()
    if not user:
        conn.close()
        raise HTTPException(401, "Pseudo ou mot de passe incorrect")
    if user["is_banned"]:
        conn.close()
        raise HTTPException(403, "Compte banni")
    
    conn.execute("UPDATE users SET last_seen = ? WHERE id = ?",
                 (datetime.datetime.utcnow().isoformat(), user["id"]))
    conn.commit()
    conn.close()
    
    token = create_token(user["id"], bool(user["is_admin"]))
    return {"token": token, "user": format_user(dict(user))}

@app.get("/auth/me")
def me(user=Depends(get_current_user)):
    return format_user(user)

# ── USER ROUTES ───────────────────────────────────
@app.post("/user/progress")
def save_progress(data: UpdateProgressModel, user=Depends(get_current_user)):
    import json
    conn = get_db()
    # Admin always has infinite XP
    xp = 999999 if user["is_admin"] else data.xp
    level = 99 if user["is_admin"] else data.level
    conn.execute("""
        UPDATE users SET xp=?, level=?, completed_chapters=?, completed_challenges=?, earned_badges=?
        WHERE id=?
    """, (xp, level, json.dumps(data.completed_chapters), json.dumps(data.completed_challenges),
          json.dumps(data.earned_badges), user["id"]))
    conn.commit()
    conn.close()
    return {"success": True}

@app.post("/user/bio")
def update_bio(data: UpdateBioModel, user=Depends(get_current_user)):
    conn = get_db()
    conn.execute("UPDATE users SET bio=? WHERE id=?", (data.bio[:200], user["id"]))
    conn.commit()
    conn.close()
    return {"success": True}

@app.get("/user/profile/{username}")
def get_profile(username: str):
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    conn.close()
    if not user:
        raise HTTPException(404, "Utilisateur introuvable")
    return format_user_public(dict(user))

@app.get("/users/leaderboard")
def leaderboard():
    conn = get_db()
    users = conn.execute(
        "SELECT * FROM users WHERE is_banned=0 ORDER BY xp DESC LIMIT 20"
    ).fetchall()
    conn.close()
    return [format_user_public(dict(u)) for u in users]

# ── ADMIN ROUTES ──────────────────────────────────
@app.get("/admin/users")
def admin_get_users(admin=Depends(require_admin)):
    conn = get_db()
    users = conn.execute("SELECT * FROM users ORDER BY created_at DESC").fetchall()
    conn.close()
    return [format_user(dict(u)) for u in users]

@app.post("/admin/update-user")
def admin_update_user(data: AdminUpdateUser, admin=Depends(require_admin)):
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE id=?", (data.user_id,)).fetchone()
    if not user:
        conn.close()
        raise HTTPException(404, "Utilisateur introuvable")
    
    updates = []
    values = []
    if data.xp is not None:
        updates.append("xp=?"); values.append(data.xp)
    if data.level is not None:
        updates.append("level=?"); values.append(data.level)
    if data.is_banned is not None:
        updates.append("is_banned=?"); values.append(1 if data.is_banned else 0)
    if data.license_type is not None:
        updates.append("license_type=?"); values.append(data.license_type)
    if data.bio is not None:
        updates.append("bio=?"); values.append(data.bio)
    
    if updates:
        values.append(data.user_id)
        conn.execute(f"UPDATE users SET {', '.join(updates)} WHERE id=?", values)
        conn.commit()
    conn.close()
    return {"success": True}

@app.delete("/admin/delete-user/{user_id}")
def admin_delete_user(user_id: str, admin=Depends(require_admin)):
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    if not user:
        conn.close()
        raise HTTPException(404, "Utilisateur introuvable")
    if user["is_admin"]:
        conn.close()
        raise HTTPException(403, "Impossible de supprimer un admin")
    conn.execute("DELETE FROM users WHERE id=?", (user_id,))
    conn.commit()
    conn.close()
    return {"success": True}

@app.get("/admin/stats")
def admin_stats(admin=Depends(require_admin)):
    conn = get_db()
    total = conn.execute("SELECT COUNT(*) as n FROM users").fetchone()["n"]
    banned = conn.execute("SELECT COUNT(*) as n FROM users WHERE is_banned=1").fetchone()["n"]
    pro = conn.execute("SELECT COUNT(*) as n FROM users WHERE license_type='pro'").fetchone()["n"]
    standard = conn.execute("SELECT COUNT(*) as n FROM users WHERE license_type='standard'").fetchone()["n"]
    today = datetime.datetime.utcnow().date().isoformat()
    new_today = conn.execute("SELECT COUNT(*) as n FROM users WHERE created_at LIKE ?", (today+"%",)).fetchone()["n"]
    conn.close()
    return {"total": total, "banned": banned, "pro": pro, "standard": standard, "new_today": new_today}

# ── HELPERS ───────────────────────────────────────
def format_user(u: dict) -> dict:
    import json
    return {
        "id": u["id"],
        "username": u["username"],
        "email": u["email"],
        "is_admin": bool(u["is_admin"]),
        "is_banned": bool(u["is_banned"]),
        "xp": u["xp"],
        "level": u["level"],
        "completed_chapters": json.loads(u["completed_chapters"] or "[]"),
        "completed_challenges": json.loads(u["completed_challenges"] or "[]"),
        "earned_badges": json.loads(u["earned_badges"] or "[]"),
        "license_type": u["license_type"],
        "created_at": u["created_at"],
        "last_seen": u["last_seen"],
        "bio": u["bio"] or ""
    }

def format_user_public(u: dict) -> dict:
    import json
    return {
        "username": u["username"],
        "xp": u["xp"],
        "level": u["level"],
        "completed_chapters": json.loads(u["completed_chapters"] or "[]"),
        "completed_challenges": json.loads(u["completed_challenges"] or "[]"),
        "earned_badges": json.loads(u["earned_badges"] or "[]"),
        "license_type": u["license_type"],
        "created_at": u["created_at"],
        "bio": u["bio"] or "",
        "is_admin": bool(u["is_admin"])
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
