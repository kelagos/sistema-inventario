from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, Field
from passlib.context import CryptContext
from jose import jwt, JWTError
from dotenv import load_dotenv
from pathlib import Path
import os, json, time


# ---------- CONFIG ----------
load_dotenv()

JWT_SECRET = os.getenv("JWT_SECRET", "dev_secret_change_me")
JWT_ALG = "HS256"
TOKEN_EXPIRE_SECONDS = 60 * 60 * 2  # 2 horas

DATA_PATH = Path(__file__).parent / "data" / "users.json"
DATA_PATH.parent.mkdir(parents=True, exist_ok=True)
if not DATA_PATH.exists():
    DATA_PATH.write_text(json.dumps({"users": []}, indent=2), encoding="utf-8")

# ✅ Usamos pbkdf2_sha256 (evita problemas con bcrypt en Windows/Python nuevos)
pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")
security = HTTPBearer()

app = FastAPI(title="Inventario API")

# ---------- CORS ----------
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # en producción restringe esto
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------- HELPERS ----------
def read_db() -> dict:
    """Lee la 'DB' del archivo JSON. Si está vacío/roto, vuelve a un estado seguro."""
    try:
        text = DATA_PATH.read_text(encoding="utf-8").strip()
        if not text:
            return {"users": []}
        db = json.loads(text)
        if "users" not in db or not isinstance(db["users"], list):
            return {"users": []}
        return db
    except (json.JSONDecodeError, OSError):
        return {"users": []}


def write_db(db: dict) -> None:
    DATA_PATH.write_text(json.dumps(db, indent=2), encoding="utf-8")


def create_token(payload: dict) -> str:
    now = int(time.time())
    exp = now + TOKEN_EXPIRE_SECONDS
    to_encode = {**payload, "iat": now, "exp": exp}
    return jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALG)


def decode_token(token: str) -> dict:
    return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])


def get_user_by_email(email: str):
    db = read_db()
    email = email.lower()
    return next((u for u in db["users"] if u.get("email") == email), None)


def safe_user(user: dict) -> dict:
    """Lo que devolvemos al frontend (sin password_hash)."""
    return {
        "id": user["id"],
        "name": user["name"],
        "email": user["email"],
        "role": user["role"],
    }


# ---------- SCHEMAS ----------
class RegisterIn(BaseModel):
    name: str = Field(min_length=2, max_length=60)
    email: EmailStr
    password: str = Field(min_length=6, max_length=128)


class LoginIn(BaseModel):
    email: EmailStr
    password: str = Field(min_length=6, max_length=128)


class UserOut(BaseModel):
    id: int
    name: str
    email: EmailStr
    role: str


class LoginOut(BaseModel):
    token: str
    user: UserOut


class MeOut(BaseModel):
    user: dict  # payload del token (sub, email, name, role, iat, exp)


# ---------- ROUTES ----------
@app.get("/")
def root():
    return {"ok": True, "service": "inventario-api"}


@app.post("/auth/register", response_model=UserOut, status_code=201)
def register(payload: RegisterIn):
    db = read_db()
    email = payload.email.lower()

    if any(u.get("email") == email for u in db["users"]):
        raise HTTPException(status_code=409, detail="Ese email ya está registrado.")

    user_id = int(time.time() * 1000)
    password_hash = pwd_context.hash(payload.password)

    user = {
        "id": user_id,
        "name": payload.name.strip(),
        "email": email,
        "password_hash": password_hash,
        "role": "admin",  # por ahora fijo; después lo haces dinámico
    }

    db["users"].append(user)
    write_db(db)

    return safe_user(user)


@app.post("/auth/login", response_model=LoginOut)
def login(payload: LoginIn):
    user = get_user_by_email(payload.email)
    if not user:
        raise HTTPException(status_code=401, detail="Email o contraseña incorrectos.")

    if not pwd_context.verify(payload.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Email o contraseña incorrectos.")

    token = create_token(
        {
            "sub": str(user["id"]),
            "email": user["email"],
            "name": user["name"],
            "role": user["role"],
        }
    )

    return {"token": token, "user": safe_user(user)}


def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        return decode_token(credentials.credentials)
    except JWTError:
        raise HTTPException(status_code=401, detail="Token inválido o expirado.")


@app.get("/auth/me", response_model=MeOut)
def me(user=Depends(get_current_user)):
    return {"user": user}
