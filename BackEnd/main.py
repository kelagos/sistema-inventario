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

DATA_DIR = Path(__file__).parent / "data"
USERS_PATH = DATA_DIR / "users.json"
PRODUCTS_PATH = DATA_DIR / "products.json"

DATA_DIR.mkdir(parents=True, exist_ok=True)

if not USERS_PATH.exists():
    USERS_PATH.write_text(json.dumps({"users": []}, indent=2), encoding="utf-8")

if not PRODUCTS_PATH.exists():
    PRODUCTS_PATH.write_text(json.dumps({"products": []}, indent=2), encoding="utf-8")

# ✅ Evita bcrypt (problemas en Windows/Python nuevos)
pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")
security = HTTPBearer()

app = FastAPI(title="Inventario API")

# ---------- CORS ----------
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # en producción restringe
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------- HELPERS (JSON) ----------
def _read_json(path: Path, default: dict) -> dict:
    try:
        text = path.read_text(encoding="utf-8").strip()
        if not text:
            return default
        return json.loads(text)
    except (json.JSONDecodeError, OSError):
        return default


def _write_json(path: Path, data: dict) -> None:
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def read_users() -> dict:
    db = _read_json(USERS_PATH, {"users": []})
    if "users" not in db or not isinstance(db["users"], list):
        return {"users": []}
    return db


def write_users(db: dict) -> None:
    _write_json(USERS_PATH, db)


def read_products() -> dict:
    db = _read_json(PRODUCTS_PATH, {"products": []})
    if "products" not in db or not isinstance(db["products"], list):
        return {"products": []}
    return db


def write_products(db: dict) -> None:
    _write_json(PRODUCTS_PATH, db)


# ---------- HELPERS (JWT/Auth) ----------
def create_token(payload: dict) -> str:
    now = int(time.time())
    exp = now + TOKEN_EXPIRE_SECONDS
    to_encode = {**payload, "iat": now, "exp": exp}
    return jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALG)


def decode_token(token: str) -> dict:
    return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])


def get_user_by_email(email: str):
    db = read_users()
    email = email.lower()
    return next((u for u in db["users"] if u.get("email") == email), None)


def safe_user(user: dict) -> dict:
    return {
        "id": user["id"],
        "name": user["name"],
        "email": user["email"],
        "role": user["role"],
    }


def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        return decode_token(credentials.credentials)
    except JWTError:
        raise HTTPException(status_code=401, detail="Token inválido o expirado.")


def require_admin(user=Depends(get_current_user)):
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="No autorizado (requiere admin).")
    return user


# ---------- SCHEMAS (Auth) ----------
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

class AdminCreateUserIn(BaseModel):
    name: str = Field(min_length=2, max_length=60)
    email: EmailStr
    password: str = Field(min_length=6, max_length=128)
    role: str = Field(default="user", pattern="^(admin|user)$")


class LoginOut(BaseModel):
    token: str
    user: UserOut


# ---------- SCHEMAS (Products) ----------
class ProductIn(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    sku: str = Field(min_length=2, max_length=40)
    quantity: int = Field(ge=0)
    location: str | None = Field(default=None, max_length=80)


class ProductOut(BaseModel):
    id: int
    name: str
    sku: str
    quantity: int
    location: str | None = None
    created_at: int

@app.post("/admin/users", response_model=UserOut, status_code=201)
def admin_create_user(payload: AdminCreateUserIn, admin=Depends(require_admin)):
    db = read_users()
    email = payload.email.lower().strip()

    if any(u.get("email") == email for u in db["users"]):
        raise HTTPException(status_code=409, detail="Ese email ya está registrado.")

    user_id = int(time.time() * 1000)
    password_hash = pwd_context.hash(payload.password)

    user = {
        "id": user_id,
        "name": payload.name.strip(),
        "email": email,
        "password_hash": password_hash,
        "role": payload.role,  # "admin" o "user"
    }

    db["users"].append(user)
    write_users(db)

    return safe_user(user)


# ---------- ROUTES ----------
@app.get("/")
def root():
    return {"ok": True, "service": "inventario-api"}


# ----- AUTH -----
@app.post("/auth/register", response_model=UserOut, status_code=201)
def register(payload: RegisterIn):
    db = read_users()
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
        "role": "admin",  # por ahora fijo
    }

    db["users"].append(user)
    write_users(db)
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


@app.get("/auth/me")
def me(user=Depends(get_current_user)):
    return {"user": user}


# ----- PRODUCTS (protegido con JWT) -----
@app.get("/products", response_model=list[ProductOut])
def list_products(user=Depends(get_current_user)):
    db = read_products()
    return db["products"]


@app.post("/products", response_model=ProductOut, status_code=201)
def create_product(payload: ProductIn, user=Depends(require_admin)):
    db = read_products()

    # evitar SKU duplicado
    if any(p.get("sku", "").lower() == payload.sku.lower() for p in db["products"]):
        raise HTTPException(status_code=409, detail="SKU ya existe.")

    product_id = int(time.time() * 1000)
    product = {
        "id": product_id,
        "name": payload.name.strip(),
        "sku": payload.sku.strip(),
        "quantity": payload.quantity,
        "location": payload.location.strip() if payload.location else None,
        "created_at": int(time.time()),
    }

    db["products"].append(product)
    write_products(db)
    return product


@app.get("/products/{product_id}", response_model=ProductOut)
def get_product(product_id: int, user=Depends(get_current_user)):
    db = read_products()
    product = next((p for p in db["products"] if p["id"] == product_id), None)
    if not product:
        raise HTTPException(status_code=404, detail="Producto no encontrado.")
    return product


@app.put("/products/{product_id}", response_model=ProductOut)
def update_product(product_id: int, payload: ProductIn, user=Depends(require_admin)):
    db = read_products()
    idx = next((i for i, p in enumerate(db["products"]) if p["id"] == product_id), None)
    if idx is None:
        raise HTTPException(status_code=404, detail="Producto no encontrado.")

    # validar SKU duplicado (otro producto)
    for p in db["products"]:
        if p["id"] != product_id and p.get("sku", "").lower() == payload.sku.lower():
            raise HTTPException(status_code=409, detail="SKU ya existe.")

    updated = {
        **db["products"][idx],
        "name": payload.name.strip(),
        "sku": payload.sku.strip(),
        "quantity": payload.quantity,
        "location": payload.location.strip() if payload.location else None,
    }

    db["products"][idx] = updated
    write_products(db)
    return updated


@app.delete("/products/{product_id}", status_code=204)
def delete_product(product_id: int, user=Depends(require_admin)):
    db = read_products()
    before = len(db["products"])
    db["products"] = [p for p in db["products"] if p["id"] != product_id]
    if len(db["products"]) == before:
        raise HTTPException(status_code=404, detail="Producto no encontrado.")
    write_products(db)
    return None
