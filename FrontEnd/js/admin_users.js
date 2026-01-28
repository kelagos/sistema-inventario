const API_BASE = "http://localhost:3000";

// ----- Session guard -----
const sessionRaw = localStorage.getItem("session");
const session = sessionRaw ? JSON.parse(sessionRaw) : null;

function goLogin() {
  localStorage.removeItem("session");
  window.location.href = "./login.html";
}

if (!session || !session.token) goLogin();

// Solo admins
if (session.user?.role !== "admin") {
  alert("No autorizado. Solo admins pueden acceder a esta página.");
  window.location.href = "./dashboard.html";
}

document.getElementById("subtitle").textContent =
  `Sesión: ${session.user?.name || "admin"} · rol: ${session.user?.role}`;

document.getElementById("logoutBtn").addEventListener("click", goLogin);

// ----- UI -----
const form = document.getElementById("createUserForm");
const nameEl = document.getElementById("name");
const emailEl = document.getElementById("email");
const passEl = document.getElementById("password");
const roleEl = document.getElementById("role");
const btn = document.getElementById("createBtn");
const msg = document.getElementById("msg");

const nameErr = document.getElementById("nameErr");
const emailErr = document.getElementById("emailErr");
const passErr = document.getElementById("passErr");

const togglePass = document.getElementById("togglePass");
togglePass.addEventListener("click", () => {
  const hidden = passEl.type === "password";
  passEl.type = hidden ? "text" : "password";
  togglePass.textContent = hidden ? "🙈" : "👁";
});

function clearErrors(){
  nameErr.textContent = "";
  emailErr.textContent = "";
  passErr.textContent = "";
  msg.className = "msg";
  msg.textContent = "";
}

function showMsg(type, text){
  msg.className = "msg " + (type === "ok" ? "ok" : "bad");
  msg.textContent = text;
}

function isValidEmail(value){
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}

async function apiFetch(path, options = {}) {
  const res = await fetch(API_BASE + path, options);

  if (res.status === 401) goLogin();

  if (res.status === 204) return { ok: true, status: 204, data: null };

  let data = null;
  try { data = await res.json(); } catch { data = null; }
  return { ok: res.ok, status: res.status, data };
}

function authHeaders() {
  return {
    "Content-Type": "application/json",
    "Authorization": `Bearer ${session.token}`
  };
}

function setLoading(on){
  btn.disabled = on;
  btn.textContent = on ? "Creando…" : "Crear usuario";
}

form.addEventListener("submit", async (e) => {
  e.preventDefault();
  clearErrors();

  const payload = {
    name: nameEl.value.trim(),
    email: emailEl.value.trim().toLowerCase(),
    password: passEl.value,
    role: roleEl.value
  };

  let ok = true;
  if (!payload.name || payload.name.length < 2){
    nameErr.textContent = "Nombre inválido (mín 2 caracteres).";
    ok = false;
  }
  if (!isValidEmail(payload.email)){
    emailErr.textContent = "Email inválido.";
    ok = false;
  }
  if (!payload.password || payload.password.length < 6){
    passErr.textContent = "Contraseña inválida (mín 6 caracteres).";
    ok = false;
  }
  if (!ok) return;

  setLoading(true);

  const r = await apiFetch("/admin/users", {
    method: "POST",
    headers: authHeaders(),
    body: JSON.stringify(payload)
  });

  setLoading(false);

  if (!r) return;

  if (!r.ok){
    showMsg("bad", r.data?.detail || `No se pudo crear (${r.status})`);
    return;
  }

  showMsg("ok", `Usuario creado ✅ (${r.data.email} · rol: ${r.data.role})`);
  form.reset();
  roleEl.value = "user";
});
