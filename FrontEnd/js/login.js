const form = document.getElementById("loginForm");
const email = document.getElementById("email");
const password = document.getElementById("password");
const remember = document.getElementById("remember");

const emailError = document.getElementById("emailError");
const passError = document.getElementById("passError");
const formMsg = document.getElementById("formMsg");
const btnLogin = document.getElementById("btnLogin");

const togglePass = document.getElementById("togglePass");

function setLoading(isLoading){
  btnLogin.disabled = isLoading;
  btnLogin.textContent = isLoading ? "Ingresando..." : "Entrar";
}

function showFieldError(el, msg){
  el.textContent = msg;
}

function clearErrors(){
  emailError.textContent = "";
  passError.textContent = "";
  formMsg.style.display = "none";
  formMsg.textContent = "";
  formMsg.classList.remove("ok");
}

function isValidEmail(value){
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}

togglePass.addEventListener("click", () => {
  const isHidden = password.type === "password";
  password.type = isHidden ? "text" : "password";
  togglePass.textContent = isHidden ? "🙈" : "👁";
});

form.addEventListener("submit", async (e) => {
  e.preventDefault();
  clearErrors();

  const eVal = email.value.trim();
  const pVal = password.value;

  let ok = true;

  if (!isValidEmail(eVal)){
    showFieldError(emailError, "Ingresa un email válido.");
    ok = false;
  }
  if (!pVal || pVal.length < 6){
    showFieldError(passError, "La contraseña debe tener al menos 6 caracteres.");
    ok = false;
  }

  if (!ok) return;

   setLoading(true);

  try {
    const res = await fetch("http://localhost:3000/auth/login", {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        email: eVal,
        password: pVal
      })
    });

    const data = await res.json();

    if (!res.ok) {
      throw new Error(data.detail || "Email o contraseña incorrectos.");
    }

    const session = {
      token: data.token,
      user: data.user,
      remember: remember.checked
    };

  
    localStorage.setItem("session", JSON.stringify(session));

    formMsg.textContent = "¡Login correcto! Redirigiendo…";
    formMsg.classList.add("ok");
    formMsg.style.display = "block";

    setTimeout(() => {
      window.location.href = "./dashboard.html";
    }, 500);

  } catch (err) {
    formMsg.textContent = err.message || "No se pudo iniciar sesión.";
    formMsg.style.display = "block";
  } finally {
    setLoading(false);
  }
});