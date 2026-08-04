document.getElementById('login-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const error = document.getElementById('login-error'); error.textContent = '';
  const payload = {username: document.getElementById('login-user').value, password: document.getElementById('login-password').value, totp: document.getElementById('login-totp').value};
  try {
    const response = await fetch('/api/auth/login', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(payload)});
    const body = await response.json().catch(()=>({}));
    if (!response.ok) throw new Error(body.detail || `HTTP ${response.status}`);
    sessionStorage.setItem('scoutCsrf', body.csrf); location.href='/';
  } catch (e) { error.textContent=e.message; }
});
