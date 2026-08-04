const totpInput = document.getElementById('login-totp');

function formatTotp(value) {
  const digits = String(value || '').replace(/\D/g, '').slice(0, 6);
  return digits.length > 3 ? `${digits.slice(0, 3)}-${digits.slice(3)}` : digits;
}

totpInput.addEventListener('input', () => {
  const cursorAtEnd = totpInput.selectionStart === totpInput.value.length;
  totpInput.value = formatTotp(totpInput.value);
  if (cursorAtEnd) totpInput.setSelectionRange(totpInput.value.length, totpInput.value.length);
});

totpInput.addEventListener('paste', (event) => {
  event.preventDefault();
  const text = event.clipboardData?.getData('text') || '';
  totpInput.value = formatTotp(text);
});

document.getElementById('login-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const error = document.getElementById('login-error');
  error.textContent = '';
  const totp = totpInput.value.replace(/\D/g, '');
  if (totp.length !== 6) {
    error.textContent = 'Введите код 2FA в формате 000-000';
    totpInput.focus();
    return;
  }
  const payload = {
    username: document.getElementById('login-user').value,
    password: document.getElementById('login-password').value,
    totp,
  };
  try {
    const response = await fetch('/api/auth/login', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(payload),
    });
    const body = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(body.detail || `HTTP ${response.status}`);
    sessionStorage.setItem('scoutCsrf', body.csrf);
    location.href = '/';
  } catch (e) {
    error.textContent = e.message;
  }
});
