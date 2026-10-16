let csrf = '';
const notice = document.querySelector('#notice') || document.querySelector('#dash-notice');

function showNotice(text, ok = false) {
  if (!notice) return;
  notice.textContent = text;
  notice.className = ok ? 'notice success' : 'notice';
}

async function api(path, options = {}) {
  const headers = {
    'Content-Type': 'application/json',
    ...(csrf ? { 'x-csrf-token': csrf } : {}),
    ...(options.headers || {})
  };
  const response = await fetch(path, { ...options, headers });
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || 'Request failed.');
  return data;
}

async function load() {
  try {
    const data = await api('/api/me');
    csrf = data.csrfToken;
    const nameEl = document.querySelector('#name') || document.querySelector('#greeting');
    if (nameEl) nameEl.textContent = `Welcome, ${data.user.name.split(' ')[0]}.`;
    const emailEl = document.querySelector('#email');
    if (emailEl) emailEl.textContent = data.user.email;
    const enabled = data.user.twoFactorEnabled;
    const statusEl = document.querySelector('#two-factor-status') || document.querySelector('#twofa-status');
    if (statusEl) statusEl.textContent = enabled ? 'Enabled' : 'Not enabled';
    const actionEl = document.querySelector('#setup-button') || document.querySelector('#twofa-action');
    if (actionEl) {
      actionEl.textContent = enabled ? 'Disable 2FA' : 'Set up 2FA';
      actionEl.onclick = enabled ? disable : setup;
    }
  } catch (error) {
    window.location.href = '/';
  }
}

async function setup() {
  try {
    const data = await api('/api/2fa/setup', { method: 'POST', body: JSON.stringify({ _csrf: csrf }) });
    const qrEl = document.querySelector('#qr');
    if (qrEl) qrEl.src = data.qrCode || data.qr;
    const secretEl = document.querySelector('#secret');
    if (secretEl) secretEl.textContent = data.secret;
    const boxEl = document.querySelector('#setup') || document.querySelector('#twofa-box');
    if (boxEl) boxEl.classList.remove('hidden');
    const enableBtn = document.querySelector('#enable-button') || document.querySelector('#enable');
    if (enableBtn) enableBtn.onclick = enable;
  } catch (error) {
    showNotice(error.message);
  }
}

async function enable() {
  try {
    const token = (document.querySelector('#token')?.value || '').trim();
    await api('/api/2fa/enable', { method: 'POST', body: JSON.stringify({ _csrf: csrf, token }) });
    window.location.reload();
  } catch (error) {
    showNotice(error.message);
  }
}

async function disable() {
  try {
    await api('/api/2fa/disable', { method: 'POST', body: JSON.stringify({ _csrf: csrf }) });
    window.location.reload();
  } catch (error) {
    showNotice(error.message);
  }
}

const logoutBtn = document.querySelector('#logout');
if (logoutBtn) {
  logoutBtn.onclick = async () => {
    try {
      await api('/api/logout', { method: 'POST', body: JSON.stringify({ _csrf: csrf }) });
      window.location.href = '/';
    } catch (error) {
      showNotice(error.message);
    }
  };
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', load);
} else {
  load();
}
