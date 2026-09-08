const notice = document.querySelector('#notice');
const forms = document.querySelectorAll('[data-form]');
let csrfToken = '';

function showNotice(message, success = false) {
  notice.textContent = message;
  notice.className = success ? 'notice success' : 'notice';
}
function switchView(view) {
  forms.forEach((form) => form.classList.toggle('hidden', form.dataset.form !== view));
  document.querySelectorAll('.tab').forEach((tab) => {
    const active = tab.dataset.view === view;
    tab.classList.toggle('active', active);
    tab.setAttribute('aria-selected', String(active));
  });
  showNotice('');
}
function payload(form) {
  return Object.fromEntries(new FormData(form).entries());
}
async function submitForm(form) {
  const endpoint = form.dataset.form === 'two-factor' ? '/api/2fa/verify' : `/api/${form.dataset.form}`;
  const button = form.querySelector('button');
  button.disabled = true;
  showNotice('');
  try {
    const response = await fetch(endpoint, { method: 'POST', headers: { 'Content-Type': 'application/json', 'x-csrf-token': csrfToken }, body: JSON.stringify(payload(form)) });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || 'Something went wrong.');
    if (data.requiresTwoFactor) {
      switchView('two-factor');
      showNotice('Check your authenticator app.', true);
    } else {
      window.location.href = '/dashboard.html';
    }
  } catch (error) { showNotice(error.message); } finally { button.disabled = false; }
}
document.querySelectorAll('.tab').forEach((tab) => tab.addEventListener('click', () => switchView(tab.dataset.view)));
forms.forEach((form) => form.addEventListener('submit', (event) => { event.preventDefault(); submitForm(form); }));
document.querySelectorAll('.password-toggle').forEach((toggle) => toggle.addEventListener('click', () => {
  const input = document.querySelector(`#${toggle.dataset.target}`);
  const showing = input.type === 'text';
  input.type = showing ? 'password' : 'text';
  toggle.textContent = showing ? 'Show' : 'Hide';
  toggle.setAttribute('aria-label', showing ? 'Show password' : 'Hide password');
}));
fetch('/api/csrf').then((response) => response.json()).then((data) => { csrfToken = data.csrfToken; }).catch(() => showNotice('Unable to start a secure session.'));
