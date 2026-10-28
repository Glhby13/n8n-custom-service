(function () {
  'use strict';
  var $ = function (id) { return document.getElementById(id); };
  var form = $('f'), userEl = $('username'), passEl = $('password'), err = $('err');
  var adBtn = $('ad'), localBtn = $('local');
  var modal = $('modal'), mTitle = $('m-title'), mDesc = $('m-desc'), mQR = $('m-qr'), mQRImg = $('m-qr-img'),
    mSecret = $('m-secret'), mForm = $('m-form'), mCode = $('m-code'), mErr = $('m-err'), mOK = $('m-ok'), mCancel = $('m-cancel');

  // n8n sends the user here as /signin?redirect=%252F (encoded twice); the server sanitises again, this keeps the
  // already-signed-in shortcut equally strict.
  function cleanRedirect(raw) {
    var v = raw || '/';
    for (var i = 0; i < 2; i++) { try { v = decodeURIComponent(v); } catch (e) { break; } }
    if (v.charAt(0) !== '/' || v.slice(0, 2) === '//' || v.indexOf('\\') >= 0 || /^\/(signin|sso\/)/.test(v)) return '/';
    return v;
  }
  var redirect = cleanRedirect(new URLSearchParams(location.search).get('redirect'));

  function browserId() { try { return localStorage.getItem('n8n-browserId') || ''; } catch (e) { return ''; } }

  // Already signed in to n8n? Go where the user wanted to be.
  fetch('/rest/login', { credentials: 'same-origin', headers: { 'browser-id': browserId() } })
    .then(function (r) { if (r.ok) location.replace(redirect); })
    .catch(function () {});

  function show(el, msg) { el.textContent = msg; el.hidden = false; }
  function hide(el) { el.hidden = true; el.textContent = ''; }

  function post(path, body) {
    return fetch(path, {
      method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body)
    }).then(function (r) {
      return r.json().catch(function () { return {}; }).then(function (j) { return { status: r.status, body: j }; });
    });
  }

  function done(b) {
    try { localStorage.setItem('n8n-browserId', b.browser_id); } catch (e) { /* storage blocked: n8n will issue its own */ }
    location.replace(b.redirect || '/');
  }

  var busy = false;
  function setBusy(v) {
    busy = v;
    adBtn.disabled = v; localBtn.disabled = v; mOK.disabled = v;
  }

  var pending = null; // what the dialog finishes: { kind: 'ad'|'local'|'setup', ... }

  function openModal(kind, data) {
    pending = { kind: kind, token: data && data.setup_token };
    hide(mErr); mCode.value = '';
    mQR.hidden = kind !== 'setup';
    if (kind === 'setup') {
      mTitle.textContent = 'Set up your authenticator';
      mDesc.textContent = 'Administrator accounts need two-factor authentication. Scan the QR code with an authenticator app, then enter the 6-digit code it shows.';
      mQRImg.src = data.qr_code; mSecret.textContent = data.secret;
    } else {
      mTitle.textContent = 'Two-factor authentication';
      mDesc.textContent = 'Enter the 6-digit code from your authenticator app.';
      mQRImg.removeAttribute('src'); mSecret.textContent = '';
    }
    modal.hidden = false; mCode.focus();
  }
  function closeModal() { modal.hidden = true; pending = null; mCode.value = ''; mQRImg.removeAttribute('src'); mSecret.textContent = ''; }

  function creds(extra) {
    var o = { username: userEl.value.trim(), password: passEl.value, redirect: new URLSearchParams(location.search).get('redirect') || '/' };
    for (var k in extra) o[k] = extra[k];
    return o;
  }

  function handle(kind, res, inModal) {
    var b = res.body || {};
    if (res.status === 200 && b.redirect) { done(b); return; }
    if (b.error === 'totp_required' || b.error === 'mfa_required') {
      if (inModal) { show(mErr, 'Invalid authenticator code.'); return; }
      openModal(kind, b); return;
    }
    if (b.error === 'totp_setup_required') { openModal('setup', b); return; }
    if (b.error === 'invalid_or_expired_token') { closeModal(); show(err, b.error_description || 'Session expired. Sign in again.'); return; }
    var msg = b.error_description || (res.status === 429 ? 'Too many attempts. Try again later.' : 'Sign-in failed.');
    show(inModal ? mErr : err, msg);
  }

  function submit(kind) {
    if (busy) return;
    hide(err);
    if (!userEl.value.trim() || !passEl.value) { show(err, 'Enter your email and password.'); return; }
    setBusy(true);
    post(kind === 'ad' ? '/sso/login/ad' : '/sso/login/local', creds({}))
      .then(function (r) { handle(kind, r, false); })
      .catch(function () { show(err, 'Cannot reach the server. Try again.'); })
      .then(function () { setBusy(false); });
  }

  form.addEventListener('submit', function (e) { e.preventDefault(); submit('ad'); });
  localBtn.addEventListener('click', function () { submit('local'); });

  mForm.addEventListener('submit', function (e) {
    e.preventDefault();
    if (busy || !pending) return;
    var code = mCode.value.replace(/\s+/g, '');
    if (!/^[0-9]{6}$/.test(code)) { show(mErr, 'Enter the 6-digit code.'); return; }
    hide(mErr); setBusy(true);
    var kind = pending.kind;
    var req = kind === 'setup'
      ? post('/sso/login/ad/totp-setup', { setup_token: pending.token, code: code })
      : post(kind === 'ad' ? '/sso/login/ad' : '/sso/login/local', creds({ totp: code }));
    req.then(function (r) { handle(kind, r, true); })
      .catch(function () { show(mErr, 'Cannot reach the server. Try again.'); })
      .then(function () { setBusy(false); });
  });
  mCancel.addEventListener('click', closeModal);
  document.addEventListener('keydown', function (e) { if (e.key === 'Escape' && !modal.hidden) closeModal(); });
})();
