/**
 * Wilbanks Company — Auth Layer
 * Injected into both apps via index.html before React loads.
 * - JWT token stored in memory only (window.__WC_TOKEN)
 * - Username saved to localStorage for "remember me"
 * - Face ID / WebAuthn: optional after first login
 * - Monkey-patches fetch to inject Authorization headers on Railway calls
 */
(function () {
  const API = "https://wilbanks-server-production.up.railway.app";
  const TOKEN_KEY = "wc_auth_token"; // sessionStorage — clears when tab closes... we use memory
  const USERNAME_KEY = "wc_saved_username";
  const WEBAUTHN_PROMPT_KEY = "wc_webauthn_prompted"; // so we only ask once

  // ── Token storage (memory primary, sessionStorage fallback for page refresh) ──
  // We store in sessionStorage so a page refresh doesn't require re-login within the session.
  // The 30-day JWT itself is the security boundary.
  let _token = null;

  function saveToken(token) {
    _token = token;
    try { sessionStorage.setItem(TOKEN_KEY, token); } catch {}
  }
  function loadToken() {
    if (_token) return _token;
    try { _token = sessionStorage.getItem(TOKEN_KEY); } catch {}
    return _token;
  }
  function clearToken() {
    _token = null;
    try { sessionStorage.removeItem(TOKEN_KEY); } catch {}
  }

  // Expose token globally for React app to use
  Object.defineProperty(window, "__WC_TOKEN", {
    get: () => _token,
    set: (v) => { _token = v; },
    configurable: true,
  });

  // ── Fetch interceptor — inject Authorization on all Railway calls ──────────
  const _origFetch = window.fetch.bind(window);
  window.fetch = function (input, init = {}) {
    const url = typeof input === "string" ? input : (input?.url || "");
    if (url.includes("wilbanks-server-production.up.railway.app") && _token) {
      init = {
        ...init,
        headers: {
          ...(init.headers || {}),
          Authorization: "Bearer " + _token,
        },
      };
    }
    return _origFetch(input, init);
  };

  // ── Auth state ─────────────────────────────────────────────────────────────
  let currentUser = null;

  function getSavedUsername() {
    try { return localStorage.getItem(USERNAME_KEY) || ""; } catch { return ""; }
  }
  function setSavedUsername(u) {
    try { localStorage.setItem(USERNAME_KEY, u); } catch {}
  }

  function hasPromptedWebAuthn() {
    try { return localStorage.getItem(WEBAUTHN_PROMPT_KEY) === "1"; } catch { return false; }
  }
  function markWebAuthnPrompted() {
    try { localStorage.setItem(WEBAUTHN_PROMPT_KEY, "1"); } catch {}
  }

  // ── WebAuthn helpers ───────────────────────────────────────────────────────
  function bufferToBase64url(buffer) {
    const bytes = new Uint8Array(buffer);
    let str = "";
    for (const b of bytes) str += String.fromCharCode(b);
    return btoa(str).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
  }
  function base64urlToBuffer(b64) {
    const b = b64.replace(/-/g, "+").replace(/_/g, "/");
    const str = atob(b);
    const buf = new Uint8Array(str.length);
    for (let i = 0; i < str.length; i++) buf[i] = str.charCodeAt(i);
    return buf.buffer;
  }

  async function tryWebAuthnLogin(username) {
    try {
      const optRes = await _origFetch(API + "/api/auth/webauthn/authenticate/options", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username }),
      });
      if (!optRes.ok) return null;
      const options = await optRes.json();

      // Convert base64url fields
      options.challenge = base64urlToBuffer(options.challenge);
      if (options.allowCredentials) {
        options.allowCredentials = options.allowCredentials.map(c => ({
          ...c,
          id: base64urlToBuffer(c.id),
        }));
      }

      const credential = await navigator.credentials.get({ publicKey: options });
      if (!credential) return null;

      const assertionBody = {
        userId: options.userId,
        id: credential.id,
        rawId: bufferToBase64url(credential.rawId),
        type: credential.type,
        response: {
          clientDataJSON: bufferToBase64url(credential.response.clientDataJSON),
          authenticatorData: bufferToBase64url(credential.response.authenticatorData),
          signature: bufferToBase64url(credential.response.signature),
          userHandle: credential.response.userHandle ? bufferToBase64url(credential.response.userHandle) : null,
        },
      };

      const verifyRes = await _origFetch(API + "/api/auth/webauthn/authenticate/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(assertionBody),
      });
      if (!verifyRes.ok) return null;
      return await verifyRes.json();
    } catch (e) {
      console.warn("[auth] WebAuthn failed:", e.message);
      return null;
    }
  }

  async function registerWebAuthn() {
    try {
      const optRes = await _origFetch(API + "/api/auth/webauthn/register/options", {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: "Bearer " + _token },
      });
      if (!optRes.ok) return false;
      const options = await optRes.json();

      options.challenge = base64urlToBuffer(options.challenge);
      options.user.id = base64urlToBuffer(options.user.id);
      if (options.excludeCredentials) {
        options.excludeCredentials = options.excludeCredentials.map(c => ({
          ...c,
          id: base64urlToBuffer(c.id),
        }));
      }

      const credential = await navigator.credentials.create({ publicKey: options });
      if (!credential) return false;

      const regBody = {
        id: credential.id,
        rawId: bufferToBase64url(credential.rawId),
        type: credential.type,
        response: {
          clientDataJSON: bufferToBase64url(credential.response.clientDataJSON),
          attestationObject: bufferToBase64url(credential.response.attestationObject),
          transports: credential.response.getTransports ? credential.response.getTransports() : [],
        },
      };

      const verifyRes = await _origFetch(API + "/api/auth/webauthn/register/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: "Bearer " + _token },
        body: JSON.stringify(regBody),
      });
      return verifyRes.ok;
    } catch (e) {
      console.warn("[auth] WebAuthn register failed:", e.message);
      return false;
    }
  }

  // ── UI rendering ───────────────────────────────────────────────────────────
  const CSS = `
    #wc-auth-overlay {
      position: fixed; inset: 0; z-index: 99999;
      background: #09090b;
      display: flex; align-items: center; justify-content: center;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
      transition: opacity 0.35s ease;
    }
    #wc-auth-overlay.wc-fade-out { opacity: 0; pointer-events: none; }
    .wc-card {
      background: #18181b;
      border: 1px solid #27272a;
      border-radius: 16px;
      padding: 36px 32px;
      width: 100%;
      max-width: 380px;
      margin: 0 16px;
      box-shadow: 0 24px 80px rgba(0,0,0,0.6);
    }
    .wc-logo {
      display: flex; align-items: center; gap: 12px;
      margin-bottom: 28px;
    }
    .wc-logo img { width: 48px; height: 48px; border-radius: 10px; object-fit: cover; }
    .wc-logo-text { line-height: 1.2; }
    .wc-logo-text h1 { margin:0; font-size: 17px; font-weight: 700; color: #fafafa; }
    .wc-logo-text p { margin:0; font-size: 12px; color: #71717a; }
    .wc-title { font-size: 22px; font-weight: 700; color: #fafafa; margin: 0 0 6px; }
    .wc-subtitle { font-size: 14px; color: #71717a; margin: 0 0 24px; }
    .wc-field { margin-bottom: 16px; }
    .wc-label { display: block; font-size: 12px; font-weight: 500; color: #a1a1aa; margin-bottom: 6px; letter-spacing: 0.02em; text-transform: uppercase; }
    .wc-input {
      width: 100%; box-sizing: border-box;
      background: #09090b; border: 1px solid #3f3f46;
      border-radius: 8px; padding: 11px 14px;
      font-size: 15px; color: #fafafa; outline: none;
      transition: border-color 0.15s;
    }
    .wc-input:focus { border-color: #3b82f6; }
    .wc-input::placeholder { color: #52525b; }
    .wc-btn {
      width: 100%; padding: 12px;
      border: none; border-radius: 8px;
      font-size: 15px; font-weight: 600; cursor: pointer;
      transition: background 0.15s, opacity 0.15s;
      margin-bottom: 10px;
    }
    .wc-btn:disabled { opacity: 0.5; cursor: not-allowed; }
    .wc-btn-primary { background: #3b82f6; color: #fff; }
    .wc-btn-primary:hover:not(:disabled) { background: #2563eb; }
    .wc-btn-faceid {
      background: #18181b; color: #fafafa;
      border: 1px solid #3f3f46;
      display: flex; align-items: center; justify-content: center; gap: 10px;
    }
    .wc-btn-faceid:hover:not(:disabled) { background: #27272a; }
    .wc-error {
      background: #3f1212; border: 1px solid #7f1d1d;
      color: #fca5a5; border-radius: 8px;
      padding: 10px 14px; font-size: 13px;
      margin-bottom: 14px; display: none;
    }
    .wc-error.visible { display: block; }
    .wc-divider {
      display: flex; align-items: center; gap: 10px;
      margin: 14px 0; color: #3f3f46; font-size: 12px;
    }
    .wc-divider::before, .wc-divider::after {
      content: ''; flex: 1; height: 1px; background: #27272a;
    }
    .wc-spinner {
      width: 18px; height: 18px;
      border: 2px solid rgba(255,255,255,0.2);
      border-top-color: #fff;
      border-radius: 50%;
      animation: wc-spin 0.7s linear infinite;
      display: inline-block;
    }
    @keyframes wc-spin { to { transform: rotate(360deg); } }

    /* Change password screen */
    .wc-change-pw-hint { font-size: 13px; color: #71717a; margin: 0 0 20px; }

    /* Face ID prompt */
    .wc-faceid-icon { font-size: 48px; text-align: center; margin-bottom: 12px; }
    .wc-faceid-desc { font-size: 14px; color: #a1a1aa; text-align: center; margin: 0 0 24px; line-height: 1.5; }
    .wc-btn-skip { background: transparent; color: #71717a; font-size: 14px; border: none; cursor: pointer; width: 100%; padding: 8px; text-decoration: underline; }
    .wc-btn-skip:hover { color: #a1a1aa; }
  `;

  function injectStyles() {
    if (document.getElementById("wc-auth-styles")) return;
    const el = document.createElement("style");
    el.id = "wc-auth-styles";
    el.textContent = CSS;
    document.head.appendChild(el);
  }

  function showOverlay(html) {
    injectStyles();
    let overlay = document.getElementById("wc-auth-overlay");
    if (!overlay) {
      overlay = document.createElement("div");
      overlay.id = "wc-auth-overlay";
      document.body.appendChild(overlay);
    }
    overlay.innerHTML = `<div class="wc-card">${html}</div>`;
    overlay.classList.remove("wc-fade-out");
    return overlay;
  }

  function dismissOverlay() {
    const overlay = document.getElementById("wc-auth-overlay");
    if (overlay) {
      overlay.classList.add("wc-fade-out");
      setTimeout(() => overlay.remove(), 400);
    }
    // Unhide root
    const root = document.getElementById("root");
    if (root) root.style.display = "";
  }

  // ── Login screen ──────────────────────────────────────────────────────────
  function renderLogin(errorMsg = "") {
    const savedUsername = getSavedUsername();
    const faceIdAvailable = window.PublicKeyCredential && typeof navigator.credentials?.get === "function";

    const faceIdHtml = faceIdAvailable && savedUsername ? `
      <div class="wc-divider">or</div>
      <button class="wc-btn wc-btn-faceid" id="wc-faceid-btn">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M9 3H5a2 2 0 0 0-2 2v4m6-6h6m-6 0v18m0 0H5a2 2 0 0 1-2-2v-4m6 6h6m0 0h4a2 2 0 0 0 2-2v-4m-6 6V3m6 0h-4a2 2 0 0 1 2 2v4"/>
        </svg>
        Sign in with Face ID
      </button>
    ` : "";

    const overlay = showOverlay(`
      <div class="wc-logo">
        <img src="./assets/logo-DmC-dsba-1776655699849.jpg" onerror="this.src='./assets/logo-DmC-dsba.jpg'" alt="Wilbanks" />
        <div class="wc-logo-text">
          <h1>Wilbanks Company</h1>
          <p>HVAC &amp; Plumbing</p>
        </div>
      </div>
      <h2 class="wc-title">Sign In</h2>
      <p class="wc-subtitle">Enter your credentials to continue</p>
      <div class="wc-error${errorMsg ? " visible" : ""}" id="wc-error">${errorMsg}</div>
      <div class="wc-field">
        <label class="wc-label" for="wc-username">Username</label>
        <input class="wc-input" id="wc-username" type="text" placeholder="username" autocomplete="username" autocapitalize="none" value="${savedUsername}" />
      </div>
      <div class="wc-field">
        <label class="wc-label" for="wc-password">Password</label>
        <input class="wc-input" id="wc-password" type="password" placeholder="••••••••" autocomplete="current-password" />
      </div>
      <button class="wc-btn wc-btn-primary" id="wc-login-btn">Sign In</button>
      ${faceIdHtml}
    `);

    const usernameInput = overlay.querySelector("#wc-username");
    const passwordInput = overlay.querySelector("#wc-password");
    const loginBtn = overlay.querySelector("#wc-login-btn");
    const errorEl = overlay.querySelector("#wc-error");
    const faceIdBtn = overlay.querySelector("#wc-faceid-btn");

    // Focus
    setTimeout(() => {
      if (savedUsername) passwordInput?.focus();
      else usernameInput?.focus();
    }, 100);

    function showError(msg) {
      errorEl.textContent = msg;
      errorEl.classList.add("visible");
    }

    async function doLogin() {
      const username = usernameInput.value.trim();
      const password = passwordInput.value;
      if (!username || !password) { showError("Please enter your username and password."); return; }
      loginBtn.disabled = true;
      loginBtn.innerHTML = '<span class="wc-spinner"></span>';
      errorEl.classList.remove("visible");

      try {
        const res = await _origFetch(API + "/api/auth/login", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ username, password }),
        });
        const data = await res.json();
        if (!res.ok) { showError(data.error || "Login failed"); loginBtn.disabled = false; loginBtn.textContent = "Sign In"; return; }
        setSavedUsername(username);
        onLoginSuccess(data.token, data.user);
      } catch (e) {
        showError("Connection error. Please try again.");
        loginBtn.disabled = false;
        loginBtn.textContent = "Sign In";
      }
    }

    loginBtn.addEventListener("click", doLogin);
    passwordInput.addEventListener("keydown", e => { if (e.key === "Enter") doLogin(); });
    usernameInput.addEventListener("keydown", e => { if (e.key === "Enter") passwordInput.focus(); });

    if (faceIdBtn) {
      faceIdBtn.addEventListener("click", async () => {
        const username = usernameInput.value.trim() || savedUsername;
        if (!username) { showError("Enter your username first, then try Face ID."); return; }
        faceIdBtn.disabled = true;
        faceIdBtn.innerHTML = '<span class="wc-spinner"></span> Checking Face ID...';
        const result = await tryWebAuthnLogin(username);
        if (result?.token) {
          setSavedUsername(username);
          onLoginSuccess(result.token, result.user);
        } else {
          faceIdBtn.disabled = false;
          faceIdBtn.innerHTML = `
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <path d="M9 3H5a2 2 0 0 0-2 2v4m6-6h6m-6 0v18m0 0H5a2 2 0 0 1-2-2v-4m6 6h6m0 0h4a2 2 0 0 0 2-2v-4m-6 6V3m6 0h-4a2 2 0 0 1 2 2v4"/>
            </svg>
            Sign in with Face ID`;
          showError("Face ID verification failed. Use password instead.");
        }
      });
    }
  }

  // ── Change Password screen ────────────────────────────────────────────────
  function renderChangePassword() {
    const overlay = showOverlay(`
      <div class="wc-logo">
        <img src="./assets/logo-DmC-dsba-1776655699849.jpg" onerror="this.src='./assets/logo-DmC-dsba.jpg'" alt="Wilbanks" />
        <div class="wc-logo-text">
          <h1>Wilbanks Company</h1>
          <p>HVAC &amp; Plumbing</p>
        </div>
      </div>
      <h2 class="wc-title">Set Your Password</h2>
      <p class="wc-change-pw-hint">This is your first login. Please create a new password to continue.</p>
      <div class="wc-error" id="wc-error"></div>
      <div class="wc-field">
        <label class="wc-label" for="wc-newpw">New Password</label>
        <input class="wc-input" id="wc-newpw" type="password" placeholder="At least 6 characters" autocomplete="new-password" />
      </div>
      <div class="wc-field">
        <label class="wc-label" for="wc-confirmpw">Confirm Password</label>
        <input class="wc-input" id="wc-confirmpw" type="password" placeholder="Re-enter password" autocomplete="new-password" />
      </div>
      <button class="wc-btn wc-btn-primary" id="wc-setpw-btn">Set Password & Continue</button>
    `);

    const newPw = overlay.querySelector("#wc-newpw");
    const confirmPw = overlay.querySelector("#wc-confirmpw");
    const btn = overlay.querySelector("#wc-setpw-btn");
    const errorEl = overlay.querySelector("#wc-error");

    setTimeout(() => newPw?.focus(), 100);

    async function doChange() {
      const pw = newPw.value;
      const cpw = confirmPw.value;
      if (pw.length < 6) { errorEl.textContent = "Password must be at least 6 characters."; errorEl.classList.add("visible"); return; }
      if (pw !== cpw) { errorEl.textContent = "Passwords don't match."; errorEl.classList.add("visible"); return; }
      btn.disabled = true;
      btn.innerHTML = '<span class="wc-spinner"></span>';
      try {
        const res = await _origFetch(API + "/api/auth/change-password", {
          method: "POST",
          headers: { "Content-Type": "application/json", Authorization: "Bearer " + _token },
          body: JSON.stringify({ newPassword: pw }),
        });
        const data = await res.json();
        if (!res.ok) { errorEl.textContent = data.error || "Error setting password"; errorEl.classList.add("visible"); btn.disabled = false; btn.textContent = "Set Password & Continue"; return; }
        // Update token
        saveToken(data.token);
        currentUser = { ...currentUser, mustChangePassword: false };
        // Proceed to Face ID prompt or app
        afterPasswordSet();
      } catch {
        errorEl.textContent = "Connection error.";
        errorEl.classList.add("visible");
        btn.disabled = false;
        btn.textContent = "Set Password & Continue";
      }
    }

    btn.addEventListener("click", doChange);
    confirmPw.addEventListener("keydown", e => { if (e.key === "Enter") doChange(); });
  }

  // ── Face ID prompt ─────────────────────────────────────────────────────────
  function renderFaceIdPrompt() {
    const overlay = showOverlay(`
      <div class="wc-faceid-icon">
        <svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="#3b82f6" stroke-width="1.5">
          <path d="M9 3H5a2 2 0 0 0-2 2v4m6-6h6m-6 0v18m0 0H5a2 2 0 0 1-2-2v-4m6 6h6m0 0h4a2 2 0 0 0 2-2v-4m-6 6V3m6 0h-4a2 2 0 0 1 2 2v4"/>
        </svg>
      </div>
      <h2 class="wc-title" style="text-align:center">Enable Face ID?</h2>
      <p class="wc-faceid-desc">Skip the password next time. Sign in instantly with your face using Face ID.</p>
      <div class="wc-error" id="wc-error"></div>
      <button class="wc-btn wc-btn-primary" id="wc-enable-faceid">Enable Face ID</button>
      <button class="wc-btn-skip" id="wc-skip-faceid">Not now</button>
    `);

    const enableBtn = overlay.querySelector("#wc-enable-faceid");
    const skipBtn = overlay.querySelector("#wc-skip-faceid");
    const errorEl = overlay.querySelector("#wc-error");

    enableBtn.addEventListener("click", async () => {
      enableBtn.disabled = true;
      enableBtn.innerHTML = '<span class="wc-spinner"></span> Setting up...';
      const ok = await registerWebAuthn();
      if (ok) {
        markWebAuthnPrompted();
        launchApp();
      } else {
        errorEl.textContent = "Face ID setup failed. You can enable it later in settings.";
        errorEl.classList.add("visible");
        enableBtn.disabled = false;
        enableBtn.textContent = "Try Again";
      }
    });

    skipBtn.addEventListener("click", () => {
      markWebAuthnPrompted();
      launchApp();
    });
  }

  // ── Flow control ──────────────────────────────────────────────────────────
  function onLoginSuccess(token, user) {
    saveToken(token);
    currentUser = user;
    window.__WC_USER = user;

    if (user.mustChangePassword) {
      renderChangePassword();
    } else {
      afterPasswordSet();
    }
  }

  function afterPasswordSet() {
    const faceIdAvailable = window.PublicKeyCredential && typeof navigator.credentials?.get === "function";
    const alreadyPrompted = hasPromptedWebAuthn();
    const hasWebAuthn = currentUser?.hasWebAuthn;

    if (faceIdAvailable && !alreadyPrompted && !hasWebAuthn) {
      renderFaceIdPrompt();
    } else {
      launchApp();
    }
  }

  function launchApp() {
    dismissOverlay();
    // Expose user globally for React to read
    window.__WC_USER = currentUser;
    window.__WC_LOGOUT = logout;
    injectLogoutButton();
  }

  function injectLogoutButton() {
    // Remove any existing
    document.getElementById('wc-logout-btn')?.remove();
    const btn = document.createElement('button');
    btn.id = 'wc-logout-btn';
    btn.title = 'Sign Out';
    btn.innerHTML = `
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/>
        <polyline points="16,17 21,12 16,7"/>
        <line x1="21" y1="12" x2="9" y2="12"/>
      </svg>
      Sign Out
    `;
    Object.assign(btn.style, {
      position: 'fixed', bottom: '16px', right: '16px', zIndex: '9998',
      background: '#18181b', border: '1px solid #3f3f46',
      color: '#a1a1aa', borderRadius: '8px',
      padding: '8px 14px', fontSize: '13px', fontWeight: '500',
      cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '6px',
      fontFamily: '-apple-system, BlinkMacSystemFont, sans-serif',
      boxShadow: '0 2px 8px rgba(0,0,0,0.4)',
    });
    btn.addEventListener('mouseenter', () => { btn.style.background = '#27272a'; btn.style.color = '#fafafa'; });
    btn.addEventListener('mouseleave', () => { btn.style.background = '#18181b'; btn.style.color = '#a1a1aa'; });
    btn.addEventListener('click', () => {
      if (confirm('Sign out of Wilbanks Company?')) logout();
    });
    document.body.appendChild(btn);
  }

  function logout() {
    clearToken();
    currentUser = null;
    window.__WC_USER = null;
    document.getElementById('wc-logout-btn')?.remove();
    renderLogin();
    // Hide app
    const root = document.getElementById("root");
    if (root) root.style.display = "none";
  }

  // Expose logout globally
  window.__WC_LOGOUT = logout;

  // ── Bootstrap ─────────────────────────────────────────────────────────────
  async function bootstrap() {
    // Hide root until auth is confirmed
    const root = document.getElementById("root");
    if (root) root.style.display = "none";

    injectStyles();

    // Try existing token
    const token = loadToken();
    if (token) {
      try {
        const res = await _origFetch(API + "/api/auth/me", {
          headers: { Authorization: "Bearer " + token },
        });
        if (res.ok) {
          const user = await res.json();
          saveToken(token);
          currentUser = user;
          window.__WC_USER = user;
          window.__WC_LOGOUT = logout;
          // Token valid — show app directly
          if (root) root.style.display = "";
          return;
        }
      } catch {}
      // Token invalid/expired — clear it and show login
      clearToken();
    }

    renderLogin();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", bootstrap);
  } else {
    bootstrap();
  }
})();
