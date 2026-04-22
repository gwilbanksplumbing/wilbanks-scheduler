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

  // ── Token storage ────────────────────────────────────────────────────────
  // Field tech app is a PWA installed on iPhone home screen — standalone windows
  // have isolated sessionStorage that clears on every cold launch, so we use
  // localStorage for the field app so the session survives PWA restarts.
  // Dashboard uses sessionStorage (clears when tab closes, more secure on shared desktops).
  // The 30-day JWT + inactivity timeout are the security boundaries in both cases.
  let _token = null;

  function isFieldApp() {
    return window.location.pathname.includes('fieldtech') ||
           window.location.href.includes('wilbanks-fieldtech');
  }

  function saveToken(token) {
    _token = token;
    try {
      if (isFieldApp()) { localStorage.setItem(TOKEN_KEY, token); }
      else { sessionStorage.setItem(TOKEN_KEY, token); }
    } catch {}
  }
  function loadToken() {
    if (_token) return _token;
    try {
      if (isFieldApp()) { _token = localStorage.getItem(TOKEN_KEY); }
      else { _token = sessionStorage.getItem(TOKEN_KEY); }
    } catch {}
    return _token;
  }
  function clearToken() {
    _token = null;
    try { sessionStorage.removeItem(TOKEN_KEY); } catch {}
    try { localStorage.removeItem(TOKEN_KEY); } catch {}
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
        <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round">
          <circle cx="12" cy="12" r="9"/>
          <circle cx="9" cy="10.5" r="1" fill="currentColor" stroke="none"/>
          <circle cx="15" cy="10.5" r="1" fill="currentColor" stroke="none"/>
          <path d="M8.5 14.5 Q12 17.5 15.5 14.5"/>
        </svg>
        Sign in with Face ID
      </button>
    ` : "";

    const overlay = showOverlay(`
      <div class="wc-logo">
        <img src="./assets/logo-DmC-dsba-1776655699849.jpg" onerror="this.src='./assets/logo-DmC-dsba.jpg'" alt="Wilbanks" />
        <div class="wc-logo-text">
          <h1>Wilbanks Company</h1>
          <p>Cooling &bull; Heating &bull; Plumbing</p>
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
          // Clear stale credentials so user can re-register after password login
          try {
            localStorage.removeItem(WEBAUTHN_PROMPT_KEY);
            // Best-effort server-side clear using stored token (may not be available here)
            const storedToken = localStorage.getItem(TOKEN_KEY) || sessionStorage.getItem(TOKEN_KEY);
            if (storedToken) {
              _origFetch(API + "/api/auth/webauthn", {
                method: "DELETE",
                headers: { "Authorization": "Bearer " + storedToken }
              }).catch(() => {});
            }
          } catch {}
          faceIdBtn.disabled = false;
          faceIdBtn.innerHTML = `
            <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round">
              <circle cx="12" cy="12" r="9"/>
              <circle cx="9" cy="10.5" r="1" fill="currentColor" stroke="none"/>
              <circle cx="15" cy="10.5" r="1" fill="currentColor" stroke="none"/>
              <path d="M8.5 14.5 Q12 17.5 15.5 14.5"/>
            </svg>
            Sign in with Face ID`;
          showError("Face ID needs to be set up again. Use your password — you'll be prompted to re-enable Face ID after logging in.");
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
          <p>Cooling &bull; Heating &bull; Plumbing</p>
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
        <svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="#3b82f6" stroke-width="1.5" stroke-linecap="round">
          <circle cx="12" cy="12" r="9"/>
          <circle cx="9" cy="10.5" r="1" fill="#3b82f6" stroke="none"/>
          <circle cx="15" cy="10.5" r="1" fill="#3b82f6" stroke="none"/>
          <path d="M8.5 14.5 Q12 17.5 15.5 14.5"/>
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

    // Determine which app we're on
    const isDashboard = !window.location.pathname.includes('fieldtech') &&
                        !window.location.href.includes('wilbanks-fieldtech');
    // 'tech' can only access field tech app
    if (user.role === 'tech' && isDashboard) {
      clearToken();
      renderLogin('Field Tech accounts can only access the Field Tech app, not the dashboard.');
      return;
    }
    // 'dispatcher' can only access dashboard (admin can access both)
    if (user.role === 'dispatcher' && !isDashboard) {
      clearToken();
      renderLogin('Dashboard accounts cannot access the Field Tech app.');
      return;
    }
    // 'both' role can access either app — no block needed

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
    // Only offer Face ID to field tech users (tech/both) — not dashboard-only roles
    const isTechRole = currentUser?.role === 'tech' || currentUser?.role === 'both';

    if (faceIdAvailable && !alreadyPrompted && !hasWebAuthn && isTechRole) {
      renderFaceIdPrompt();
    } else {
      launchApp();
    }
  }

  function launchApp() {
    dismissOverlay();
    window.__WC_USER = currentUser;
    window.__WC_LOGOUT = logout;
    // Sync display name into the field tech app's localStorage key
    // so the top-left header always shows the logged-in user's name
    syncFieldTechName(currentUser);
    injectLogoutButton();
    // Only inject Users nav for admin users on the dashboard
    if (currentUser?.role === 'admin') injectUsersNav();
    // Start inactivity timer
    startInactivityTimer();
  }

  // ── Inactivity timeout ─────────────────────────────────────────────────────
  // Dashboard: 30 minutes. Field app: 24 hours.
  const LAST_ACTIVE_KEY = 'wc_last_active';
  let _inactivityInterval = null;

  function getInactivityLimit() {
    const isDashboard = !window.location.pathname.includes('fieldtech') &&
                        !window.location.href.includes('wilbanks-fieldtech');
    return isDashboard ? 30 * 60 * 1000 : 24 * 60 * 60 * 1000; // 30min or 24hr in ms
  }

  function touchActivity() {
    try { localStorage.setItem(LAST_ACTIVE_KEY, Date.now().toString()); } catch {}
  }

  function startInactivityTimer() {
    // Record activity now
    touchActivity();
    // Listen for any user interaction
    ['mousemove','mousedown','keydown','touchstart','scroll','click'].forEach(evt => {
      window.addEventListener(evt, touchActivity, { passive: true });
    });
    // Check every minute
    if (_inactivityInterval) clearInterval(_inactivityInterval);
    _inactivityInterval = setInterval(() => {
      try {
        const last = parseInt(localStorage.getItem(LAST_ACTIVE_KEY) || '0', 10);
        if (last && Date.now() - last > getInactivityLimit()) {
          clearInterval(_inactivityInterval);
          _inactivityInterval = null;
          logout();
          // Show a message on the login screen
          setTimeout(() => {
            const err = document.getElementById('wc-error');
            if (err) {
              err.textContent = 'You were logged out due to inactivity.';
              err.classList.add('visible');
            }
          }, 300);
        }
      } catch {}
    }, 60 * 1000); // check every 60 seconds
  }

  function syncFieldTechName(user) {
    if (!user) return;
    const isDashboard = !window.location.pathname.includes('fieldtech') &&
                        !window.location.href.includes('wilbanks-fieldtech');
    if (isDashboard) return; // only needed on field tech app
    try {
      const name = user.displayName || user.username || '';
      localStorage.setItem('wc_tech_name', name);
    } catch {}
  }

  // ── User Management ────────────────────────────────────────────────────────
  function injectUsersNav() {
    // Guard: only admins get this nav item
    if (currentUser?.role !== 'admin') return;

    function tryInject() {
      // Desktop sidebar: find Archive nav link and add Users after it
      const navLinks = document.querySelectorAll('nav a, aside a');
      let archiveLink = null;
      for (const a of navLinks) {
        if (a.textContent?.trim().includes('Archive')) archiveLink = a;
      }
      if (archiveLink && !document.getElementById('wc-users-nav-desktop')) {
        // Clone just for the classes/attributes, then rebuild children cleanly
        const usersLink = archiveLink.cloneNode(false);
        usersLink.id = 'wc-users-nav-desktop';
        usersLink.removeAttribute('href');
        usersLink.removeAttribute('data-testid');
        usersLink.style.cursor = 'pointer';
        usersLink.innerHTML = `
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/>
            <circle cx="9" cy="7" r="4"/>
            <path d="M22 21v-2a4 4 0 0 0-3-3.87"/>
            <path d="M16 3.13a4 4 0 0 1 0 7.75"/>
          </svg>
          <span>Users</span>
        `;
        usersLink.addEventListener('click', () => openUsersPanel());
        archiveLink.parentElement?.insertBefore(usersLink, archiveLink.nextSibling);
        return true;
      }
      return false;
    }

    function tryInjectMobile() {
      const mobileMenu = Array.from(document.querySelectorAll('div')).find(el =>
        el.className?.includes?.('top-[57px]')
      );
      if (mobileMenu && !mobileMenu.querySelector('#wc-users-nav-mobile')) {
        const links = mobileMenu.querySelectorAll('a');
        let archiveLink = null;
        for (const a of links) {
          if (a.textContent?.trim().includes('Archive')) archiveLink = a;
        }
        if (archiveLink) {
          const btn = document.createElement('button');
          btn.id = 'wc-users-nav-mobile';
          btn.innerHTML = `
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/>
              <circle cx="9" cy="7" r="4"/>
              <path d="M22 21v-2a4 4 0 0 0-3-3.87"/>
              <path d="M16 3.13a4 4 0 0 1 0 7.75"/>
            </svg>
            <span>Users</span>
          `;
          // Match the style of existing nav links
          const existingStyle = window.getComputedStyle(archiveLink);
          Object.assign(btn.style, {
            display: 'flex', alignItems: 'center', gap: '12px',
            width: '100%', padding: '10px 12px',
            background: 'transparent', border: 'none',
            borderRadius: '6px', cursor: 'pointer',
            fontSize: '14px', fontWeight: '500',
            color: 'inherit', fontFamily: 'inherit',
          });
          btn.addEventListener('click', () => openUsersPanel());
          archiveLink.parentElement?.insertBefore(btn, archiveLink.nextSibling);
        }
      }
    }

    if (!tryInject()) {
      const obs = new MutationObserver(() => {
        tryInject();
        tryInjectMobile();
      });
      obs.observe(document.body, { childList: true, subtree: true });
      setTimeout(() => obs.disconnect(), 10000);
    }

    // Keep watching for mobile menu opens
    const mobileObs = new MutationObserver(() => tryInjectMobile());
    mobileObs.observe(document.body, { childList: true, subtree: true });
    setTimeout(() => mobileObs.disconnect(), 300000);
  }

  function openUsersPanel() {
    if (document.getElementById('wc-users-panel')) return;
    injectStyles();

    const panel = document.createElement('div');
    panel.id = 'wc-users-panel';
    Object.assign(panel.style, {
      position: 'fixed', inset: '0', zIndex: '99990',
      background: 'rgba(0,0,0,0.7)', display: 'flex',
      alignItems: 'center', justifyContent: 'center',
      fontFamily: '-apple-system, BlinkMacSystemFont, sans-serif',
    });
    panel.innerHTML = `
      <div style="background:#18181b;border:1px solid #27272a;border-radius:16px;width:100%;max-width:560px;margin:16px;max-height:90vh;display:flex;flex-direction:column;box-shadow:0 24px 80px rgba(0,0,0,0.6)">
        <div style="padding:20px 24px 16px;border-bottom:1px solid #27272a;display:flex;align-items:center;justify-content:space-between;flex-shrink:0">
          <div>
            <h2 style="margin:0;font-size:18px;font-weight:700;color:#fafafa">User Management</h2>
            <p style="margin:4px 0 0;font-size:13px;color:#71717a">Manage who can access the apps</p>
          </div>
          <button id="wc-users-close" style="background:transparent;border:none;color:#71717a;cursor:pointer;font-size:20px;padding:4px 8px;line-height:1">&times;</button>
        </div>
        <div style="padding:20px 24px;border-bottom:1px solid #27272a;flex-shrink:0">
          <h3 style="margin:0 0 14px;font-size:14px;font-weight:600;color:#a1a1aa;text-transform:uppercase;letter-spacing:0.05em">Add New User</h3>
          <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:10px">
            <div>
              <label style="display:block;font-size:12px;color:#71717a;margin-bottom:5px">USERNAME</label>
              <input id="wc-new-username" placeholder="e.g. john" style="width:100%;box-sizing:border-box;background:#09090b;border:1px solid #3f3f46;border-radius:8px;padding:9px 12px;font-size:14px;color:#fafafa;outline:none" />
            </div>
            <div>
              <label style="display:block;font-size:12px;color:#71717a;margin-bottom:5px">ROLE</label>
              <select id="wc-new-role" style="width:100%;box-sizing:border-box;background:#09090b;border:1px solid #3f3f46;border-radius:8px;padding:9px 12px;font-size:14px;color:#fafafa;outline:none">
                <option value="tech">Field Tech Only</option>
                <option value="dispatcher">Dashboard Only</option>
                <option value="both">Dashboard + Field Tech</option>
                <option value="admin">Admin (Dashboard + Users)</option>
              </select>
            </div>
          </div>
          <div style="margin-bottom:12px">
            <label style="display:block;font-size:12px;color:#71717a;margin-bottom:5px">DISPLAY NAME (optional)</label>
            <input id="wc-new-displayname" placeholder="Full name shown in app" style="width:100%;box-sizing:border-box;background:#09090b;border:1px solid #3f3f46;border-radius:8px;padding:9px 12px;font-size:14px;color:#fafafa;outline:none" />
          </div>
          <div style="display:flex;align-items:center;gap:10px">
            <div style="flex:1">
              <label style="display:block;font-size:12px;color:#71717a;margin-bottom:5px">TEMP PASSWORD</label>
              <input id="wc-new-password" type="text" value="Wilbanks1!" style="width:100%;box-sizing:border-box;background:#09090b;border:1px solid #3f3f46;border-radius:8px;padding:9px 12px;font-size:14px;color:#fafafa;outline:none" />
            </div>
            <button id="wc-add-user-btn" style="background:#3b82f6;border:none;color:#fff;border-radius:8px;padding:9px 20px;font-size:14px;font-weight:600;cursor:pointer;white-space:nowrap;margin-top:18px">Add User</button>
          </div>
          <div id="wc-add-error" style="display:none;margin-top:8px;background:#3f1212;border:1px solid #7f1d1d;color:#fca5a5;border-radius:6px;padding:8px 12px;font-size:13px"></div>
          <div id="wc-add-success" style="display:none;margin-top:8px;background:#14532d;border:1px solid #166534;color:#86efac;border-radius:6px;padding:8px 12px;font-size:13px"></div>
        </div>
        <div style="flex:1;overflow-y:auto;padding:16px 24px" id="wc-user-list-container">
          <h3 style="margin:0 0 14px;font-size:14px;font-weight:600;color:#a1a1aa;text-transform:uppercase;letter-spacing:0.05em">Existing Users</h3>
          <div id="wc-user-list"><div style="color:#52525b;font-size:14px">Loading...</div></div>
        </div>
      </div>
    `;

    document.body.appendChild(panel);
    document.getElementById('wc-users-close').addEventListener('click', () => panel.remove());
    panel.addEventListener('click', e => { if (e.target === panel) panel.remove(); });

    loadUserList();

    document.getElementById('wc-add-user-btn').addEventListener('click', async () => {
      const username = document.getElementById('wc-new-username').value.trim().toLowerCase();
      const role = document.getElementById('wc-new-role').value;
      const displayName = document.getElementById('wc-new-displayname').value.trim();
      const password = document.getElementById('wc-new-password').value.trim();
      const errEl = document.getElementById('wc-add-error');
      const okEl = document.getElementById('wc-add-success');
      errEl.style.display = 'none';
      okEl.style.display = 'none';

      if (!username) { errEl.textContent = 'Username is required.'; errEl.style.display = 'block'; return; }
      if (!password || password.length < 6) { errEl.textContent = 'Password must be at least 6 characters.'; errEl.style.display = 'block'; return; }

      const btn = document.getElementById('wc-add-user-btn');
      btn.disabled = true; btn.textContent = 'Adding...';

      try {
        const res = await fetch(API + '/api/auth/users', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + _token },
          body: JSON.stringify({ username, password, role, displayName: displayName || undefined }),
        });
        const data = await res.json();
        if (!res.ok) { errEl.textContent = data.error || 'Failed to create user'; errEl.style.display = 'block'; }
        else {
          okEl.textContent = `User "${username}" created. Temp password: ${password} (they will be asked to change it on first login)`;
          okEl.style.display = 'block';
          document.getElementById('wc-new-username').value = '';
          document.getElementById('wc-new-displayname').value = '';
          document.getElementById('wc-new-password').value = 'Wilbanks1!';
          loadUserList();
        }
      } catch { errEl.textContent = 'Connection error.'; errEl.style.display = 'block'; }
      btn.disabled = false; btn.textContent = 'Add User';
    });
  }

  async function loadUserList() {
    const container = document.getElementById('wc-user-list');
    if (!container) return;
    container.innerHTML = '<div style="color:#52525b;font-size:14px">Loading...</div>';
    try {
      const res = await fetch(API + '/api/auth/users', {
        headers: { Authorization: 'Bearer ' + _token },
      });
      const users = await res.json();
      if (!users.length) { container.innerHTML = '<div style="color:#52525b;font-size:14px">No users yet.</div>'; return; }

      container.innerHTML = users.map(u => `
        <div id="wc-user-row-${u.id}" style="display:flex;align-items:center;justify-content:space-between;padding:10px 12px;background:#09090b;border:1px solid #27272a;border-radius:8px;margin-bottom:8px">
          <div>
            <div style="font-size:14px;font-weight:600;color:#fafafa">${u.display_name || u.username} <span style="font-size:12px;color:#52525b;font-weight:400">@${u.username}</span></div>
            <div style="font-size:12px;color:#71717a;margin-top:2px">${u.role === 'admin' ? '🔑 Admin (Dashboard + Users)' : u.role === 'dispatcher' ? '🖥️ Dashboard Only' : u.role === 'both' ? '🖥️🔧 Dashboard + Field Tech' : '🔧 Field Tech Only'}</div>
          </div>
          <div style="display:flex;gap:6px;flex-shrink:0">
            <button onclick="window.__wcResetPw(${u.id}, '${u.username}')" style="background:#27272a;border:none;color:#a1a1aa;border-radius:6px;padding:6px 10px;font-size:12px;cursor:pointer">Reset PW</button>
            ${u.id !== currentUser?.id ? `<button onclick="window.__wcDeleteUser(${u.id}, '${u.username}')" style="background:rgba(239,68,68,0.1);border:1px solid rgba(239,68,68,0.3);color:#ef4444;border-radius:6px;padding:6px 10px;font-size:12px;cursor:pointer">Remove</button>` : '<span style="font-size:12px;color:#52525b;padding:6px 10px">(you)</span>'}
          </div>
        </div>
      `).join('');

      window.__wcResetPw = async (id, username) => {
        if (!confirm(`Reset password for "${username}" to Wilbanks1!?`)) return;
        const res = await fetch(API + '/api/auth/users/' + id + '/reset-password', {
          method: 'POST', headers: { Authorization: 'Bearer ' + _token },
        });
        if (res.ok) alert(`Password reset. "${username}" will be asked to set a new password on next login.`);
        else alert('Reset failed.');
      };

      window.__wcDeleteUser = async (id, username) => {
        if (!confirm(`Remove user "${username}"? This cannot be undone.`)) return;
        const res = await fetch(API + '/api/auth/users/' + id, {
          method: 'DELETE', headers: { Authorization: 'Bearer ' + _token },
        });
        if (res.ok) { document.getElementById('wc-user-row-' + id)?.remove(); }
        else alert('Delete failed.');
      };

    } catch { container.innerHTML = '<div style="color:#ef4444;font-size:14px">Failed to load users.</div>'; }
  }

  function injectLogoutButton() {
    document.getElementById('wc-logout-btn')?.remove();

    // Build a sidebar-style logout button (dashboard desktop)
    function buildSidebarBtn() {
      const btn = document.createElement('button');
      btn.id = 'wc-logout-btn';
      btn.innerHTML = `
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="flex-shrink:0">
          <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/>
          <polyline points="16,17 21,12 16,7"/>
          <line x1="21" y1="12" x2="9" y2="12"/>
        </svg>
        Sign Out
      `;
      Object.assign(btn.style, {
        display: 'flex', alignItems: 'center', gap: '12px',
        width: '100%', padding: '10px 12px',
        background: 'transparent', border: 'none',
        borderRadius: '6px', cursor: 'pointer',
        fontSize: '14px', fontWeight: '500',
        color: '#ef4444',
        fontFamily: 'inherit',
        transition: 'background 0.15s',
        marginTop: '4px',
      });
      btn.addEventListener('mouseenter', () => btn.style.background = 'rgba(239,68,68,0.1)');
      btn.addEventListener('mouseleave', () => btn.style.background = 'transparent');
      btn.addEventListener('click', doLogout);
      return btn;
    }



    function doLogout() {
      if (confirm('Sign out of Wilbanks Company?')) logout();
    }

    // Strategy 1a: Dashboard desktop sidebar — inject below theme toggle
    function tryInjectSidebar() {
      const themeBtn = document.querySelector('[data-testid="button-toggle-theme"]');
      if (themeBtn && !document.getElementById('wc-logout-btn')) {
        themeBtn.parentElement?.appendChild(buildSidebarBtn());
        return true;
      }
      return false;
    }

    // Strategy 1b: Dashboard mobile menu — inject Sign Out at bottom of open dropdown
    function tryInjectMobileMenu() {
      // The mobile dropdown has class 'md:hidden fixed top-[57px]'
      const mobileMenu = document.querySelector('.fixed.top-\\[57px\\]');
      if (mobileMenu && !mobileMenu.querySelector('#wc-logout-mobile')) {
        const btn = buildSidebarBtn();
        btn.id = 'wc-logout-mobile';
        btn.style.marginTop = '4px';
        btn.style.marginBottom = '4px';
        mobileMenu.appendChild(btn);
      }
    }

    // Strategy 2: Field tech — hijack the existing LogOut icon button in the header
    // The compiled app already has a LogOut SVG button — rewire it
    function tryHijackLogoutBtn() {
      const existing = document.getElementById('wc-logout-btn');
      if (existing && document.body.contains(existing)) return true;
      if (existing) existing.remove(); // stale — clean up
      // Find button containing LogOut SVG path (M9 21H5)
      const buttons = document.querySelectorAll('button');
      for (const btn of buttons) {
        const svg = btn.querySelector('svg');
        if (!svg) continue;
        const paths = btn.querySelectorAll('path, polyline, line');
        for (const p of paths) {
          const d = p.getAttribute('d') || p.getAttribute('points') || '';
          if (d.includes('M9 21H5') || d.includes('16 17 21 12')) {
            // This is the LogOut button — rewire it
            btn.id = 'wc-logout-btn';
            // Clone to remove old listeners
            const newBtn = btn.cloneNode(true);
            newBtn.id = 'wc-logout-btn';
            // Style it red to indicate logout
            newBtn.style.color = '#ef4444';
            newBtn.addEventListener('click', doLogout);
            btn.parentNode?.replaceChild(newBtn, btn);
            return true;
          }
        }
      }
      return false;
    }



    function tryInject() {
      if (tryInjectSidebar()) return true;
      if (tryHijackLogoutBtn()) return true;
      return false;
    }

    tryInject();
    let attempts = 0;

    // Keep observer running permanently — re-wires logout btn after every React navigation
    const observer = new MutationObserver(() => {
      attempts++;
      tryInject();
      tryInjectMobileMenu();
      if (attempts > 2000) observer.disconnect();
    });
    observer.observe(document.body, { childList: true, subtree: true });


  }

  function logout() {
    clearToken();
    currentUser = null;
    window.__WC_USER = null;
    document.getElementById('wc-logout-btn')?.remove();
    document.getElementById('wc-logout-mobile')?.remove();
    document.getElementById('wc-users-nav-desktop')?.remove();
    document.getElementById('wc-users-nav-mobile')?.remove();
    document.getElementById('wc-users-panel')?.remove();
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
          // Token valid — show app and inject UI elements
          if (root) root.style.display = "";
          // Sync display name into field tech app header
          syncFieldTechName(user);
          // Start inactivity timer
          startInactivityTimer();
          // Wait for React to mount then inject
          setTimeout(() => {
            injectLogoutButton();
            if (user.role === 'admin') injectUsersNav();
          }, 1500);
          // Block field techs from accessing the dashboard URL
          if (user.role === 'tech') {
            const isDashboard = !window.location.pathname.includes('fieldtech') &&
                                !window.location.href.includes('wilbanks-fieldtech');
            if (isDashboard) {
              if (root) root.style.display = 'none';
              renderLogin('Field Tech accounts cannot access the dashboard.');
              clearToken();
              return;
            }
          }
          // Block dispatcher-only role from field tech app (admin can access both)
          if (user.role === 'dispatcher') {
            const isDashboard = !window.location.pathname.includes('fieldtech') &&
                                !window.location.href.includes('wilbanks-fieldtech');
            if (!isDashboard) {
              if (root) root.style.display = 'none';
              renderLogin('Dashboard accounts cannot access the Field Tech app.');
              clearToken();
              return;
            }
          }
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
