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
  const WEBAUTHN_VALID_KEY = "wc_webauthn_valid"; // set after a successful Face ID login

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
      if (!optRes.ok) return { error: "no_credential" };
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
          try { localStorage.setItem(WEBAUTHN_VALID_KEY, '1'); } catch {}
          setSavedUsername(username);
          onLoginSuccess(result.token, result.user);
        } else {
          try {
            localStorage.removeItem(WEBAUTHN_PROMPT_KEY);
            localStorage.removeItem(WEBAUTHN_VALID_KEY);
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
          if (result?.error === 'no_credential') {
            showError("Face ID isn't set up yet. Sign in with your password below — you'll be prompted to enable Face ID right after.");
          } else {
            showError("Face ID failed. Sign in with your password — you'll be prompted to re-enable Face ID after logging in.");
          }
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
        try { localStorage.setItem(WEBAUTHN_VALID_KEY, '1'); } catch {}
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
    const credentialValid = localStorage.getItem(WEBAUTHN_VALID_KEY) === '1';
    // Only offer Face ID to field tech users (tech/both) — not dashboard-only roles
    const isTechRole = true; // All roles can use Face ID

    if (faceIdAvailable && isTechRole) {
      // Credentials are stale if server has them but they've never successfully
      // authenticated (WEBAUTHN_VALID_KEY not set) — wipe and re-prompt
      const stale = (hasWebAuthn || alreadyPrompted) && !credentialValid;
      if (stale) {
        const tok = _token || localStorage.getItem(TOKEN_KEY) || '';
        const wipe = tok
          ? _origFetch(API + '/api/auth/webauthn', { method: 'DELETE', headers: { 'Authorization': 'Bearer ' + tok } }).catch(() => {})
          : Promise.resolve();
        wipe.then(() => {
          try {
            localStorage.removeItem(WEBAUTHN_PROMPT_KEY);
            localStorage.removeItem(WEBAUTHN_VALID_KEY);
          } catch {}
          currentUser.hasWebAuthn = false;
          renderFaceIdPrompt();
        });
        return;
      }
      // Already set up and working — skip prompt
      if (alreadyPrompted && credentialValid) { launchApp(); return; }
      // Fresh user — never prompted yet
      renderFaceIdPrompt();
    } else {
      launchApp();
    }
  }

  function launchApp() {
    dismissOverlay();
    window.__WC_USER = currentUser;
    window.__WC_LOGOUT = logout;
    // Restore the hash route from before the refresh
    try {
      const savedHash = sessionStorage.getItem('wc_last_hash');
      if (savedHash && savedHash !== '#/' && savedHash !== '#') {
        sessionStorage.removeItem('wc_last_hash');
        // Try immediately, then retry after React has mounted — wouter picks up
        // window.location.hash changes via its own popstate/hashchange listeners
        const _applyHash = () => {
          try { window.location.hash = savedHash.replace(/^#/, ''); } catch {}
        };
        _applyHash();
        setTimeout(_applyHash, 150);
        setTimeout(_applyHash, 500);
      }
    } catch {}
    // Sync display name into the field tech app's localStorage key
    // so the top-left header always shows the logged-in user's name
    syncFieldTechName(currentUser);
    injectLogoutButton();
    // Only inject Users nav for admin users on the dashboard
    // Inject collapsible Admin Tools group for admin/both
    if (currentUser?.role === 'admin' || currentUser?.role === 'both') injectAdminToolsNav();
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
                        !window.location.href.includes('wilbanks-fieldtech') &&
                        !window.location.href.includes('fieldtech');
    if (isDashboard) return; // only needed on field tech app
    try {
      const name = user.displayName || user.username || '';
      localStorage.setItem('wc_tech_name', name);
      // Dispatch storage event so React state in hb() picks up the new value
      // even though it was set in the same window (storage event normally only
      // fires in OTHER windows, so we dispatch it manually)
      window.dispatchEvent(new StorageEvent('storage', {
        key: 'wc_tech_name',
        newValue: name,
        storageArea: localStorage
      }));
    } catch {}
  }

  // ── User Management ────────────────────────────────────────────────────────
  function injectAdminToolsNav() {
    const role = currentUser?.role;
    if (role !== 'admin' && role !== 'both') return;
    const isAdmin = role === 'admin';

    // Track collapsed state across re-injections; auto-open when on an admin page
    if (typeof window._wcAdminOpen === 'undefined') window._wcAdminOpen = false;
    const _curHash = window.location.hash;
    if (_curHash.includes('audit-log') || _curHash.includes('deleted-jobs') || _curHash.includes('/settings')) window._wcAdminOpen = true;

    function buildGroup(refLink) {
      // Remove old group if present
      const old = document.getElementById('wc-admin-tools-group');
      if (old) old.remove();

      const isDark = document.documentElement.classList.contains('dark');
      const open = window._wcAdminOpen;
      const hash = window.location.hash;
      const isActive = hash.includes('audit-log') || hash.includes('deleted-jobs') || hash.includes('/settings');

      const group = document.createElement('div');
      group.id = 'wc-admin-tools-group';
      group.style.cssText = 'margin-bottom:2px;';

      // Folder toggle button
      const toggle = document.createElement('button');
      toggle.style.cssText = `
        display:flex; align-items:center; gap:10px;
        width:100%; padding:8px 12px;
        background:${isActive ? 'hsl(var(--primary))' : 'transparent'};
        color:${isActive ? 'hsl(var(--primary-foreground))' : 'hsl(var(--muted-foreground))'};
        border:none; border-radius:6px; cursor:pointer;
        font-size:14px; font-weight:500; font-family:inherit;
        text-align:left; transition:background 0.15s;
      `;
      toggle.onmouseenter = () => { if (!isActive) toggle.style.background = 'hsl(var(--muted))'; toggle.style.color = 'hsl(var(--foreground))'; };
      toggle.onmouseleave = () => { if (!isActive) { toggle.style.background = 'transparent'; toggle.style.color = 'hsl(var(--muted-foreground))'; } };
      toggle.innerHTML = `
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="flex-shrink:0">
          <rect x="2" y="3" width="20" height="14" rx="2"/><path d="M8 21h8"/><path d="M12 17v4"/>
        </svg>
        <span style="flex:1">Admin Tools</span>
        <svg id="wc-admin-chevron" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"
          style="flex-shrink:0;transition:transform 0.2s;transform:rotate(${open ? 180 : 0}deg)">
          <polyline points="6 9 12 15 18 9"/>
        </svg>
      `;

      // Sub-items container
      const sub = document.createElement('div');
      sub.id = 'wc-admin-sub';
      sub.style.cssText = `overflow:hidden; max-height:${open ? '200px' : '0'}; transition:max-height 0.2s ease;`;

      function makeSubItem({ label, href, onClick, svgPath, active }) {
        const el = document.createElement(href ? 'a' : 'button');
        if (href) el.href = href;
        el.style.cssText = `
          display:flex; align-items:center; gap:10px;
          width:100%; padding:6px 12px 6px 36px;
          background:${active ? 'hsl(var(--primary)/0.15)' : 'transparent'};
          color:${active ? 'hsl(var(--primary))' : 'hsl(var(--muted-foreground))'};
          border:none; border-radius:6px; cursor:pointer;
          font-size:13px; font-weight:500; font-family:inherit;
          text-decoration:none; text-align:left; transition:background 0.15s;
          margin-bottom:1px;
        `;
        el.onmouseenter = () => { if (!active) { el.style.background = 'hsl(var(--muted))'; el.style.color = 'hsl(var(--foreground))'; } };
        el.onmouseleave = () => { if (!active) { el.style.background = 'transparent'; el.style.color = 'hsl(var(--muted-foreground))'; } };
        el.innerHTML = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="flex-shrink:0">${svgPath}</svg><span>${label}</span>`;
        if (onClick) el.addEventListener('click', onClick);
        return el;
      }

      const items = [];
      items.push(makeSubItem({
        label: 'Settings', href: '#/settings', active: hash.includes('/settings'),
        svgPath: '<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/>',
        onClick: null,
      }));
      if (isAdmin) {
        items.push(makeSubItem({
          label: 'Users', href: null, active: false,
          svgPath: '<path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M22 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/>',
          onClick: () => openUsersPanel(),
        }));
      }
      items.push(makeSubItem({
        label: 'Audit Log', href: '#/audit-log', active: hash.includes('audit-log'),
        svgPath: '<path d="M3 3v5h5"/><path d="M3.05 13A9 9 0 1 0 6 5.3L3 8"/><path d="M12 7v5l4 2"/>',
        onClick: null,
      }));
      items.push(makeSubItem({
        label: 'Deleted Jobs', href: '#/deleted-jobs', active: hash.includes('deleted-jobs'),
        svgPath: '<polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/><path d="M10 11v6"/><path d="M14 11v6"/><path d="M9 6V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2"/>',
        onClick: null,
      }));

      items.forEach(item => sub.appendChild(item));

      toggle.addEventListener('click', () => {
        window._wcAdminOpen = !window._wcAdminOpen;
        const chevron = toggle.querySelector('#wc-admin-chevron');
        if (window._wcAdminOpen) {
          sub.style.maxHeight = '200px';
          if (chevron) chevron.style.transform = 'rotate(180deg)';
        } else {
          sub.style.maxHeight = '0';
          if (chevron) chevron.style.transform = 'rotate(0deg)';
        }
      });

      group.appendChild(toggle);
      group.appendChild(sub);
      return group;
    }

    function tryInjectDesktop() {
      const navLinks = document.querySelectorAll('nav a, aside a');
      let settingsLink = null;
      for (const a of navLinks) {
        if (a.textContent?.trim() === 'Settings') settingsLink = a;
      }
      if (!settingsLink) return false;
      if (document.getElementById('wc-admin-tools-group')) return true;

      const group = buildGroup(settingsLink);
      settingsLink.parentElement?.insertBefore(group, settingsLink);
      return true;
    }

    if (!tryInjectDesktop()) {
      const obs = new MutationObserver(() => { if (tryInjectDesktop()) obs.disconnect(); });
      obs.observe(document.body, { childList: true, subtree: true });
      setTimeout(() => obs.disconnect(), 10000);
    }

    // Re-inject on navigation (React wipes injected DOM on route changes)
    window.addEventListener('hashchange', () => {
      setTimeout(() => {
        document.getElementById('wc-admin-tools-group')?.remove();
        tryInjectDesktop();
      }, 300);
    });
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
          // Restore the hash route from before the refresh
          try {
            const savedHash = sessionStorage.getItem('wc_last_hash');
            if (savedHash && savedHash !== '#/' && savedHash !== '#') {
              sessionStorage.removeItem('wc_last_hash');
              const _applyHash = () => {
                try { window.location.hash = savedHash.replace(/^#/, ''); } catch {}
              };
              _applyHash();
              setTimeout(_applyHash, 150);
              setTimeout(_applyHash, 500);
            }
          } catch {}
          // Sync display name into field tech app header
          syncFieldTechName(user);
          // Start inactivity timer
          startInactivityTimer();
          // Wait for React to mount then inject
          setTimeout(() => {
            injectLogoutButton();
            if (user.role === 'admin' || user.role === 'both') injectAdminToolsNav();
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

  // ── Hash persistence on refresh ────────────────────────────────────────────
  // Save the current hash route continuously so a refresh (or iOS PWA relaunch)
  // lands back on the same screen. iOS Safari does NOT reliably fire beforeunload,
  // so we save on hashchange and visibilitychange instead.
  const HASH_KEY = 'wc_last_hash';
  function _saveHash() {
    try {
      const h = window.location.hash;
      if (h && h !== '#/' && h !== '#') {
        sessionStorage.setItem(HASH_KEY, h);
      } else {
        sessionStorage.removeItem(HASH_KEY);
      }
    } catch {}
  }
  window.addEventListener('hashchange', _saveHash);
  document.addEventListener('visibilitychange', _saveHash);
  window.addEventListener('pagehide', _saveHash);
  window.addEventListener('beforeunload', _saveHash);

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", bootstrap);
  } else {
    bootstrap();
  }
})();
