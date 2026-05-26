// Author: Cole Conley
/* ═══════════════════════════════════════════════════════
   OIDC Federation Tester — SP Portal
   app.js
═══════════════════════════════════════════════════════ */

// ═══════════════════════════════════════════════════════
//  APPLICATION STATE
// ═══════════════════════════════════════════════════════
const STORAGE_KEY = 'oidcSpTester_v2';

let APP = loadState() || {
  idps: [],
  users: [
    {
      id: uid(),
      name: 'Admin User',
      username: 'admin',
      email: 'admin@example.com',
      password: hashPw('admin123'),
      role: 'admin',
      source: 'local',
      idpSubs: {},
      createdAt: new Date().toISOString(),
      lastLogin: null,
      loginCount: 0
    }
  ],
  sessions: [],
  auditLog: [],
  currentSession: null,
  stats: { logins: 0 }
};

let FLOW_STATE = {
  idpId: null,
  state: null,
  nonce: null,
  codeVerifier: null,
  codeChallenge: null,
  authCode: null,
  tokens: null,
  userinfo: null,
  startedAt: null
};

function loadState() {
  try { return JSON.parse(localStorage.getItem(STORAGE_KEY)); } catch (e) { return null; }
}
function saveState() {
  try { localStorage.setItem(STORAGE_KEY, JSON.stringify(APP)); } catch (e) {}
}

// ═══════════════════════════════════════════════════════
//  CRYPTO / UTILS
// ═══════════════════════════════════════════════════════
function uid() {
  return Math.random().toString(36).slice(2) + Date.now().toString(36);
}

function hashPw(pw) {
  let h = 0;
  for (let c of pw) { h = (h << 5) - h + c.charCodeAt(0); h |= 0; }
  return h.toString(16);
}

function fmtTime(iso) {
  if (!iso) return '—';
  return new Date(iso).toLocaleString();
}

function fmtAgo(iso) {
  if (!iso) return '—';
  const d = (Date.now() - new Date(iso)) / 1000;
  if (d < 60)    return Math.round(d) + 's ago';
  if (d < 3600)  return Math.round(d / 60) + 'm ago';
  if (d < 86400) return Math.round(d / 3600) + 'h ago';
  return Math.round(d / 86400) + 'd ago';
}

function randomStr(n = 32) {
  const arr = new Uint8Array(n);
  crypto.getRandomValues(arr);
  return btoa(String.fromCharCode(...arr)).replace(/[+/=]/g, '').slice(0, n);
}

async function sha256base64url(str) {
  const enc = new TextEncoder().encode(str);
  const buf = await crypto.subtle.digest('SHA-256', enc);
  return btoa(String.fromCharCode(...new Uint8Array(buf)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function b64urlDecode(s) {
  s = s.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  return JSON.parse(atob(s));
}

function parseJwt(token) {
  try {
    const parts = token.split('.');
    return { header: b64urlDecode(parts[0]), payload: b64urlDecode(parts[1]), raw: token };
  } catch (e) { return null; }
}

function initials(name) {
  if (!name) return '?';
  return name.split(' ').map(w => w[0]).join('').toUpperCase().slice(0, 2);
}

function sourceBadge(source) {
  if (!source || source === 'local') return '<span class="badge badge-gray">local</span>';
  if (source.startsWith('idp:'))     return `<span class="badge badge-blue">${source.slice(4)}</span>`;
  return `<span class="badge badge-purple">${source}</span>`;
}

// ═══════════════════════════════════════════════════════
//  NAVIGATION
// ═══════════════════════════════════════════════════════
function nav(page) {
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));

  const pg = document.getElementById('page-' + page);
  if (pg) pg.classList.add('active');
  const nb = document.getElementById('nav-' + page);
  if (nb) nb.classList.add('active');

  if (page === 'dashboard') renderDashboard();
  if (page === 'idps')      renderIdps();
  if (page === 'oidcflow')  renderFlowPage();
  if (page === 'users')     renderUsers();
  if (page === 'sessions')  renderSessions();
  if (page === 'audit')     renderAudit();
  if (page === 'tokens')    renderSessionTokens();
  if (page === 'profile')   renderProfile();
}

function showLoginPage() {
  document.getElementById('loginPage').classList.add('active');
  document.getElementById('mainApp').style.display = 'none';
  renderIdpButtons();
}

function showApp() {
  document.getElementById('loginPage').classList.remove('active');
  document.getElementById('mainApp').style.display = 'flex';
  updateSidebar();
  renderDashboard();
}

// ═══════════════════════════════════════════════════════
//  AUTH — LOCAL
// ═══════════════════════════════════════════════════════
function localLogin() {
  const email = document.getElementById('loginEmail').value.trim();
  const pw    = document.getElementById('loginPassword').value;
  const user  = APP.users.find(u => (u.email === email || u.username === email) && u.password === hashPw(pw));
  if (!user) { showLoginError('Invalid credentials.'); return; }
  startSession(user, 'local', null);
  showApp();
  nav('dashboard');
  toast(`Welcome back, ${user.name}!`, 'success');
}

function showLoginError(msg) {
  document.getElementById('loginErrorMsg').textContent = msg;
  document.getElementById('loginError').classList.remove('hidden');
}

function logout() {
  if (APP.currentSession) {
    addAudit('LOGOUT', APP.currentSession.userId, null, 'success', 'User signed out');
    APP.currentSession = null;
  }
  saveState();
  updateSidebar();
  showLoginPage();
  toast('Signed out.', 'success');
}

function startSession(user, method, idpId) {
  const session = {
    id: uid(),
    userId: user.id,
    userName: user.name,
    userEmail: user.email,
    method,
    idpId,
    startedAt: new Date().toISOString(),
    tokens: FLOW_STATE.tokens || null
  };
  APP.currentSession = session;
  APP.sessions.unshift(session);
  if (APP.sessions.length > 50) APP.sessions = APP.sessions.slice(0, 50);
  user.lastLogin  = new Date().toISOString();
  user.loginCount = (user.loginCount || 0) + 1;
  APP.stats.logins = (APP.stats.logins || 0) + 1;
  addAudit('LOGIN', user.id, idpId, 'success', `Auth via ${method}`);
  saveState();
  updateSidebar();
  renderSidebarBadges();
}

// ═══════════════════════════════════════════════════════
//  AUTH — USER MANAGEMENT
// ═══════════════════════════════════════════════════════
function createUser(opts) {
  // Programmatic call (from IDP auto-provisioning)
  if (opts) {
    APP.users.push(opts);
    saveState();
    renderSidebarBadges();
    return opts;
  }
  // Modal form submission
  const name     = document.getElementById('regName').value.trim();
  const username = document.getElementById('regUsername').value.trim();
  const email    = document.getElementById('regEmail').value.trim();
  const pw       = document.getElementById('regPassword').value;
  const role     = document.getElementById('regRole').value;

  if (!name || !username || !email || !pw) { regError('All fields required.'); return; }
  if (pw.length < 6)                        { regError('Password min 6 chars.'); return; }
  if (APP.users.find(u => u.email === email))      { regError('Email already exists.'); return; }
  if (APP.users.find(u => u.username === username)) { regError('Username already taken.'); return; }

  const user = {
    id: uid(), name, username, email,
    password: hashPw(pw), role,
    source: 'local', idpSubs: {},
    createdAt: new Date().toISOString(),
    lastLogin: null, loginCount: 0
  };
  APP.users.push(user);
  saveState();
  closeModal('registerModal');
  renderUsers();
  renderSidebarBadges();
  toast(`User ${name} created.`, 'success');
}

function regError(msg) {
  document.getElementById('regErrorMsg').textContent = msg;
  document.getElementById('regError').classList.remove('hidden');
}

function deleteUser(id) {
  if (!confirm('Delete this user?')) return;
  APP.users = APP.users.filter(u => u.id !== id);
  saveState();
  renderUsers();
  renderSidebarBadges();
  toast('User deleted.', 'success');
}

function viewUserDetail(id) {
  const user = APP.users.find(u => u.id === id);
  if (!user) return;
  const el = document.getElementById('userDetailBody');
  el.innerHTML = `
    <div style="display:flex;align-items:center;gap:14px;margin-bottom:20px;">
      <div class="avatar-lg">${initials(user.name)}</div>
      <div>
        <div style="font-size:18px;font-weight:700;font-family:var(--display);">${user.name}</div>
        <div class="text-muted text-sm">${user.email}</div>
        <div style="margin-top:6px;display:flex;gap:6px;">
          ${sourceBadge(user.source)}
          <span class="badge ${user.role === 'admin' ? 'badge-purple' : 'badge-gray'}">${user.role}</span>
        </div>
      </div>
    </div>
    <div class="claims-grid">
      <div class="claim-key">username</div><div class="claim-val">${user.username || '—'}</div>
      <div class="claim-key">id</div><div class="claim-val text-mono" style="font-size:11px;">${user.id}</div>
      <div class="claim-key">created</div><div class="claim-val">${fmtTime(user.createdAt)}</div>
      <div class="claim-key">last login</div><div class="claim-val">${fmtTime(user.lastLogin)}</div>
      <div class="claim-key">login count</div><div class="claim-val">${user.loginCount || 0}</div>
    </div>
    ${Object.keys(user.idpSubs || {}).length ? `
      <hr>
      <div class="card-title" style="margin-bottom:10px;">Linked IDP Identities</div>
      ${Object.entries(user.idpSubs).map(([idpId, sub]) => {
        const idp = APP.idps.find(i => i.id === idpId);
        return `<div style="display:flex;gap:8px;align-items:center;font-size:12px;margin-bottom:6px;">
          <span class="badge badge-blue">${idp ? idp.name : idpId}</span>
          <span class="text-mono text-muted">${sub}</span>
        </div>`;
      }).join('')}
    ` : ''}
  `;
  openModal('userDetailModal');
}

// ═══════════════════════════════════════════════════════
//  IDP CONFIGURATION
// ═══════════════════════════════════════════════════════
function openIdpModal(id) {
  document.getElementById('editIdpId').value    = id || '';
  document.getElementById('idpModalTitle').textContent = id ? 'Edit IDP' : 'Add Identity Provider';

  if (id) {
    const idp = APP.idps.find(i => i.id === id);
    if (idp) {
      document.getElementById('idpName').value           = idp.name           || '';
      document.getElementById('idpColor').value          = idp.color          || '#3b82f6';
      document.getElementById('idpProtocol').value       = idp.protocol       || 'oidc';
      document.getElementById('idpIssuer').value         = idp.issuer         || '';
      document.getElementById('idpAuthEndpoint').value   = idp.authEndpoint   || '';
      document.getElementById('idpTokenEndpoint').value  = idp.tokenEndpoint  || '';
      document.getElementById('idpUserinfoEndpoint').value = idp.userinfoEndpoint || '';
      document.getElementById('idpJwksUri').value        = idp.jwksUri        || '';
      document.getElementById('idpClientId').value       = idp.clientId       || '';
      document.getElementById('idpClientSecret').value   = idp.clientSecret   || '';
      document.getElementById('idpRedirectUri').value    = idp.redirectUri    || '';
      document.getElementById('idpScopes').value         = idp.scopes         || 'openid profile email';
      document.getElementById('idpMatchField').value     = idp.matchField     || 'email';
      document.getElementById('idpAutoProvision').value  = String(idp.autoProvision !== false);
    }
  } else {
    document.getElementById('idpName').value           = '';
    document.getElementById('idpColor').value          = '#3b82f6';
    document.getElementById('idpProtocol').value       = 'oidc';
    document.getElementById('idpIssuer').value         = '';
    document.getElementById('idpAuthEndpoint').value   = '';
    document.getElementById('idpTokenEndpoint').value  = '';
    document.getElementById('idpUserinfoEndpoint').value = '';
    document.getElementById('idpJwksUri').value        = '';
    document.getElementById('idpClientId').value       = '';
    document.getElementById('idpClientSecret').value   = '';
    document.getElementById('idpRedirectUri').value    = window.location.href.split('?')[0];
    document.getElementById('idpScopes').value         = 'openid profile email';
    document.getElementById('idpMatchField').value     = 'email';
    document.getElementById('idpAutoProvision').value  = 'true';
  }
  openModal('idpModal');
}

function saveIdp() {
  const id  = document.getElementById('editIdpId').value;
  const idp = {
    id:                id || uid(),
    name:              document.getElementById('idpName').value.trim(),
    color:             document.getElementById('idpColor').value,
    protocol:          document.getElementById('idpProtocol').value,
    issuer:            document.getElementById('idpIssuer').value.trim(),
    authEndpoint:      document.getElementById('idpAuthEndpoint').value.trim(),
    tokenEndpoint:     document.getElementById('idpTokenEndpoint').value.trim(),
    userinfoEndpoint:  document.getElementById('idpUserinfoEndpoint').value.trim(),
    jwksUri:           document.getElementById('idpJwksUri').value.trim(),
    clientId:          document.getElementById('idpClientId').value.trim(),
    clientSecret:      document.getElementById('idpClientSecret').value,
    redirectUri:       document.getElementById('idpRedirectUri').value.trim(),
    scopes:            document.getElementById('idpScopes').value.trim(),
    matchField:        document.getElementById('idpMatchField').value,
    autoProvision:     document.getElementById('idpAutoProvision').value === 'true',
    createdAt:         new Date().toISOString()
  };

  if (!idp.name || !idp.authEndpoint || !idp.tokenEndpoint || !idp.clientId) {
    toast('Name, Auth/Token endpoints and Client ID are required.', 'error');
    return;
  }

  if (id) {
    const idx = APP.idps.findIndex(i => i.id === id);
    if (idx >= 0) APP.idps[idx] = idp;
  } else {
    APP.idps.push(idp);
  }

  saveState();
  closeModal('idpModal');
  renderIdps();
  renderSidebarBadges();
  renderIdpButtons();
  toast(`IDP "${idp.name}" saved.`, 'success');
}

function deleteIdp(id) {
  if (!confirm('Remove this IDP?')) return;
  APP.idps = APP.idps.filter(i => i.id !== id);
  saveState();
  renderIdps();
  renderSidebarBadges();
  renderIdpButtons();
}

function toggleIdpBody(id) {
  const el = document.getElementById('idpBody-' + id);
  el.classList.toggle('open');
}

// ═══════════════════════════════════════════════════════
//  OIDC FLOW
// ═══════════════════════════════════════════════════════
async function startOidcFlow() {
  const idpId = document.getElementById('flowIdpSelect').value;
  const idp   = APP.idps.find(i => i.id === idpId);
  if (!idp) { toast('Select an IDP first.', 'error'); return; }

  resetFlow();
  FLOW_STATE = {
    idpId, state: null, nonce: null,
    codeVerifier: null, codeChallenge: null,
    authCode: null, tokens: null, userinfo: null,
    startedAt: new Date().toISOString()
  };

  const usePkce  = document.getElementById('usePkce').checked;
  const useNonce = document.getElementById('useNonce').checked;
  const scopes   = document.getElementById('flowScopes').value.trim();
  const acr      = document.getElementById('flowAcr').value.trim();

  // Step 1 — Generate state & PKCE
  setStep('state', 'active');
  FLOW_STATE.state = randomStr(32);
  FLOW_STATE.nonce = useNonce ? randomStr(32) : null;

  let challengeInfo = 'state=' + FLOW_STATE.state.slice(0, 16) + '…';
  if (usePkce) {
    FLOW_STATE.codeVerifier  = randomStr(64);
    FLOW_STATE.codeChallenge = await sha256base64url(FLOW_STATE.codeVerifier);
    challengeInfo += ' | verifier=' + FLOW_STATE.codeVerifier.slice(0, 12) + '… challenge=' + FLOW_STATE.codeChallenge.slice(0, 12) + '…';
  }
  if (useNonce) challengeInfo += ' | nonce=' + FLOW_STATE.nonce.slice(0, 12) + '…';

  // Persist flow state for redirect callback
  sessionStorage.setItem('oidcFlowState', JSON.stringify({ ...FLOW_STATE, idpId }));
  setStep('state', 'done', challengeInfo);

  // Step 2 — Build authorize URL
  setStep('authorize', 'active');
  const params = new URLSearchParams({
    response_type: 'code',
    client_id:     idp.clientId,
    redirect_uri:  idp.redirectUri || window.location.href.split('?')[0],
    scope:         scopes,
    state:         FLOW_STATE.state
  });
  if (usePkce) {
    params.set('code_challenge',        FLOW_STATE.codeChallenge);
    params.set('code_challenge_method', 'S256');
  }
  if (useNonce) params.set('nonce',       FLOW_STATE.nonce);
  if (acr)      params.set('acr_values',  acr);

  const authUrl = idp.authEndpoint + '?' + params.toString();
  setStep('authorize', 'done', authUrl.slice(0, 80) + '…');

  document.getElementById('flowRequestCard').style.display = '';
  document.getElementById('flowRequestUrl').textContent    = authUrl;
  document.getElementById('manualCodeCard').style.display  = '';

  setStep('callback', 'active', 'Waiting for redirect…');
  addAudit('OIDC_FLOW_START', APP.currentSession?.userId || null, idpId, 'pending', 'Authorization request built');

  // Attempt popup
  try {
    const popup = window.open(authUrl, 'oidcLogin', 'width=600,height=700,scrollbars=yes');
    if (!popup) throw new Error('blocked');

    let checkCount = 0;
    const timer = setInterval(() => {
      checkCount++;
      if (checkCount > 300) { clearInterval(timer); return; }
      try {
        const popupUrl = popup.location.href;
        if (popupUrl && popupUrl.includes('code=')) {
          clearInterval(timer);
          popup.close();
          handleCallback(new URL(popupUrl).searchParams);
        }
        if (popup.closed && checkCount > 2) clearInterval(timer);
      } catch (e) { /* cross-origin — still loading */ }
    }, 500);
  } catch (e) {
    toast('Popup blocked. Copy the URL, complete login, then paste the code.', 'warn');
  }
}

async function handleCallback(params) {
  const code          = params.get('code');
  const returnedState = params.get('state');
  const error         = params.get('error');

  if (error) {
    setStep('callback', 'error', 'IDP error: ' + error + ' — ' + (params.get('error_description') || ''));
    addAudit('OIDC_CALLBACK', null, FLOW_STATE.idpId, 'error', error);
    return;
  }
  if (returnedState !== FLOW_STATE.state) {
    setStep('callback', 'error', 'State mismatch! Possible CSRF. Expected: ' + FLOW_STATE.state.slice(0, 12));
    return;
  }

  FLOW_STATE.authCode = code;
  setStep('callback', 'done', 'code=' + code.slice(0, 20) + '…  state ✓ verified');
  await exchangeCode(code);
}

async function exchangeCodeManual() {
  const code = document.getElementById('manualCode').value.trim();
  if (!code) { toast('Enter the authorization code.', 'error'); return; }
  handleCallback(new URLSearchParams('code=' + code + '&state=' + FLOW_STATE.state));
}

async function exchangeCode(code) {
  const idp = APP.idps.find(i => i.id === FLOW_STATE.idpId);
  if (!idp) return;

  const body = new URLSearchParams({
    grant_type:   'authorization_code',
    code,
    redirect_uri: idp.redirectUri || window.location.href.split('?')[0],
    client_id:    idp.clientId
  });
  if (idp.clientSecret)       body.set('client_secret',  idp.clientSecret);
  if (FLOW_STATE.codeVerifier) body.set('code_verifier', FLOW_STATE.codeVerifier);

  const tokenReqDetail =
    `POST ${idp.tokenEndpoint}\n  grant_type=authorization_code\n  code=${code.slice(0, 20)}…\n  ` +
    (FLOW_STATE.codeVerifier ? 'code_verifier=' + FLOW_STATE.codeVerifier.slice(0, 16) + '…' : '(no PKCE)');
  setStep('token', 'active', tokenReqDetail);

  try {
    const resp = await fetch(idp.tokenEndpoint, {
      method:  'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body:    body.toString()
    });
    const data = await resp.json();

    if (!resp.ok || data.error) {
      setStep('token', 'error', 'Error: ' + (data.error || resp.status) + ' — ' + (data.error_description || ''));
      addAudit('TOKEN_EXCHANGE', null, idp.id, 'error', data.error || resp.status);
      return;
    }

    FLOW_STATE.tokens = data;
    setStep('token', 'done',
      `access_token ✓ (${data.token_type || 'Bearer'}, expires_in=${data.expires_in || '?'}s)` +
      (data.id_token      ? ' | id_token ✓'      : '') +
      (data.refresh_token ? ' | refresh_token ✓' : '')
    );
    addAudit('TOKEN_EXCHANGE', null, idp.id, 'success', 'Tokens received');
    await fetchUserInfo(idp, data);

  } catch (e) {
    setStep('token', 'error', 'Network error: ' + e.message);
    addAudit('TOKEN_EXCHANGE', null, idp.id, 'error', e.message);
  }
}

async function fetchUserInfo(idp, tokens) {
  if (!idp.userinfoEndpoint) {
    setStep('userinfo', 'done', 'No userinfo endpoint configured — skipping');
    provisionUser(idp, tokens, {});
    return;
  }

  setStep('userinfo', 'active', `GET ${idp.userinfoEndpoint}`);

  try {
    const resp = await fetch(idp.userinfoEndpoint, {
      headers: {
        'Authorization': 'Bearer ' + tokens.access_token,
        'Accept':        'application/json'
      }
    });
    const info = await resp.json();

    if (!resp.ok) {
      setStep('userinfo', 'error', 'Error ' + resp.status + ': ' + JSON.stringify(info));
      return;
    }

    FLOW_STATE.userinfo = info;
    setStep('userinfo', 'done', `sub=${info.sub || '?'} email=${info.email || '?'} name=${info.name || '?'}`);
    addAudit('USERINFO', null, idp.id, 'success', `sub=${info.sub}`);
    provisionUser(idp, tokens, info);

  } catch (e) {
    setStep('userinfo', 'error', 'Network error: ' + e.message + ' (check CORS)');
    // Fall back to id_token claims
    if (tokens.id_token) {
      const claims = parseJwt(tokens.id_token);
      if (claims) provisionUser(idp, tokens, claims.payload);
    }
  }
}

function provisionUser(idp, tokens, userinfo) {
  setStep('provision', 'active');

  // Merge id_token claims with userinfo (userinfo takes precedence)
  let claims = { ...userinfo };
  if (tokens.id_token) {
    const parsed = parseJwt(tokens.id_token);
    if (parsed) claims = { ...parsed.payload, ...claims };
  }

  const matchField = idp.matchField || 'email';
  const matchVal   = claims[matchField] || claims.email || claims.sub;

  let user   = null;
  let action = '';

  // Match existing user
  if (matchField === 'email')    user = APP.users.find(u => u.email    === matchVal);
  if (matchField === 'username') user = APP.users.find(u => u.username === matchVal);
  if (matchField === 'sub')      user = APP.users.find(u => u.idpSubs && u.idpSubs[idp.id] === matchVal);

  // Fallback: match by stored sub for this IDP
  if (!user && claims.sub) {
    user = APP.users.find(u => u.idpSubs && u.idpSubs[idp.id] === claims.sub);
  }

  if (user) {
    if (!user.idpSubs) user.idpSubs = {};
    if (claims.sub) user.idpSubs[idp.id] = claims.sub;
    action = 'matched_existing';
    setStep('provision', 'done', `Matched existing user: ${user.name} (${user.email})`);

  } else if (idp.autoProvision) {
    user = {
      id:          uid(),
      name:        claims.name || claims.given_name || claims.email || claims.sub || 'IDP User',
      username:    claims.preferred_username || claims.email?.split('@')[0] || claims.sub?.slice(0, 12) || uid().slice(0, 8),
      email:       claims.email || claims.sub + '@idp.local',
      password:    null,
      role:        'user',
      source:      'idp:' + idp.name,
      idpSubs:     { [idp.id]: claims.sub },
      createdAt:   new Date().toISOString(),
      lastLogin:   null,
      loginCount:  0
    };
    APP.users.push(user);
    action = 'provisioned';
    setStep('provision', 'done', `Auto-provisioned new user: ${user.name} (${user.email})`);
    addAudit('USER_PROVISION', user.id, idp.id, 'success', 'New user created from IDP');
    toast(`New user provisioned: ${user.name}`, 'success');

  } else {
    setStep('provision', 'error', 'No matching user found and auto-provision disabled.');
    addAudit('USER_PROVISION', null, idp.id, 'error', `No match for ${matchField}=${matchVal}`);
    return;
  }

  startSession(user, 'oidc:' + idp.name, idp.id);
  renderSidebarBadges();
  showFlowResult(idp, tokens, claims, user, action);
  renderSessionTokens();
}

function showFlowResult(idp, tokens, claims, user, action) {
  const el   = document.getElementById('flowResult');
  const body = document.getElementById('flowResultBody');
  el.style.display = '';

  const idClaims = tokens.id_token ? parseJwt(tokens.id_token) : null;

  body.innerHTML = `
    <div class="alert alert-success" style="margin-bottom:14px;">
      <span>✓</span>
      <span>Federation successful — user ${action === 'provisioned' ? '<strong>provisioned</strong>' : '<strong>matched</strong>'} and session started.</span>
    </div>
    <div class="two-col" style="margin-bottom:14px;">
      <div>
        <div class="token-label">Matched User</div>
        <div style="display:flex;align-items:center;gap:10px;margin-top:6px;">
          <div class="avatar-sm" style="width:36px;height:36px;font-size:13px;">${initials(user.name)}</div>
          <div>
            <div style="font-weight:500;">${user.name}</div>
            <div class="text-muted text-sm">${user.email}</div>
            <div style="margin-top:4px;">${sourceBadge(user.source)}</div>
          </div>
        </div>
      </div>
      <div>
        <div class="token-label">Token Summary</div>
        <div style="display:flex;flex-direction:column;gap:4px;margin-top:6px;">
          ${tokens.access_token  ? '<div><span class="badge badge-green">access_token ✓</span></div>'  : ''}
          ${tokens.id_token      ? '<div><span class="badge badge-blue">id_token ✓</span></div>'       : ''}
          ${tokens.refresh_token ? '<div><span class="badge badge-amber">refresh_token ✓</span></div>' : ''}
        </div>
      </div>
    </div>
    ${idClaims ? `
      <div class="token-label">Identity Token Claims</div>
      <div class="claims-grid" style="margin-top:6px;margin-bottom:12px;">
        ${Object.entries(idClaims.payload).slice(0, 12).map(([k, v]) => `
          <div class="claim-key">${k}</div>
          <div class="claim-val">${typeof v === 'object' ? JSON.stringify(v) : String(v)}</div>
        `).join('')}
      </div>
    ` : ''}
    <div style="display:flex;gap:8px;flex-wrap:wrap;">
      <button class="btn btn-primary btn-sm" onclick="showApp();nav('dashboard');">View Dashboard →</button>
      <button class="btn btn-ghost btn-sm" onclick="nav('tokens')">Inspect Tokens</button>
    </div>
  `;
}

// ═══════════════════════════════════════════════════════
//  FLOW UI HELPERS
// ═══════════════════════════════════════════════════════
function setStep(step, status, detail) {
  const el   = document.getElementById('step-' + step);
  const icon = el.querySelector('.step-icon');
  const det  = document.getElementById('step-' + step + '-detail');

  el.className   = 'flow-step ' + (status === 'done' ? 'done' : status === 'active' ? 'active' : status === 'error' ? 'error' : '');
  icon.className = 'step-icon ' + status;

  const nums = { state: '1', authorize: '2', callback: '3', token: '4', userinfo: '5', provision: '6' };
  icon.textContent = status === 'done' ? '✓' : status === 'error' ? '✕' : status === 'active' ? '…' : nums[step];

  if (detail && det) {
    det.textContent = detail;
    det.className   = 'step-detail ' + (status === 'done' ? 'ok' : status === 'error' ? 'err' : '');
  }
}

function resetFlow() {
  ['state', 'authorize', 'callback', 'token', 'userinfo', 'provision'].forEach(s => {
    setStep(s, 'pending', '');
    const d = document.getElementById('step-' + s + '-detail');
    if (d) d.className = 'step-detail';
  });
  document.getElementById('flowRequestCard').style.display = 'none';
  document.getElementById('manualCodeCard').style.display  = 'none';
  document.getElementById('flowResult').style.display      = 'none';
  // Restore default step labels
  document.getElementById('step-authorize-detail').textContent = 'Redirect to IDP /authorize';
  document.getElementById('step-callback-detail').textContent  = 'Awaiting redirect…';
  document.getElementById('step-token-detail').textContent     = 'POST /access_token with code';
  document.getElementById('step-userinfo-detail').textContent  = 'GET /userinfo with Bearer token';
  document.getElementById('step-provision-detail').textContent = 'Match or create local user';
}

function copyFlowUrl() {
  navigator.clipboard.writeText(document.getElementById('flowRequestUrl').textContent)
    .then(() => toast('URL copied!', 'success'));
}

// ═══════════════════════════════════════════════════════
//  RENDER FUNCTIONS
// ═══════════════════════════════════════════════════════
function renderIdpButtons() {
  const cont = document.getElementById('idpButtons');
  const none = document.getElementById('noIdpsMsg');
  if (!APP.idps.length) {
    cont.innerHTML = '';
    none.classList.remove('hidden');
    return;
  }
  none.classList.add('hidden');
  cont.innerHTML = APP.idps.map(idp => `
    <button class="idp-btn idp-btn-primary" onclick="initiateIdpLogin('${idp.id}')">
      <div class="idp-icon" style="background:${idp.color}22;color:${idp.color};border-color:${idp.color}44;">
        ${(idp.name[0] || '?').toUpperCase()}
      </div>
      Login with ${idp.name}
    </button>
  `).join('');
}

function initiateIdpLogin(idpId) {
  showApp();
  nav('oidcflow');
  document.getElementById('flowIdpSelect').value = idpId;
  setTimeout(() => startOidcFlow(), 100);
}

function renderDashboard() {
  document.getElementById('statIdps').textContent  = APP.idps.length;
  document.getElementById('statUsers').textContent = APP.users.length;
  document.getElementById('statLogins').textContent = APP.stats.logins || 0;

  const sessEl    = document.getElementById('dashSession');
  const alertEl   = document.getElementById('dashAlert');
  const logoutBtn = document.getElementById('logoutBtn');

  if (APP.currentSession) {
    alertEl.classList.add('hidden');
    logoutBtn.style.display = '';
    sessEl.innerHTML = `
      <div style="display:flex;align-items:center;gap:12px;">
        <div class="avatar-lg" style="width:48px;height:48px;font-size:16px;">${initials(APP.currentSession.userName)}</div>
        <div>
          <div style="font-weight:600;font-size:15px;">${APP.currentSession.userName}</div>
          <div class="text-muted text-sm">${APP.currentSession.userEmail}</div>
          <div style="margin-top:6px;display:flex;gap:6px;flex-wrap:wrap;">
            <span class="badge badge-green">● Active</span>
            <span class="badge badge-gray">${APP.currentSession.method}</span>
            ${APP.currentSession.tokens?.id_token      ? '<span class="badge badge-blue">id_token</span>'      : ''}
            ${APP.currentSession.tokens?.access_token  ? '<span class="badge badge-green">access_token</span>' : ''}
          </div>
          <div class="text-muted text-sm" style="margin-top:6px;">Since ${fmtAgo(APP.currentSession.startedAt)}</div>
        </div>
      </div>`;
  } else {
    alertEl.classList.remove('hidden');
    logoutBtn.style.display = 'none';
    sessEl.innerHTML = '<div class="text-muted text-sm">No active session.</div>';
  }

  const actEl  = document.getElementById('dashActivity');
  const recent = APP.auditLog.slice(0, 6);
  actEl.innerHTML = recent.length
    ? recent.map(a => `
        <div style="display:flex;align-items:center;gap:8px;padding:7px 0;border-bottom:1px solid var(--border);">
          <span class="badge ${a.status === 'success' ? 'badge-green' : a.status === 'error' ? 'badge-red' : a.status === 'pending' ? 'badge-amber' : 'badge-gray'}" style="flex-shrink:0;">
            ${a.status}
          </span>
          <span style="flex:1;font-size:12px;">${a.event.replace(/_/g, ' ')}</span>
          <span class="text-muted text-sm">${fmtAgo(a.ts)}</span>
        </div>
      `).join('')
    : '<div class="text-muted text-sm">No activity yet.</div>';

  const idpEl = document.getElementById('dashIdps');
  idpEl.innerHTML = APP.idps.length
    ? `<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:10px;">
        ${APP.idps.map(idp => `
          <div style="padding:12px;background:var(--surface2);border-radius:var(--radius);border-left:3px solid ${idp.color};">
            <div style="font-weight:600;font-size:13px;">${idp.name}</div>
            <div class="text-muted text-sm">${idp.protocol.toUpperCase()} · ${idp.clientId}</div>
            <div style="margin-top:6px;display:flex;gap:4px;">
              ${idp.autoProvision ? '<span class="badge badge-green">auto-provision</span>' : '<span class="badge badge-amber">match-only</span>'}
            </div>
          </div>
        `).join('')}
       </div>`
    : '<div class="text-muted text-sm">No IDPs configured. <a href="#" onclick="nav(\'idps\');return false;" style="color:var(--accent2)">Add one →</a></div>';
}

function renderIdps() {
  const el = document.getElementById('idpList');
  if (!APP.idps.length) {
    el.innerHTML = `
      <div class="card">
        <div style="text-align:center;padding:32px;color:var(--muted);">
          <div style="font-size:32px;margin-bottom:12px;">⛓</div>
          <div style="font-size:15px;font-weight:600;margin-bottom:6px;">No IDPs configured</div>
          <div style="font-size:13px;margin-bottom:16px;">Add your ForgeRock AM or any OIDC-compliant identity provider.</div>
          <button class="btn btn-primary" onclick="openIdpModal()">+ Add IDP</button>
        </div>
      </div>`;
    return;
  }
  el.innerHTML = APP.idps.map(idp => `
    <div class="idp-config-item">
      <div class="idp-config-header" onclick="toggleIdpBody('${idp.id}')">
        <div class="idp-color-dot" style="background:${idp.color};"></div>
        <div style="flex:1;">
          <div style="font-weight:600;font-size:14px;">${idp.name}</div>
          <div class="text-muted text-sm">${idp.authEndpoint || '—'}</div>
        </div>
        <div style="display:flex;gap:6px;align-items:center;">
          <span class="badge badge-blue">${idp.protocol.toUpperCase()}</span>
          ${idp.autoProvision
            ? '<span class="badge badge-green">auto-provision</span>'
            : '<span class="badge badge-amber">match-only</span>'}
        </div>
        <div style="color:var(--muted);margin-left:8px;font-size:16px;">⌄</div>
      </div>
      <div class="idp-config-body" id="idpBody-${idp.id}">
        <div class="two-col">
          <div class="claims-grid">
            <div class="claim-key">Client ID</div><div class="claim-val text-mono">${idp.clientId}</div>
            <div class="claim-key">Match Field</div><div class="claim-val">${idp.matchField}</div>
            <div class="claim-key">Scopes</div><div class="claim-val text-mono">${idp.scopes}</div>
            <div class="claim-key">Redirect URI</div><div class="claim-val text-mono" style="font-size:11px;">${idp.redirectUri || '—'}</div>
          </div>
          <div class="claims-grid">
            <div class="claim-key">Token Endpoint</div><div class="claim-val text-mono" style="font-size:11px;">${idp.tokenEndpoint}</div>
            <div class="claim-key">UserInfo</div><div class="claim-val text-mono" style="font-size:11px;">${idp.userinfoEndpoint || '—'}</div>
            <div class="claim-key">JWKS URI</div><div class="claim-val text-mono" style="font-size:11px;">${idp.jwksUri || '—'}</div>
          </div>
        </div>
        <div style="margin-top:12px;display:flex;gap:8px;">
          <button class="btn btn-ghost btn-sm" onclick="openIdpModal('${idp.id}')">Edit</button>
          <button class="btn btn-ghost btn-sm" onclick="initiateIdpLogin('${idp.id}')">▶ Test Flow</button>
          <button class="btn btn-danger btn-sm" onclick="deleteIdp('${idp.id}')">Delete</button>
        </div>
      </div>
    </div>
  `).join('');
}

function renderFlowPage() {
  const sel = document.getElementById('flowIdpSelect');
  sel.innerHTML = APP.idps.length
    ? APP.idps.map(i => `<option value="${i.id}">${i.name}</option>`).join('')
    : '<option value="">— No IDPs configured —</option>';
}

function renderUsers() {
  const q      = (document.getElementById('userSearch')?.value || '').toLowerCase();
  const tbody  = document.getElementById('usersTableBody');
  const filtered = APP.users.filter(u =>
    !q ||
    u.name?.toLowerCase().includes(q) ||
    u.email?.toLowerCase().includes(q) ||
    u.username?.toLowerCase().includes(q)
  );
  tbody.innerHTML = filtered.map(user => `
    <tr>
      <td>
        <div style="display:flex;align-items:center;gap:10px;">
          <div class="avatar-sm">${initials(user.name)}</div>
          <div>
            <div style="font-weight:500;">${user.name}</div>
            <div class="text-muted text-sm">@${user.username || '—'}</div>
          </div>
        </div>
      </td>
      <td class="text-sm">${user.email}</td>
      <td>${sourceBadge(user.source)}</td>
      <td class="text-mono text-sm text-muted">
        ${Object.keys(user.idpSubs || {}).length ? Object.values(user.idpSubs)[0]?.slice(0, 16) + '…' : '—'}
      </td>
      <td class="text-sm text-muted">${fmtAgo(user.lastLogin)}</td>
      <td>
        <div style="display:flex;gap:4px;">
          <button class="btn btn-ghost btn-sm" onclick="viewUserDetail('${user.id}')">View</button>
          <button class="btn btn-danger btn-sm" onclick="deleteUser('${user.id}')">✕</button>
        </div>
      </td>
    </tr>
  `).join('') || `<tr><td colspan="6" class="text-muted text-sm" style="text-align:center;padding:20px;">No users found.</td></tr>`;
}

function renderSessions() {
  const tbody = document.getElementById('sessionsTableBody');
  tbody.innerHTML = APP.sessions.slice(0, 20).map(s => {
    const idp      = APP.idps.find(i => i.id === s.idpId);
    const isActive = APP.currentSession?.id === s.id;
    return `
      <tr>
        <td>
          <div style="font-weight:500;">${s.userName}</div>
          <div class="text-muted text-sm">${s.userEmail}</div>
        </td>
        <td>${idp ? `<span class="badge badge-blue">${idp.name}</span>` : '<span class="badge badge-gray">local</span>'}</td>
        <td class="text-mono text-sm">${s.method}</td>
        <td class="text-sm text-muted">${fmtAgo(s.startedAt)}</td>
        <td>
          ${s.tokens?.access_token  ? '<span class="badge badge-green">AT</span> '  : ''}
          ${s.tokens?.id_token      ? '<span class="badge badge-blue">IT</span> '   : ''}
          ${s.tokens?.refresh_token ? '<span class="badge badge-amber">RT</span>'   : ''}
        </td>
        <td>
          ${isActive ? '<span class="badge badge-green">Active</span>' : '<span class="badge badge-gray">Ended</span>'}
        </td>
      </tr>`;
  }).join('') || `<tr><td colspan="6" class="text-muted text-sm" style="text-align:center;padding:20px;">No sessions yet.</td></tr>`;
}

function renderAudit() {
  const tbody = document.getElementById('auditTableBody');
  const empty = document.getElementById('auditEmpty');
  if (!APP.auditLog.length) { tbody.innerHTML = ''; empty.style.display = ''; return; }
  empty.style.display = 'none';
  tbody.innerHTML = APP.auditLog.map(a => {
    const idp = APP.idps.find(i => i.id === a.idpId);
    return `
      <tr>
        <td class="text-mono text-sm text-muted">${fmtAgo(a.ts)}</td>
        <td style="font-weight:500;">${a.event.replace(/_/g, ' ')}</td>
        <td class="text-sm">${a.userId ? (APP.users.find(u => u.id === a.userId)?.name || a.userId) : '—'}</td>
        <td>${idp ? `<span class="badge badge-blue">${idp.name}</span>` : '—'}</td>
        <td>
          <span class="badge ${
            a.status === 'success' ? 'badge-green'  :
            a.status === 'error'   ? 'badge-red'    :
            a.status === 'pending' ? 'badge-amber'  : 'badge-gray'
          }">${a.status}</span>
        </td>
        <td class="text-sm text-muted">${a.detail || '—'}</td>
      </tr>`;
  }).join('');
}

function renderSessionTokens() {
  const el     = document.getElementById('sessionTokensList');
  const tokens = APP.currentSession?.tokens || FLOW_STATE.tokens;

  if (!tokens) {
    el.innerHTML = '<div class="text-muted text-sm">Complete an OIDC flow to see tokens here.</div>';
    return;
  }

  const sections = [
    { key: 'access_token',  label: 'Access Token',            badge: 'badge-green' },
    { key: 'id_token',      label: 'Identity Token (JWT)',     badge: 'badge-blue' },
    { key: 'refresh_token', label: 'Refresh Token',            badge: 'badge-amber' }
  ];

  el.innerHTML = sections.filter(s => tokens[s.key]).map(s => {
    const decoded = parseJwt(tokens[s.key]);
    return `
      <div class="token-section">
        <div style="display:flex;align-items:center;gap:8px;margin-bottom:6px;">
          <span class="badge ${s.badge}">${s.label}</span>
          ${decoded ? '<span class="text-muted text-sm">JWT decoded ↓</span>' : ''}
          <button class="btn btn-ghost btn-sm" style="margin-left:auto;" onclick="
            document.getElementById('tokenInput').value='${tokens[s.key]}';
            decodeToken();nav('tokens');
          ">Inspect</button>
        </div>
        <div class="token-value">${tokens[s.key].slice(0, 120)}…</div>
        ${decoded ? `
          <div class="claims-grid" style="margin-top:8px;padding:10px;background:var(--surface2);border-radius:var(--radius);">
            ${Object.entries(decoded.payload).slice(0, 8).map(([k, v]) =>
              `<div class="claim-key">${k}</div><div class="claim-val">${typeof v === 'object' ? JSON.stringify(v) : String(v)}</div>`
            ).join('')}
          </div>
        ` : ''}
      </div>
      <hr>
    `;
  }).join('');

  if (tokens.expires_in) {
    el.innerHTML += `<div class="text-muted text-sm">Token expires in: ${tokens.expires_in}s · Token type: ${tokens.token_type || 'Bearer'}</div>`;
  }
}

function renderProfile() {
  const card    = document.getElementById('profileCard');
  const tokCard = document.getElementById('profileTokens');

  if (!APP.currentSession) {
    card.innerHTML    = '<div class="text-muted text-sm">Not signed in. <a href="#" onclick="showLoginPage();return false;" style="color:var(--accent2)">Sign in →</a></div>';
    tokCard.style.display = 'none';
    return;
  }

  const user = APP.users.find(u => u.id === APP.currentSession.userId);
  if (!user) return;
  const idp = APP.idps.find(i => i.id === APP.currentSession.idpId);

  card.innerHTML = `
    <div class="avatar-lg">${initials(user.name)}</div>
    <div style="text-align:center;">
      <div style="font-size:18px;font-weight:700;font-family:var(--display);">${user.name}</div>
      <div class="text-muted" style="font-size:13px;">${user.email}</div>
    </div>
    <div style="display:flex;gap:6px;flex-wrap:wrap;justify-content:center;">
      ${sourceBadge(user.source)}
      <span class="badge ${user.role === 'admin' ? 'badge-purple' : 'badge-gray'}">${user.role}</span>
      ${idp ? `<span class="badge badge-blue">${idp.name}</span>` : ''}
    </div>
    <div class="claims-grid" style="text-align:left;width:100%;">
      <div class="claim-key">username</div><div class="claim-val">@${user.username || '—'}</div>
      <div class="claim-key">last login</div><div class="claim-val">${fmtTime(user.lastLogin)}</div>
      <div class="claim-key">total logins</div><div class="claim-val">${user.loginCount || 0}</div>
      <div class="claim-key">method</div><div class="claim-val text-mono">${APP.currentSession.method}</div>
    </div>
  `;

  const tokens = APP.currentSession.tokens;
  if (tokens) {
    tokCard.style.display = '';
    document.getElementById('profileTokenBody').innerHTML = Object.entries(tokens)
      .filter(([k]) => ['access_token', 'id_token', 'refresh_token', 'token_type', 'expires_in', 'scope'].includes(k))
      .map(([k, v]) => `
        <div class="token-section">
          <div class="token-label">${k}</div>
          <div class="token-value">${typeof v === 'string' && v.length > 60 ? v.slice(0, 60) + '…' : v}</div>
        </div>
      `).join('');
  } else {
    tokCard.style.display = 'none';
  }
}

// ═══════════════════════════════════════════════════════
//  TOKEN DECODER
// ═══════════════════════════════════════════════════════
function decodeToken() {
  const raw     = document.getElementById('tokenInput').value.trim();
  const decoded = parseJwt(raw);
  const card    = document.getElementById('tokenDecoded');

  if (!decoded) { card.style.display = 'none'; toast('Not a valid JWT.', 'error'); return; }

  card.style.display = '';
  renderClaimsGrid('tokenHeaderGrid',  decoded.header);
  renderClaimsGrid('tokenPayloadGrid', decoded.payload);
  document.getElementById('tokenRaw').textContent = JSON.stringify(decoded.payload, null, 2);
}

function renderClaimsGrid(id, obj) {
  document.getElementById(id).innerHTML = Object.entries(obj).map(([k, v]) => {
    let display = typeof v === 'object' ? JSON.stringify(v) : String(v);
    if (['iat', 'exp', 'nbf', 'auth_time'].includes(k) && typeof v === 'number') {
      display = `${v} (${new Date(v * 1000).toLocaleString()})`;
    }
    return `<div class="claim-key">${k}</div><div class="claim-val">${display}</div>`;
  }).join('');
}

function tokenTab(name, btn) {
  document.querySelectorAll('#tokenDecoded .tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('#tokenDecoded .tab-panel').forEach(p => p.classList.remove('active'));
  btn.classList.add('active');
  document.getElementById('token-' + name + '-panel').classList.add('active');
}

// ═══════════════════════════════════════════════════════
//  SIDEBAR / BADGES
// ═══════════════════════════════════════════════════════
function updateSidebar() {
  const sess = APP.currentSession;
  document.getElementById('sidebarName').textContent   = sess ? sess.userName : 'Not signed in';
  document.getElementById('sidebarRole').textContent   = sess ? sess.method   : 'guest';
  document.getElementById('sidebarAvatar').textContent = sess ? initials(sess.userName) : '?';
  const dot = document.getElementById('sidebarStatus');
  dot.style.background = sess ? 'var(--green)' : 'var(--muted)';
  dot.style.boxShadow  = sess ? '0 0 6px var(--green)' : 'none';
  renderSidebarBadges();
}

function renderSidebarBadges() {
  document.getElementById('idpCount').textContent   = APP.idps.length;
  document.getElementById('userCount').textContent  = APP.users.length;
  document.getElementById('auditCount').textContent = APP.auditLog.length;
}

// ═══════════════════════════════════════════════════════
//  AUDIT LOG
// ═══════════════════════════════════════════════════════
function addAudit(event, userId, idpId, status, detail) {
  APP.auditLog.unshift({ id: uid(), ts: new Date().toISOString(), event, userId, idpId, status, detail });
  if (APP.auditLog.length > 200) APP.auditLog = APP.auditLog.slice(0, 200);
  saveState();
  renderSidebarBadges();
}

// ═══════════════════════════════════════════════════════
//  MODALS
// ═══════════════════════════════════════════════════════
function openModal(id)  { document.getElementById(id).classList.add('open'); }
function closeModal(id) { document.getElementById(id).classList.remove('open'); }

function openRegisterModal() {
  ['regName', 'regUsername', 'regEmail', 'regPassword'].forEach(f => {
    document.getElementById(f).value = '';
  });
  document.getElementById('regError').classList.add('hidden');
  openModal('registerModal');
}

// Close modal on backdrop click
document.addEventListener('DOMContentLoaded', () => {
  document.querySelectorAll('.modal-backdrop').forEach(m => {
    m.addEventListener('click', e => { if (e.target === m) m.classList.remove('open'); });
  });
});

// ═══════════════════════════════════════════════════════
//  TOAST NOTIFICATIONS
// ═══════════════════════════════════════════════════════
function toast(msg, type = 'info') {
  const area  = document.getElementById('toastArea');
  const t     = document.createElement('div');
  const icons = { success: '✓', error: '✕', warn: '⚠', info: 'ℹ' };
  t.className = `toast ${type === 'success' ? 'success' : type === 'error' ? 'error' : ''}`;
  t.innerHTML = `<span>${icons[type] || 'ℹ'}</span><span>${msg}</span>`;
  area.appendChild(t);
  setTimeout(() => t.remove(), 3500);
}

// ═══════════════════════════════════════════════════════
//  URL CALLBACK HANDLER
// ═══════════════════════════════════════════════════════
function checkUrlCallback() {
  const params = new URLSearchParams(window.location.search);
  if (!params.has('code') && !params.has('error')) return;

  const saved = sessionStorage.getItem('oidcFlowState');
  if (!saved) return;

  try {
    const fs = JSON.parse(saved);
    FLOW_STATE = fs;
    sessionStorage.removeItem('oidcFlowState');
    showApp();
    nav('oidcflow');
    setStep('state',     'done', 'State restored from session');
    setStep('authorize', 'done', 'Authorization redirect completed');
    document.getElementById('manualCodeCard').style.display = '';
    handleCallback(params);
    window.history.replaceState({}, '', window.location.pathname);
  } catch (e) {
    console.error('Failed to restore OIDC flow state:', e);
  }
}

// ═══════════════════════════════════════════════════════
//  INIT
// ═══════════════════════════════════════════════════════
window.addEventListener('load', () => {
  checkUrlCallback();
  renderIdpButtons();
  renderSidebarBadges();
  updateSidebar();

  if (APP.currentSession) {
    showApp();
    nav('dashboard');
  } else {
    showLoginPage();
  }
});
