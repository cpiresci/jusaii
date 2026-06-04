/**
 * ╔══════════════════════════════════════════════════════════════════════╗
 * ║  JURIR — webview-guard.js v3.0                                     ║
 * ║  WebView Guard + Ambiente + Auth Redirect + Token Bridge           ║
 * ╠══════════════════════════════════════════════════════════════════════╣
 * ║  [NEW v3.0] Bridge token para WebView Android/iOS nativo           ║
 * ║  [NEW v3.0] Detecção de ambiente (web/pwa/webview/app)             ║
 * ║  [KEEP]    Proteção de acesso ao admin.html                        ║
 * ║  [KEEP]    Redirecionamento de auth expirado                       ║
 * ╚══════════════════════════════════════════════════════════════════════╝
 *
 * INCLUIR em todas as páginas ANTES de qualquer outro script:
 *   <script src="webview-guard.js"></script>
 */

(function JURIR_GUARD() {
  'use strict';

  /* ══════════════════════════════════════════════════════════════
     1. CONSTANTES
  ══════════════════════════════════════════════════════════════ */
  const GUARD_VERSION   = '3.0.0';
  const ADMIN_PATH_RE   = /admin\.html$/i;
  const TOKEN_KEY       = 'jurir_token';
  const USER_KEY        = 'jurir_user';
  const SESSION_KEY     = 'jurir_admin_token';
  const TOKEN_TTL_MS    = 8 * 60 * 60 * 1000;   // 8h — mesmo TTL do JWT
  const LAST_ACTIVE_KEY = 'jurir_last_active';
  const ENV_KEY         = 'jurir_env';
  const API_BASE_PROD   = 'https://jusaii-app-daqr.onrender.com';
  const API_BASE_DEV    = 'http://localhost:10000';

  /* ══════════════════════════════════════════════════════════════
     2. ENVIRONMENT DETECTION
  ══════════════════════════════════════════════════════════════ */
  const _ua = (navigator.userAgent || '').toLowerCase();

  const ENV = {
    isWebView: (
      /wv/.test(_ua) ||
      /webview/.test(_ua) ||
      (/android/.test(_ua) && !/chrome/.test(_ua)) ||
      (window.webkit && window.webkit.messageHandlers) ||
      typeof window.JurirAndroid !== 'undefined' ||
      typeof window.JurirBridge  !== 'undefined'
    ),
    isAndroid:  /android/.test(_ua),
    isIOS:      /iphone|ipad|ipod/.test(_ua),
    isPWA: (
      window.matchMedia('(display-mode: standalone)').matches ||
      window.navigator.standalone === true
    ),
    isDev: (
      location.hostname === 'localhost' ||
      location.hostname === '127.0.0.1' ||
      location.hostname.startsWith('192.168.')
    ),
    isAdmin: ADMIN_PATH_RE.test(location.pathname),
  };

  ENV.type = ENV.isWebView ? 'webview'
           : ENV.isPWA     ? 'pwa'
           : ENV.isDev      ? 'dev'
           :                  'web';

  ENV.apiBase = ENV.isDev ? API_BASE_DEV : API_BASE_PROD;

  // Expõe globalmente para uso em index.html / admin.html
  window.__JURIR_ENV__    = ENV;
  window.__JURIR_GUARD__  = GUARD_VERSION;

  /* ══════════════════════════════════════════════════════════════
     3. STORAGE HELPERS — safe wrappers (não trava em iframe/incognito)
  ══════════════════════════════════════════════════════════════ */
  function _lsGet(key) {
    try { return localStorage.getItem(key); } catch (_) { return null; }
  }
  function _lsSet(key, val) {
    try { localStorage.setItem(key, val); } catch (_) {}
  }
  function _lsDel(key) {
    try { localStorage.removeItem(key); } catch (_) {}
  }
  function _ssGet(key) {
    try { return sessionStorage.getItem(key); } catch (_) { return null; }
  }
  function _ssDel(key) {
    try { sessionStorage.removeItem(key); } catch (_) {}
  }

  /* ══════════════════════════════════════════════════════════════
     4. TOKEN HELPERS
  ══════════════════════════════════════════════════════════════ */
  function _parseJWT(token) {
    try {
      const parts = token.split('.');
      if (parts.length !== 3) return null;
      const payload = JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/')));
      return payload;
    } catch (_) {
      return null;
    }
  }

  function _isTokenExpired(token) {
    if (!token) return true;
    const payload = _parseJWT(token);
    if (!payload) return true;
    const exp = payload.exp;
    if (!exp) return false;                        // sem exp → considera válido
    return Date.now() / 1000 > exp;
  }

  function _clearAuth() {
    _lsDel(TOKEN_KEY);
    _lsDel(USER_KEY);
    _ssDel(SESSION_KEY);
    _lsDel(LAST_ACTIVE_KEY);
  }

  /* ══════════════════════════════════════════════════════════════
     5. WEBVIEW TOKEN BRIDGE
     Recebe token injetado pelo app nativo (Android/iOS) e
     armazena no localStorage para que o JS do index.html o use.
  ══════════════════════════════════════════════════════════════ */
  function _installBridge() {
    /**
     * Chamado pelo app Android via:
     *   webView.evaluateJavascript("window.JurirBridge.receiveToken('...')", null)
     * Ou pelo iOS via:
     *   window.webkit.messageHandlers.jurirToken.postMessage({token:'...'})
     */
    window.JurirBridge = window.JurirBridge || {};

    window.JurirBridge.receiveToken = function (token) {
      if (!token || typeof token !== 'string') return;
      _lsSet(TOKEN_KEY, token);
      _lsSet(LAST_ACTIVE_KEY, Date.now().toString());
      // Dispara evento para que o index.html saiba que o token chegou
      window.dispatchEvent(new CustomEvent('jurir:token-received', { detail: { token } }));
      _log('bridge: token received from native app');
    };

    window.JurirBridge.clearSession = function () {
      _clearAuth();
      window.dispatchEvent(new CustomEvent('jurir:session-cleared'));
      _log('bridge: session cleared by native app');
    };

    window.JurirBridge.getApiBase = function () {
      return ENV.apiBase;
    };

    // iOS WKWebView message handler polyfill
    if (window.webkit && window.webkit.messageHandlers) {
      window.addEventListener('message', function (e) {
        if (!e.data) return;
        try {
          const msg = typeof e.data === 'string' ? JSON.parse(e.data) : e.data;
          if (msg.type === 'jurir:token' && msg.token) {
            window.JurirBridge.receiveToken(msg.token);
          }
          if (msg.type === 'jurir:clear') {
            window.JurirBridge.clearSession();
          }
        } catch (_) {}
      });
    }
  }

  /* ══════════════════════════════════════════════════════════════
     6. SESSION INACTIVITY TIMEOUT
     Invalida o token local após TOKEN_TTL_MS de inatividade.
     (Não desconecta o usuário que está ativo — apenas sessões antigas)
  ══════════════════════════════════════════════════════════════ */
  function _checkInactivityTimeout() {
    const last = parseInt(_lsGet(LAST_ACTIVE_KEY) || '0', 10);
    if (!last) return;                             // nunca registrado → ignora
    if (Date.now() - last > TOKEN_TTL_MS) {
      _log('session expired by inactivity — clearing auth');
      _clearAuth();
    }
  }

  function _refreshActivity() {
    _lsSet(LAST_ACTIVE_KEY, Date.now().toString());
  }

  /* ══════════════════════════════════════════════════════════════
     7. ADMIN PAGE GUARD
     Só permite acesso ao admin.html se houver token de admin válido.
  ══════════════════════════════════════════════════════════════ */
  function _adminGuard() {
    if (!ENV.isAdmin) return;

    const adminToken = _ssGet(SESSION_KEY);

    // Sem token de sessão admin → mostra gate (já está no HTML)
    // Nada a fazer aqui — o admin.html tem seu próprio gate embutido.
    // Este guard apenas evita que o conteúdo seja carregado em iframe.

    // Anti-clickjacking: impede o admin.html de ser embarcado em iframe
    if (window.top !== window.self) {
      document.documentElement.innerHTML = '<body style="background:#000;color:#f44;font-family:monospace;padding:20px;">403 — Acesso negado: framing não permitido.</body>';
      _log('SECURITY: admin.html framing blocked');
      return;
    }

    // Esconde o app até que o gate valide (o gate é exibido por padrão pelo CSS do admin.html)
    _log(`admin guard active — ENV.type=${ENV.type}`);
  }

  /* ══════════════════════════════════════════════════════════════
     8. AUTH REDIRECT LISTENER
     Ouve eventos de 401/403 disparados pelo JS das páginas e
     redireciona para o modal de login (ou limpa a sessão).
  ══════════════════════════════════════════════════════════════ */
  function _installAuthListener() {
    window.addEventListener('jurir:auth-error', function (e) {
      const reason = (e.detail && e.detail.reason) || 'unknown';
      _log(`auth error: ${reason}`);
      if (reason === 'token_expired' || reason === '401' || reason === '403') {
        _clearAuth();
        // Notifica a página para abrir o modal de login
        window.dispatchEvent(new CustomEvent('jurir:open-login'));
      }
    });
  }

  /* ══════════════════════════════════════════════════════════════
     9. NETWORK INTERCEPTOR
     Patches fetch globalmente para:
       - Injetar token automaticamente em requests para API_BASE
       - Disparar jurir:auth-error em 401/403
       - Registrar latência de requests no console (apenas DEV)
  ══════════════════════════════════════════════════════════════ */
  function _patchFetch() {
    const _originalFetch = window.fetch.bind(window);

    window.fetch = async function (input, init) {
      const url = typeof input === 'string' ? input : (input.url || '');
      const isApiCall = url.startsWith(ENV.apiBase) || url.startsWith('/api/');

      // Injeta token se a chamada for para a nossa API e não tiver Authorization explícito
      if (isApiCall) {
        const token = _lsGet(TOKEN_KEY) || _ssGet(SESSION_KEY);
        if (token && !_isTokenExpired(token)) {
          init = init || {};
          init.headers = init.headers || {};
          // Não sobrescreve se já foi passado explicitamente
          if (!init.headers['Authorization'] && !init.headers['authorization']) {
            init.headers['Authorization'] = `Bearer ${token}`;
          }
        }
        _refreshActivity();
      }

      const t0 = performance.now();
      let response;
      try {
        response = await _originalFetch(input, init);
      } catch (networkErr) {
        if (ENV.isDev) _log(`fetch error [${url.slice(0,60)}]: ${networkErr.message}`);
        throw networkErr;
      }

      const ms = (performance.now() - t0).toFixed(0);
      if (ENV.isDev && isApiCall) {
        _log(`fetch ${response.status} ${url.slice(0, 60)} — ${ms}ms`);
      }

      // 401 / 403 → dispara evento de auth error
      if (isApiCall && (response.status === 401 || response.status === 403)) {
        const cloned = response.clone();
        cloned.json().catch(() => ({})).then(body => {
          window.dispatchEvent(new CustomEvent('jurir:auth-error', {
            detail: {
              reason:  String(response.status),
              message: body.detail || body.message || '',
              url,
            },
          }));
        });
      }

      return response;
    };
  }

  /* ══════════════════════════════════════════════════════════════
     10. PERFORMANCE METRICS (Web Vitals lite)
     Expõe window.__JURIR_PERF__ para debug.
  ══════════════════════════════════════════════════════════════ */
  function _installPerfMonitor() {
    window.__JURIR_PERF__ = {
      navigationStart: performance.now(),
      requests: [],
      mark: function (name) {
        this.requests.push({ name, ts: performance.now() });
      },
    };

    // LCP aproximado via PerformanceObserver
    if (typeof PerformanceObserver !== 'undefined') {
      try {
        const obs = new PerformanceObserver(function (list) {
          const entries = list.getEntries();
          if (entries.length) {
            const lcp = entries[entries.length - 1].startTime;
            window.__JURIR_PERF__.lcp = lcp;
            if (ENV.isDev) _log(`LCP: ${lcp.toFixed(0)}ms`);
          }
        });
        obs.observe({ type: 'largest-contentful-paint', buffered: true });
      } catch (_) {}
    }
  }

  /* ══════════════════════════════════════════════════════════════
     11. CSP VIOLATION REPORTER (DEV only)
  ══════════════════════════════════════════════════════════════ */
  function _installCSPReporter() {
    if (!ENV.isDev) return;
    document.addEventListener('securitypolicyviolation', function (e) {
      _log(`CSP violation: ${e.blockedURI} — directive: ${e.violatedDirective}`);
    });
  }

  /* ══════════════════════════════════════════════════════════════
     12. CONSOLE HELPER
  ══════════════════════════════════════════════════════════════ */
  function _log(msg) {
    if (ENV.isDev || ENV.isWebView) {
      console.log(`[JURIR Guard v${GUARD_VERSION}] ${msg}`);
    }
  }

  /* ══════════════════════════════════════════════════════════════
     13. DARK MODE SYNC
     Persiste e sincroniza a preferência de tema entre páginas.
  ══════════════════════════════════════════════════════════════ */
  function _syncTheme() {
    const stored = _lsGet('jurir_theme');
    const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
    const theme = stored || (prefersDark ? 'dark' : 'dark'); // JURIR é sempre dark por design

    // Por ora apenas aplica a classe ao html para uso futuro
    document.documentElement.dataset.theme = theme;
  }

  /* ══════════════════════════════════════════════════════════════
     14. RESIZE / ORIENTATION HELPER
     Expõe evento jurir:layout-change para o index.html
     adaptar o painel de agentes em mobile.
  ══════════════════════════════════════════════════════════════ */
  function _installLayoutHelper() {
    let lastW = window.innerWidth;
    const onResize = _debounce(function () {
      const newW = window.innerWidth;
      if (newW !== lastW) {
        lastW = newW;
        window.dispatchEvent(new CustomEvent('jurir:layout-change', {
          detail: {
            width:    newW,
            height:   window.innerHeight,
            isMobile: newW < 640,
            isTablet: newW >= 640 && newW < 1024,
          },
        }));
      }
    }, 150);
    window.addEventListener('resize', onResize);
    window.addEventListener('orientationchange', onResize);
  }

  /* ══════════════════════════════════════════════════════════════
     15. UTILS
  ══════════════════════════════════════════════════════════════ */
  function _debounce(fn, ms) {
    let timer;
    return function () {
      clearTimeout(timer);
      timer = setTimeout(fn, ms);
    };
  }

  /* ══════════════════════════════════════════════════════════════
     16. PUBLIC API
     Expõe métodos úteis para o código das páginas.
  ══════════════════════════════════════════════════════════════ */
  window.JurirGuard = {
    version:    GUARD_VERSION,
    env:        ENV,

    getToken: function () {
      return _lsGet(TOKEN_KEY) || null;
    },

    getAdminToken: function () {
      return _ssGet(SESSION_KEY) || null;
    },

    isAuthenticated: function () {
      const token = _lsGet(TOKEN_KEY);
      return !!token && !_isTokenExpired(token);
    },

    isAdminAuthenticated: function () {
      const token = _ssGet(SESSION_KEY);
      return !!token && !_isTokenExpired(token);
    },

    clearAuth: _clearAuth,

    refreshActivity: _refreshActivity,

    parseJWT: _parseJWT,

    isTokenExpired: _isTokenExpired,

    apiBase: function () {
      return ENV.apiBase;
    },

    /**
     * Emite evento de erro de autenticação — use nos handlers fetch
     * quando receber 401/403 manualmente.
     */
    triggerAuthError: function (reason, message) {
      window.dispatchEvent(new CustomEvent('jurir:auth-error', {
        detail: { reason: reason || 'unknown', message: message || '' },
      }));
    },
  };

  /* ══════════════════════════════════════════════════════════════
     17. BOOT SEQUENCE
  ══════════════════════════════════════════════════════════════ */
  _log(`booting — ENV.type=${ENV.type} | admin=${ENV.isAdmin}`);
  _checkInactivityTimeout();
  _adminGuard();
  _installBridge();
  _installAuthListener();
  _patchFetch();
  _installPerfMonitor();
  _installCSPReporter();
  _syncTheme();
  _installLayoutHelper();

  // Registra atividade ao carregar a página
  if (_lsGet(TOKEN_KEY)) {
    _refreshActivity();
  }

  _log(`ready — apiBase=${ENV.apiBase}`);

})();
