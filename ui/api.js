// The only module that talks to ferrumd. Every other file goes through here,
// so the CSRF header, the session-expiry rule and the error shape are decided
// once instead of at each call site.
//
// No framework and no build step: this is an ES module the browser loads
// directly. Keep it that way -- see nix/pkgs/ferrum-ui/default.nix for why.

// Exactly the header main.rs's CSRF_HEADER constant names. Read from the
// source, not guessed: if the daemon ever renames it, a mutating request
// starts coming back 403 and this line is the one to change.
const CSRF_HEADER = "X-CSRF-Token";

/// Thrown for any non-2xx response. `status` lets a caller distinguish the
/// cases that mean something specific -- 409 from a job already running, 400
/// from schema validation -- from the ones that are just failures.
export class ApiError extends Error {
  constructor(status, body) {
    super(body || `request failed with ${status}`);
    this.name = "ApiError";
    this.status = status;
    this.body = body;
  }
}

// The CSRF token for this session, refreshed by `session()`. Held in a module
// variable rather than localStorage on purpose: it is a per-session
// anti-forgery nonce, it dies with the tab, and persisting it would only
// create a stale copy to debug later.
let csrfToken = null;

// Set by the app so a 401 anywhere can drop straight back to the login view.
let onUnauthenticated = () => {};

export function setUnauthenticatedHandler(fn) {
  onUnauthenticated = fn;
}

/// `csrf: false` marks a mutating call the daemon does NOT gate on a CSRF
/// token, because it is not behind `require_session`. There are exactly two:
/// login and logout, both registered on the outer router in main.rs rather
/// than inside the `protected` group. Getting this wrong is not theoretical
/// -- the first browser load of this UI failed with "no CSRF token yet"
/// because login went down the guarded path and demanded the very token you
/// log in to obtain.
async function request(method, path, { body, raw = false, csrf = true } = {}) {
  const headers = {};
  const mutating = csrf && !["GET", "HEAD", "OPTIONS", "TRACE"].includes(method);

  if (mutating) {
    // The daemon rejects a mutating request whose header does not match the
    // session's own token, so sending nothing is a guaranteed 403. Better to
    // fail here, naming the real cause, than to read a 403 as "forbidden".
    if (!csrfToken) {
      throw new ApiError(0, "no CSRF token yet -- call session() before mutating");
    }
    headers[CSRF_HEADER] = csrfToken;
  }

  let payload;
  if (body !== undefined) {
    if (raw) {
      payload = body;
    } else {
      headers["Content-Type"] = "application/json";
      payload = JSON.stringify(body);
    }
  }

  const response = await fetch(path, {
    method,
    headers,
    body: payload,
    // Same-origin only. The session cookie is HttpOnly + SameSite=Strict and
    // the daemon serves this page itself, so there is never a cross-origin
    // call to make.
    credentials: "same-origin",
  });

  if (response.status === 401) {
    // A session expiring while a tab sits open is an ordinary event, not a
    // fault. Drop to the login view rather than surfacing a raw error the
    // operator can do nothing with.
    csrfToken = null;
    onUnauthenticated();
    throw new ApiError(401, "session expired");
  }

  if (!response.ok) {
    throw new ApiError(response.status, (await response.text()).trim());
  }

  if (response.status === 204) return null;
  const text = await response.text();
  if (!text) return null;
  const type = response.headers.get("content-type") || "";
  return type.includes("application/json") ? JSON.parse(text) : text;
}

// --- session -------------------------------------------------------------

export async function login(username, password) {
  // csrf: false -- see `request`. /api/login is outside the protected router,
  // so the daemon never checks a CSRF header here, and requiring one would
  // make logging in impossible on a fresh page load.
  const result = await request("POST", "/api/login", {
    body: { username, password },
    csrf: false,
  });
  csrfToken = result.csrf_token;
  return result;
}

export async function logout() {
  // csrf: false for the same reason as login, plus one of its own: logging
  // out must still work when the token is already stale, which is exactly
  // when someone reaches for it.
  try {
    await request("POST", "/api/logout", { csrf: false });
  } catch {
    // A failed logout still clears local state -- leaving the UI believing
    // it is logged in would be worse than a server-side session lingering
    // until it expires.
  }
  csrfToken = null;
}

/// Who am I, and what token do my mutating requests need?
///
/// Called on every load. The cookie survives a refresh but the token does not
/// -- the cookie is HttpOnly, so this page can never read it back -- which is
/// exactly the gap this endpoint exists to close.
export async function session() {
  const result = await request("GET", "/api/session");
  csrfToken = result.csrf_token;
  return result;
}

// --- reads ---------------------------------------------------------------

export const catalog = () => request("GET", "/api/catalog");
export const settings = () => request("GET", "/api/settings");
export const generations = () => request("GET", "/api/generations");
export const jobs = (limit) =>
  request("GET", `/api/jobs${limit ? `?limit=${encodeURIComponent(limit)}` : ""}`);
export const job = (id) => request("GET", `/api/jobs/${encodeURIComponent(id)}`);

// --- writes --------------------------------------------------------------

/// Writes settings. NEVER triggers an apply -- that is a separate, explicit
/// call the operator makes. See `startJob`.
export const putSettings = (document) =>
  request("PUT", "/api/settings", { body: document });

/// Write-only. There is no GET for a secret and there must never be one, so
/// the UI can only ever report THAT a value is set, never what it is.
export const putSecret = (name, value) =>
  request("POST", `/api/secrets/${encodeURIComponent(name)}`, {
    body: value,
    raw: true,
  });

/// Starts a privileged job. `kind` is one of the daemon's closed set:
/// preflight, apply, rollback, restore_state, gc.
export const startJob = (kind, extra = {}) =>
  request("POST", "/api/jobs", { body: { kind, ...extra } });

// --- job progress --------------------------------------------------------

/// Live-tails a job's progress over SSE.
///
/// Returns the EventSource so a caller can close it. The daemon closes the
/// stream itself once it writes the job's terminal `complete` line, but a
/// view being torn down must close it too or the connection leaks for as long
/// as the tab lives.
export function streamJob(id, { onEvent, onDone, onError } = {}) {
  const source = new EventSource(`/api/jobs/${encodeURIComponent(id)}/stream`);
  source.addEventListener("progress", (message) => {
    let parsed;
    try {
      parsed = JSON.parse(message.data);
    } catch {
      // A line that does not parse is still real evidence that the job wrote
      // something, so it is shown rather than dropped.
      parsed = { event: "raw", detail: String(message.data) };
    }
    onEvent?.(parsed);
    if (parsed.event === "complete") {
      source.close();
      onDone?.(parsed);
    }
  });
  source.onerror = () => {
    // EventSource reconnects on its own, so an error here is not necessarily
    // terminal. It is surfaced, not acted on.
    onError?.();
  };
  return source;
}
