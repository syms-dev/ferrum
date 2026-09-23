// Serving `ui/` -- the operator-facing single-page UI -- straight off disk
// from $FERRUM_UI_DIR, with no framework and no tower-http dependency.
//
// WHY THIS IS UNAUTHENTICATED, since it is the first question a security
// review asks: these are the login page and its assets. Requiring a session
// to fetch the page you log in on is circular, and `ui/` holds nothing
// secret -- it is the same hand-written HTML/CSS/JS that ships in the public
// repository. Every endpoint that returns real data stays inside the
// `protected` router; this is attached as the router's FALLBACK, outside that
// group, which is what keeps the two sets from being confused for each other.
use axum::{
    http::{header, StatusCode, Uri},
    response::{IntoResponse, Response},
};
use std::path::{Path, PathBuf};

fn ui_dir() -> PathBuf {
    std::env::var("FERRUM_UI_DIR")
        .unwrap_or_else(|_| "/share/ferrum/ui".to_string())
        .into()
}

/// Content type from the file extension.
///
/// A short explicit table rather than a mime-guessing dependency: `ui/` is a
/// hand-written tree whose file types we choose, so the set is closed and
/// knowable. Anything unlisted is served as `application/octet-stream`, which
/// a browser will download rather than execute -- the safe default for a file
/// we did not anticipate.
fn content_type(path: &Path) -> &'static str {
    match path.extension().and_then(|e| e.to_str()) {
        Some("html") => "text/html; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("js") | Some("mjs") => "text/javascript; charset=utf-8",
        Some("json") => "application/json",
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        Some("ico") => "image/vnd.microsoft.icon",
        Some("woff2") => "font/woff2",
        _ => "application/octet-stream",
    }
}

/// Percent-decodes a URI path.
///
/// Done explicitly because the traversal check below must run on what the
/// path MEANS, not on the bytes as written: `%2e%2e%2f` is `../` and a check
/// that only looked at the raw form would wave it straight through. Invalid
/// escapes are left as literal characters rather than erroring -- they cannot
/// name a real file in `ui/`, so they resolve to a miss, and a miss is
/// already handled safely.
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).ok();
            if let Some(v) = hex.and_then(|h| u8::from_str_radix(h, 16).ok()) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Collapses runs of `/` into one.
///
/// So that Rule 1 below cannot be stepped around with a doubled separator:
/// `//api/nope` and its encoded form `/%2fapi/nope` both mean `/api/nope` to
/// anyone reading them, and axum matches no real `/api/*` route for either,
/// so without this they would reach the SPA fallback and be answered with
/// index.html and a 200. Nothing legitimate in this stack emits a doubled
/// slash, so normalising costs nothing and closes the variant rather than
/// arguing about whether it is reachable.
fn collapse_slashes(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    let mut last_was_slash = false;
    for c in path.chars() {
        if c == '/' {
            if !last_was_slash {
                out.push(c);
            }
            last_was_slash = true;
        } else {
            out.push(c);
            last_was_slash = false;
        }
    }
    out
}

/// Serves one request against a real UI root.
///
/// The root is a parameter rather than read from the environment here so the
/// tests drive the real logic against a real temp directory without mutating
/// process-wide state other tests read concurrently -- the same reason
/// `jobs::list_jobs_in` exists.
pub fn serve_from(root: &Path, uri_path: &str) -> Response {
    // DECODE FIRST. Rule 1 below must test the same string the file
    // resolution tests, or the two disagree and the gap is a bypass: an
    // earlier version checked the RAW path here, so `/%61pi/nope` (%61 = 'a')
    // failed the literal `/api/` comparison, then decoded to `/api/nope`,
    // matched no file, and fell through to Rule 2 -- answering an API caller
    // with index.html and 200 instead of 404. axum's router matches route
    // strings literally without percent-decoding and this app installs no
    // path-normalising middleware, so such a request reaches the fallback
    // having bypassed every real /api/* route as well. Found in review, with
    // a probe test, not by inspection.
    let decoded = collapse_slashes(&percent_decode(uri_path));

    // Rule 1: never fall back under /api/. An unknown API path is a 404 with
    // an EMPTY body. A JSON client that silently receives an HTML page
    // instead of an error is a genuinely confusing failure -- it fails later,
    // somewhere else, as a parse error that names nothing useful.
    if decoded.starts_with("/api/") || decoded == "/api" {
        return StatusCode::NOT_FOUND.into_response();
    }

    let relative = decoded.trim_start_matches('/');

    // Rule 3: containment by canonicalisation, not by string-matching "..".
    // Canonicalising resolves `..`, `.`, duplicate separators AND symlinks,
    // so a symlink inside the root pointing outside it is caught too -- which
    // no amount of lexical inspection of the request path can do.
    let Ok(canonical_root) = root.canonicalize() else {
        return StatusCode::NOT_FOUND.into_response();
    };

    if !relative.is_empty() {
        let candidate = canonical_root.join(relative);
        if let Ok(resolved) = candidate.canonicalize() {
            if resolved.starts_with(&canonical_root) && resolved.is_file() {
                return match std::fs::read(&resolved) {
                    Ok(bytes) => {
                        ([(header::CONTENT_TYPE, content_type(&resolved))], bytes).into_response()
                    }
                    // The file resolved but could not be read: a real fault,
                    // not a miss, so it must not fall through to index.html
                    // and look like a routing outcome.
                    Err(e) => (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!("could not read {}: {e}", resolved.display()),
                    )
                        .into_response(),
                };
            }
            // Resolved OUTSIDE the root: a traversal attempt, however it was
            // spelled. Refused outright rather than quietly served the index,
            // so the attempt is distinguishable from an ordinary miss.
            if !resolved.starts_with(&canonical_root) {
                return StatusCode::NOT_FOUND.into_response();
            }
        }
    }

    // Rule 2: any other unknown path falls back to index.html, so the UI's
    // own client-side routing survives a refresh or a pasted deep link.
    let index = canonical_root.join("index.html");
    match std::fs::read(&index) {
        Ok(bytes) => (
            [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
            bytes,
        )
            .into_response(),
        Err(_) => (
            StatusCode::NOT_FOUND,
            "the ferrum UI is not installed on this host",
        )
            .into_response(),
    }
}

/// The router fallback. Resolves `$FERRUM_UI_DIR` and delegates.
///
/// The delegate canonicalizes a path and reads a whole file, both blocking,
/// so it runs on the blocking pool -- see main.rs's run_blocking. This is the
/// one route an unauthenticated caller can drive, which makes it the cheapest
/// way to occupy executor threads if it stays on them.
pub async fn serve(uri: Uri) -> Response {
    let path = uri.path().to_string();
    match crate::run_blocking(move || serve_from(&ui_dir(), &path)).await {
        Ok(response) => response,
        Err(status) => status.into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;

    /// A real UI tree: an index, a nested asset, and a file outside the root
    /// that traversal attempts will try to reach.
    fn ui_tree() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("ui");
        std::fs::create_dir_all(root.join("assets")).unwrap();
        std::fs::write(root.join("index.html"), "<!DOCTYPE html><title>ferrum</title>").unwrap();
        std::fs::write(root.join("assets/app.js"), "export const x = 1;\n").unwrap();
        std::fs::write(dir.path().join("outside.txt"), "SECRET").unwrap();
        (dir, root)
    }

    async fn parts(r: Response) -> (StatusCode, String, String) {
        let ct = r
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        let status = r.status();
        let bytes = to_bytes(r.into_body(), usize::MAX).await.unwrap();
        (status, ct, String::from_utf8_lossy(&bytes).into_owned())
    }

    #[tokio::test]
    async fn a_nested_asset_is_served_with_its_own_content_type() {
        let (_d, root) = ui_tree();
        let (status, ct, body) = parts(serve_from(&root, "/assets/app.js")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(ct, "text/javascript; charset=utf-8");
        assert!(body.contains("export const x"));
    }

    #[tokio::test]
    async fn an_unknown_non_api_path_falls_back_to_index_html() {
        let (_d, root) = ui_tree();
        for path in ["/", "/generations", "/apps/sonarr/settings", "/deep/link"] {
            let (status, ct, body) = parts(serve_from(&root, path)).await;
            assert_eq!(status, StatusCode::OK, "{path} should serve the SPA index");
            assert_eq!(ct, "text/html; charset=utf-8");
            assert!(body.contains("<title>ferrum</title>"), "{path} did not get the index");
        }
    }

    /// An unknown API path must be a 404 with an EMPTY body -- asserted on the
    /// body, not just the status, because the failure this prevents is a JSON
    /// client receiving an HTML page and failing later with a parse error that
    /// names nothing useful.
    #[tokio::test]
    async fn an_unknown_api_path_is_404_and_is_not_html() {
        let (_d, root) = ui_tree();
        for path in [
            "/api",
            "/api/",
            "/api/nope",
            "/api/jobs/not-a-real-subpath",
            // Percent-encoded forms. These must be rejected too: the router
            // matches literally and does not decode, so each of these
            // bypasses every real /api/* route and lands here. Checking the
            // RAW path instead of the decoded one let these through with a
            // 200 and an HTML body -- caught in review by a probe test.
            "/%61pi/nope",
            "/api%2fnope",
            "/%61pi%2fjobs",
            "/%2fapi/nope",
            "//api/nope",
        ] {
            let (status, _ct, body) = parts(serve_from(&root, path)).await;
            assert_eq!(status, StatusCode::NOT_FOUND, "{path} must not fall back");
            assert!(body.is_empty(), "{path} returned a body: {body:?}");
            assert!(!body.contains("<!DOCTYPE"), "{path} returned HTML to an API caller");
        }
    }

    /// Traversal, in every spelling I can construct. The canonicalisation
    /// check is what makes the encoded forms fail too -- a lexical ".." scan
    /// would pass `%2e%2e%2f` straight through.
    #[tokio::test]
    async fn traversal_is_rejected_in_every_encoding() {
        let (_d, root) = ui_tree();
        for path in [
            "/../outside.txt",
            "/../../etc/passwd",
            "/assets/../../outside.txt",
            "/%2e%2e/outside.txt",
            "/%2e%2e%2foutside.txt",
            "/..%2foutside.txt",
            "/assets/%2e%2e/%2e%2e/outside.txt",
            "/./../outside.txt",
        ] {
            let (status, _ct, body) = parts(serve_from(&root, path)).await;
            assert!(
                !body.contains("SECRET"),
                "{path} ESCAPED THE ROOT and served the file outside it"
            );
            assert!(
                status == StatusCode::NOT_FOUND || body.contains("<title>ferrum</title>"),
                "{path} gave an unexpected result: {status} {body:?}"
            );
        }
    }

    /// A symlink INSIDE the root pointing outside it. This is the case no
    /// amount of inspecting the request path can catch, and the reason the
    /// check canonicalises the resolved target rather than the request.
    #[tokio::test]
    async fn a_symlink_escaping_the_root_is_rejected() {
        let (dir, root) = ui_tree();
        std::os::unix::fs::symlink(dir.path().join("outside.txt"), root.join("escape.txt")).unwrap();
        let (_status, _ct, body) = parts(serve_from(&root, "/escape.txt")).await;
        assert!(
            !body.contains("SECRET"),
            "a symlink inside the root resolved outside it and was served"
        );
    }

    #[tokio::test]
    async fn a_missing_ui_directory_says_so_rather_than_panicking() {
        let dir = tempfile::tempdir().unwrap();
        let (status, _ct, body) = parts(serve_from(&dir.path().join("absent"), "/")).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert!(body.is_empty() || body.contains("not installed"));
    }
}
