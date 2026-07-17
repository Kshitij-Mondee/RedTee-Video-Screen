import json, urllib.request, urllib.error

B = "http://127.0.0.1:8712"

def req(path, method="GET", body=None, headers=None, cookies=None):
    h = dict(headers or {})
    if cookies:
        h["Cookie"] = "; ".join(f"{k}={v}" for k, v in cookies.items())
    data = body.encode() if isinstance(body, str) else body
    r = urllib.request.Request(B + path, data=data, method=method, headers=h)
    try:
        resp = urllib.request.urlopen(r, timeout=10)
        return resp.status, resp.read().decode("utf-8", "replace"), (resp.headers.get_all("Set-Cookie") or [])
    except urllib.error.HTTPError as e:
        try:
            b = e.read().decode("utf-8", "replace")
        except Exception:
            b = ""
        return e.code, b, []
    except (ConnectionError, OSError) as e:
        # server rejected before consuming the body (expected for oversize/unauth) -> reset
        return "RESET(%s)" % type(e).__name__, "", []

def cookies_of(setcookie):
    ck = {}
    for c in setcookie:
        k, _, v = c.split(";")[0].partition("=")
        ck[k] = v
    return ck

print("health                       :", req("/health")[0])
print("videos noauth (expect 401)   :", req("/api/videos")[0])
print("export noauth (expect 401)   :", req("/api/export.csv")[0])
print("google cb bad state (400)    :", req("/auth/google/cb?code=x&state=y")[0])

# reviewer session via access code
st, bd, sc = req("/api/auth", "POST", json.dumps({"code": "MondeeAccess"}), {"Content-Type": "application/json"})
rck = cookies_of(sc)
print("auth reviewer                :", st, bd.strip())
print("  /api/me admin flag         :", json.loads(req("/api/me", cookies=rck)[1]).get("admin"))
print("  export as reviewer (403)   :", req("/api/export.csv", cookies=rck)[0])
print("  link as reviewer  (403)    :", req("/api/link", "POST", json.dumps({"video_id": "x"}), {"Content-Type": "application/json"}, rck)[0])
print("  collections reviewer (403) :", req("/api/collections", "POST", json.dumps({}), {"Content-Type": "application/json"}, rck)[0])
print("  oversize review (RESET/400):", req("/api/review", "POST", json.dumps({"x": "a" * 2_000_000}), {"Content-Type": "application/json"}, rck)[0])

# admin session via admin code
st, bd, sc = req("/api/auth", "POST", json.dumps({"code": "RedTee_0806"}), {"Content-Type": "application/json"})
ack = cookies_of(sc)
print("auth admin                   :", st, bd.strip())
print("  /api/me admin flag         :", json.loads(req("/api/me", cookies=ack)[1]).get("admin"))
print("  export as admin (200)      :", req("/api/export.csv", cookies=ack)[0])
print("  Secure flag on http (none) :", "Secure" not in " ".join(sc))
