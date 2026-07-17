#!/usr/bin/env python3
"""RedTee Review - the screening room. A single-file, stdlib-only platform where
reviewers WATCH lesson videos (streamed from a shared Google Drive folder) and
file a DETAILED review: structured ratings (specific) + open reflections (vague)
so feedback captures both the measurable and the felt.

Run:      python review/server.py            ->  http://127.0.0.1:8712
Videos:   review/config.json - EITHER
            {"drive_folder_id": "...", "drive_api_key": "..."}   (folder listed live)
          OR a manual manifest:
            {"videos": [{"url": "https://drive.google.com/file/d/FILE_ID/view", "title": "Lesson 1"}]}
          Drive files must be shared "anyone with the link can view".
Reviews:  saved as JSON under review/reviews/<video_id>/ (git-ignored; may contain names)
Export:   /api/export.csv  - one row per review, ratings + answers flattened.
"""
import hashlib, json, os, re, secrets, shutil, time, urllib.request, urllib.parse
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from pathlib import Path

HERE = Path(__file__).resolve().parent
CONF_PATH = HERE / "config.json"
REVIEW_DIR = HERE / "reviews"
PORT = int(os.environ.get("REDTEE_REVIEW_PORT", "8712"))
HOST = os.environ.get("REDTEE_REVIEW_HOST", "127.0.0.1")   # 0.0.0.0 for a central org deployment
MAX_JSON_BODY = 1_000_000                                  # 1 MB cap on JSON POST bodies (DoS guard)


# ---------------- org access control (cookie gate; set access_code to enable) ----------------
def _codes():
    c = _conf()
    access = os.environ.get("REDTEE_REVIEW_CODE") or str(c.get("access_code") or "")
    admin = os.environ.get("REDTEE_REVIEW_ADMIN_CODE") or str(c.get("admin_code") or "") or access
    return access.strip(), admin.strip()


def _auth_on() -> bool:
    a, ad = _codes()
    return bool(a or ad or _admin_emails() or _oauth_conf().get("client_id"))


def _salt() -> str:
    c = _conf()
    if not c.get("_salt"):
        c["_salt"] = secrets.token_hex(16)
        try:
            CONF_PATH.write_text(json.dumps(c, indent=1, ensure_ascii=False), encoding="utf-8")
        except OSError:
            pass
    return str(c.get("_salt") or "static")


def _token(code: str) -> str:
    return hashlib.sha256((code + "|" + _salt()).encode()).hexdigest()[:40]


INVITES_PATH = HERE / "invites.json"
SESSIONS_PATH = HERE / "sessions.json"


def _sessions() -> dict:
    try:
        return json.loads(SESSIONS_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _save_sessions(d: dict):
    if len(d) > 2000:                                   # keep the newest 2000
        d = dict(sorted(d.items(), key=lambda kv: kv[1].get("ts", 0))[-2000:])
    SESSIONS_PATH.write_text(json.dumps(d, indent=1, ensure_ascii=False), encoding="utf-8")


def _new_session(email: str, name: str, via: str) -> str:
    sid = secrets.token_urlsafe(24)
    d = _sessions()
    d[sid] = {"email": (email or "").strip().lower(), "name": (name or email or "reviewer").strip(),
              "via": via, "ts": time.time()}
    _save_sessions(d)
    return sid


def _admin_emails() -> list:
    return [str(e).strip().lower() for e in (_conf().get("admin_emails") or []) if str(e).strip()]


# ================= COLLECTIONS (drive folders / uploads; public or private) =================
def _collections() -> list:
    c = _conf()
    cols = c.get("collections")
    if cols is None:                                     # MIGRATION: legacy single-folder config
        cols = []
        if _folder_id(c.get("drive_folder_id", "")):
            cols.append({"id": "col_legacy", "name": "Drive library", "type": "drive",
                         "folder_id": _folder_id(c["drive_folder_id"]), "visibility": "public", "allowed_emails": []})
        if c.get("videos"):
            cols.append({"id": "col_manifest", "name": "Linked videos", "type": "manifest",
                         "visibility": "public", "allowed_emails": []})
    out = list(cols)
    if c.get("videos") and not any(x.get("type") == "manifest" for x in out):
        out.append({"id": "col_manifest", "name": "Linked videos", "type": "manifest",
                    "visibility": "public", "allowed_emails": []})
    if not any(x.get("id") == "col_uploads" for x in out):
        out.append({"id": "col_uploads", "name": "Uploaded videos", "type": "uploads",
                    "visibility": "public", "allowed_emails": []})
    return out


def _can_see(col: dict, email: str, is_admin: bool) -> bool:
    if is_admin or col.get("visibility", "public") == "public":
        return True
    return email and email in [str(e).strip().lower() for e in col.get("allowed_emails", [])]


def _collection_videos(col: dict) -> list:
    """Videos for ONE collection, using the best available Drive access (oauth > key > scrape)."""
    c = _conf()
    if col.get("type") == "uploads":
        return _local_videos()
    if col.get("type") == "manifest":
        out = []
        for v in c.get("videos", []):
            fid = _drive_id(v.get("url") or v.get("id") or "")
            if fid:
                out.append({"id": fid, "title": str(v.get("title") or "Untitled video"),
                            "duration_s": v.get("duration_s"), "modified": "", "thumb": "", "access": "check"})
        return out
    fol = col.get("folder_id", "")
    if not fol:
        return []
    if _oauth_ready():
        return _list_drive_folder_oauth(fol)
    if c.get("drive_api_key"):
        return _list_drive_folder(fol, c["drive_api_key"])
    return _scrape_public_folder(fol)
VIDEO_DIR = HERE / "videos"                      # server-hosted videos: the no-Drive-drama path

# ---------------- Google OAuth (the PROPER Drive connection) ----------------
# One-time admin consent -> refresh token -> the server reads the folder with real
# authentication: private folders and Shared Drives list and STREAM without any public
# sharing. Reviewers stream through this server; they never need Drive access.
_OAUTH = {"access": None, "exp": 0.0}


def _oauth_conf() -> dict:
    return _conf().get("google_oauth") or {}


def _oauth_ready() -> bool:
    o = _oauth_conf()
    return bool(o.get("client_id") and o.get("client_secret") and o.get("refresh_token"))


def _oauth_access_token() -> str:
    if _OAUTH["access"] and time.time() < _OAUTH["exp"] - 60:
        return _OAUTH["access"]
    o = _oauth_conf()
    body = urllib.parse.urlencode({
        "client_id": o["client_id"], "client_secret": o["client_secret"],
        "refresh_token": o["refresh_token"], "grant_type": "refresh_token"}).encode()
    req = urllib.request.Request("https://oauth2.googleapis.com/token", data=body,
                                 headers={"Content-Type": "application/x-www-form-urlencoded"})
    with urllib.request.urlopen(req, timeout=15) as r:
        d = json.loads(r.read().decode())
    _OAUTH["access"] = d["access_token"]
    _OAUTH["exp"] = time.time() + float(d.get("expires_in", 3600))
    return _OAUTH["access"]


def _gapi(url: str, rng: str = ""):
    """Authenticated Google API GET (OAuth). Returns the raw response object."""
    req = urllib.request.Request(url, headers={"Authorization": "Bearer " + _oauth_access_token()})
    if rng:
        req.add_header("Range", rng)
    return urllib.request.urlopen(req, timeout=30)


def _local_videos() -> list:
    out = []
    if VIDEO_DIR.is_dir():
        for f in sorted(VIDEO_DIR.glob("*.mp4")) + sorted(VIDEO_DIR.glob("*.webm")):
            vid = "local_" + re.sub(r"[^A-Za-z0-9_-]", "_", f.stem)[:60]
            out.append({"id": vid, "title": f.stem.replace("_", " "), "duration_s": None,
                        "modified": time.strftime("%Y-%m-%d", time.localtime(f.stat().st_mtime)),
                        "thumb": "", "access": "ok", "_file": f.name})
    return out


def _local_path(vid: str):
    for v in _local_videos():
        if v["id"] == vid:
            return VIDEO_DIR / v["_file"]
    return None


def _invites() -> dict:
    try:
        return json.loads(INVITES_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _save_invites(d: dict):
    INVITES_PATH.write_text(json.dumps(d, indent=1, ensure_ascii=False), encoding="utf-8")


def _stats() -> dict:
    """Cross-video aggregation for the admin dashboard. Chips made feedback categorical,
    so verdicts / issues / changes COUNT cleanly across reviewers."""
    vids, hot, changes, reviewers = {}, {}, {}, set()
    total = 0
    if REVIEW_DIR.is_dir():
        for f in sorted(REVIEW_DIR.glob("*/*.json")):
            try:
                r = json.loads(f.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            total += 1
            vid = r.get("video_id", f.parent.name)
            v = vids.setdefault(vid, {"video_id": vid, "title": r.get("video_title") or vid,
                                      "count": 0, "sum": 0.0, "scored": 0, "verdicts": {},
                                      "off": {}, "moments": 0})
            v["count"] += 1
            if r.get("video_title"):
                v["title"] = r["video_title"]
            ov = (r.get("ratings") or {}).get("overall")
            if isinstance(ov, (int, float)):
                v["sum"] += float(ov); v["scored"] += 1
            name = ((r.get("reviewer") or {}).get("name") or "").strip().lower()
            if name:
                reviewers.add(name)
            a = r.get("answers") or {}
            if a.get("one_sentence"):
                v["verdicts"][a["one_sentence"]] = v["verdicts"].get(a["one_sentence"], 0) + 1
            for tag in [t.strip() for t in (a.get("felt_off") or "").split(",") if t.strip()]:
                v["off"][tag] = v["off"].get(tag, 0) + 1
            if a.get("one_change"):
                changes[a["one_change"]] = changes.get(a["one_change"], 0) + 1
            for mo in r.get("moments", []):
                v["moments"] += 1
                if mo.get("beat_id"):
                    k = (v["title"], mo["beat_id"])
                    h = hot.setdefault(k, {"video": v["title"], "beat_id": mo["beat_id"], "count": 0, "notes": []})
                    h["count"] += 1
                    if len(h["notes"]) < 3 and mo.get("note"):
                        h["notes"].append(mo["note"][:90])
    out_v = []
    for v in vids.values():
        v["avg"] = round(v["sum"] / v["scored"], 2) if v["scored"] else None
        v["top_off"] = sorted(v["off"].items(), key=lambda x: -x[1])[:3]
        v.pop("sum"); v.pop("scored"); v.pop("off")
        out_v.append(v)
    out_v.sort(key=lambda v: -v["count"])
    return {"totals": {"reviews": total, "videos": len(out_v), "reviewers": len(reviewers)},
            "videos": out_v,
            "hotspots": sorted(hot.values(), key=lambda h: -h["count"])[:12],
            "top_changes": sorted(changes.items(), key=lambda x: -x[1])[:8]}

_cache = {"t": 0.0, "videos": None}


def _conf() -> dict:
    try:
        return json.loads(CONF_PATH.read_text(encoding="utf-8"))
    except OSError:
        return {}
    except ValueError:
        return {"_error": "config.json is not valid JSON"}


def _drive_id(url_or_id: str) -> str:
    s = str(url_or_id or "").strip()
    if "PASTE" in s.upper() or "/drive/folders/" in s:      # template row / folder link pasted as a video
        return ""
    m = re.search(r"/file/d/([A-Za-z0-9_-]{10,})", s) or re.search(r"[?&]id=([A-Za-z0-9_-]{10,})", s)
    if m:
        return m.group(1)
    return s if re.fullmatch(r"[A-Za-z0-9_-]{10,}", s) else ""


_VIDEO_EXT = re.compile(r"\.(mp4|mov|webm|mkv|avi|m4v|mpg|mpeg|wmv)$", re.I)


def _folder_id(url_or_id: str) -> str:
    s = str(url_or_id or "").strip()
    if "PASTE" in s.upper():
        return ""
    m = re.search(r"/folders/([A-Za-z0-9_-]{10,})", s) or re.search(r"[?&]id=([A-Za-z0-9_-]{10,})", s)
    if m:
        return m.group(1)
    return s if re.fullmatch(r"[A-Za-z0-9_-]{10,}", s) else ""


# entry patterns seen in embeddedfolderview variants: double- or single-quoted hrefs,
# title div appearing within ~1200 chars of its anchor
_ENTRY_RES = (
    re.compile(r'<a href="([^"]+)"[^>]*>.{0,1200}?flip-entry-title">([^<]*)<', re.S),
    re.compile(r"<a href='([^']+)'[^>]*>.{0,1200}?flip-entry-title'>([^<]*)<", re.S),
)


def _fetch_folder_html(folder_id: str) -> str:
    url = f"https://drive.google.com/embeddedfolderview?id={urllib.parse.quote(folder_id)}#list"
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0",
                                               "Accept-Language": "en"})
    with urllib.request.urlopen(req, timeout=15) as r:
        return r.read().decode("utf-8", "replace")


def _folder_entries(html: str):
    for rx in _ENTRY_RES:
        found = rx.findall(html)
        if found:
            return found
    return []


def _looks_private(html: str) -> bool:
    h = html.lower()
    return ("servicelogin" in h or "accounts.google.com/signin" in h
            or "you need access" in h or "request access" in h)


def _scrape_public_folder(folder_id: str, depth: int = 0, seen=None) -> list:
    """NO-API-KEY listing of a PUBLIC folder via Drive's embeddedfolderview HTML.
    Finds files + recurses into subfolders (depth <= 2). Only works when the folder is
    shared 'anyone with the link' - which the player needs anyway. Thumbnails come from
    the public thumbnail endpoint; durations are unknown on this path (API key adds them)."""
    seen = seen if seen is not None else set()
    if folder_id in seen or depth > 2 or len(seen) > 30:
        return []
    seen.add(folder_id)
    html = _fetch_folder_html(folder_id)
    if _looks_private(html):
        raise PermissionError("folder is not shared publicly")
    out = []
    for href, title in _folder_entries(html):
        title = title.strip()
        fm = re.search(r"/file/d/([A-Za-z0-9_-]{10,})", href)
        dm = re.search(r"/folders/([A-Za-z0-9_-]{10,})", href)
        if fm and _VIDEO_EXT.search(title):
            fid = fm.group(1)
            out.append({"id": fid, "title": _VIDEO_EXT.sub("", title), "duration_s": None,
                        "modified": "", "thumb": f"https://drive.google.com/thumbnail?id={fid}&sz=w640",
                        "access": "ok"})
        elif dm:
            out.extend(_scrape_public_folder(dm.group(1), depth + 1, seen))
    dedup = {}
    for v in out:
        dedup.setdefault(v["id"], v)
    return sorted(dedup.values(), key=lambda v: v["title"].lower())


def _is_video(f: dict) -> bool:
    """Broad detection: real video mimeType OR a video file extension (sync tools sometimes
    upload as application/octet-stream, which the old mimeType filter silently dropped)."""
    return str(f.get("mimeType", "")).startswith("video/") or bool(_VIDEO_EXT.search(f.get("name", "")))


def _list_drive_folder_oauth(folder_id: str) -> list:
    """files.list with real auth: private folders + Shared Drives, full metadata."""
    fields = urllib.parse.quote(
        "nextPageToken,files(id,name,mimeType,modifiedTime,shortcutDetails,"
        "videoMediaMetadata(durationMillis),thumbnailLink)")
    out, seen, pages = {}, set(), 0
    queue = [(folder_id, 0)]
    while queue and pages < 40 and len(out) < 500:
        fid, dep = queue.pop(0)
        if fid in seen:
            continue
        seen.add(fid)
        q = urllib.parse.quote(f"'{fid}' in parents and trashed = false")
        token = ""
        while pages < 40:
            pages += 1
            url = (f"https://www.googleapis.com/drive/v3/files?q={q}&fields={fields}"
                   f"&pageSize=200&orderBy=name&supportsAllDrives=true&includeItemsFromAllDrives=true"
                   + (f"&pageToken={token}" if token else ""))
            with _gapi(url) as r:
                d = json.loads(r.read().decode("utf-8"))
            for f in d.get("files", []):
                mt = str(f.get("mimeType", ""))
                if mt == "application/vnd.google-apps.folder":
                    if dep < 3:
                        queue.append((f["id"], dep + 1))
                    continue
                if mt == "application/vnd.google-apps.shortcut":
                    sd = f.get("shortcutDetails") or {}
                    if sd.get("targetId") and (str(sd.get("targetMimeType", "")).startswith("video/")
                                               or _VIDEO_EXT.search(f.get("name", ""))):
                        f = {"id": sd["targetId"], "name": f.get("name", ""),
                             "mimeType": str(sd.get("targetMimeType", "")), "modifiedTime": f.get("modifiedTime", "")}
                    else:
                        continue
                if not _is_video(f):
                    continue
                ms = ((f.get("videoMediaMetadata") or {}).get("durationMillis"))
                rec = {"id": f["id"], "title": _VIDEO_EXT.sub("", f["name"]),
                       "duration_s": int(int(ms) / 1000) if ms else None,
                       "modified": f.get("modifiedTime", ""),
                       "thumb": "/api/thumb?video=" + f["id"] if f.get("thumbnailLink") else "",
                       "access": "ok"}                      # server streams with auth: always playable
                prev = out.get(f["id"])
                if prev:
                    rec = {k: (rec[k] or prev[k]) for k in rec}
                out[f["id"]] = rec
            token = d.get("nextPageToken", "")
            if not token:
                break
    return sorted(out.values(), key=lambda v: v["title"].lower())


def _list_drive_folder(folder_id: str, key: str) -> list:
    """Public-folder listing via Drive API v3 (API key only; no OAuth).

    Finds EVERYTHING a human would call "the videos in this folder":
      * walks SUBFOLDERS (breadth-first, depth <= 3) - lesson-per-folder layouts work;
      * resolves SHORTCUTS whose target is a video (folders assembled by shortcutting);
      * detects videos by mimeType OR file extension (octet-stream uploads);
      * sets supportsAllDrives/includeItemsFromAllDrives so SHARED DRIVES list fully.
    Dedupes by file id; capped at 500 videos / 40 folder pages so a mispointed id never hangs.
    """
    fields = urllib.parse.quote(
        "nextPageToken,files(id,name,mimeType,modifiedTime,shortcutDetails,"
        "videoMediaMetadata(durationMillis),thumbnailLink)")
    out, seen, pages = {}, set(), 0
    queue, depth = [(folder_id, 0)], {}
    while queue and pages < 40 and len(out) < 500:
        fid, dep = queue.pop(0)
        if fid in seen:
            continue
        seen.add(fid)
        q = urllib.parse.quote(f"'{fid}' in parents and trashed = false")
        token = ""
        while pages < 40:
            pages += 1
            url = (f"https://www.googleapis.com/drive/v3/files?q={q}&key={key}&fields={fields}"
                   f"&pageSize=200&orderBy=name&supportsAllDrives=true&includeItemsFromAllDrives=true"
                   + (f"&pageToken={token}" if token else ""))
            with urllib.request.urlopen(url, timeout=15) as r:
                d = json.loads(r.read().decode("utf-8"))
            for f in d.get("files", []):
                mt = str(f.get("mimeType", ""))
                if mt == "application/vnd.google-apps.folder":
                    if dep < 3:
                        queue.append((f["id"], dep + 1))
                    continue
                if mt == "application/vnd.google-apps.shortcut":
                    sd = f.get("shortcutDetails") or {}
                    tgt_mt = str(sd.get("targetMimeType", ""))
                    if sd.get("targetId") and (tgt_mt.startswith("video/") or _VIDEO_EXT.search(f.get("name", ""))):
                        f = {"id": sd["targetId"], "name": f.get("name", ""), "mimeType": tgt_mt,
                             "modifiedTime": f.get("modifiedTime", ""), "_via_shortcut": True}
                    else:
                        continue
                if not _is_video(f):
                    continue
                ms = ((f.get("videoMediaMetadata") or {}).get("durationMillis"))
                rec = {"id": f["id"], "title": _VIDEO_EXT.sub("", f["name"]),
                       "duration_s": int(int(ms) / 1000) if ms else None,
                       "modified": f.get("modifiedTime", ""), "thumb": f.get("thumbnailLink", ""),
                       "access": "check" if f.get("_via_shortcut") else "ok"}
                prev = out.get(f["id"])
                if prev:  # dedupe keeps the RICHEST record (a bare duplicate must not erase duration/thumb)
                    rec = {k: (rec[k] or prev[k]) for k in rec}
                out[f["id"]] = rec
            token = d.get("nextPageToken", "")
            if not token:
                break
    return sorted(out.values(), key=lambda v: v["title"].lower())


def _diag_folder(folder_url: str) -> dict:
    """Plain-words diagnosis of a folder link for the setup card."""
    fid = _folder_id(folder_url)
    if not fid:
        return {"verdict": "That is not a Drive folder link. It should contain /folders/<id>.",
                "ok": False}
    try:
        html = _fetch_folder_html(fid)
    except Exception as e:  # noqa: BLE001
        return {"verdict": f"Could not reach Drive from this machine ({type(e).__name__}). "
                           "Check the network / proxy and try again.", "ok": False, "id": fid}
    if _looks_private(html):
        return {"verdict": "Drive asked for a sign-in: the folder is NOT shared publicly. "
                           "In Drive: right-click the folder > Share > General access > "
                           "'Anyone with the link' (Viewer). Then scan again.", "ok": False, "id": fid}
    entries = _folder_entries(html)
    vids = [t for _, t in entries if _VIDEO_EXT.search(t.strip())]
    folders = [t for h, t in entries if "/folders/" in h]
    if not entries:
        snippet = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", html))[:220]
        return {"verdict": "The folder opened but appears EMPTY to an anonymous visitor "
                           f"(page {len(html)} bytes, 0 entries). Google served: \"{snippet}...\" "
                           "If files are inside: this can be a Shared Drive (anonymous listing "
                           "unsupported - use an API key or upload directly), or the files do not "
                           "inherit sharing. Tip: the admin can UPLOAD videos straight to this "
                           "server and skip Drive entirely.", "ok": False, "id": fid}
    return {"verdict": f"Folder is public: {len(entries)} item(s) visible - {len(vids)} video(s), "
                       f"{len(folders)} subfolder(s). First items: "
                       + ", ".join(t.strip() for _, t in entries[:3]), "ok": True, "id": fid,
            "videos": len(vids), "subfolders": len(folders)}


def _stream_upstream(vid: str, key: str, rng: str):
    """Upstream video stream for the native player.
    WITH an API key: googleapis alt=media (rich + reliable).
    WITHOUT a key (public files): drive.usercontent download - Drive sometimes answers with a
    'cannot scan for viruses' HTML interstitial whose hidden form fields we replay (the classic
    gdown flow). Range headers pass through on both paths so seeking works."""
    ua = {"User-Agent": "Mozilla/5.0", "Accept": "*/*"}
    if _oauth_ready():
        url = (f"https://www.googleapis.com/drive/v3/files/{urllib.parse.quote(vid)}"
               f"?alt=media&supportsAllDrives=true")
        return _gapi(url, rng)
    if key:
        url = (f"https://www.googleapis.com/drive/v3/files/{urllib.parse.quote(vid)}"
               f"?alt=media&key={urllib.parse.quote(key)}&supportsAllDrives=true")
        req = urllib.request.Request(url, headers=ua)
        if rng:
            req.add_header("Range", rng)
        return urllib.request.urlopen(req, timeout=30)
    import http.cookiejar
    op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
    url = f"https://drive.usercontent.google.com/download?id={urllib.parse.quote(vid)}&export=download&confirm=t"
    req = urllib.request.Request(url, headers=dict(ua, **({"Range": rng} if rng else {})))
    r = op.open(req, timeout=30)
    if "text/html" not in str(r.headers.get("Content-Type", "")):
        return r
    html = r.read(300000).decode("utf-8", "replace")
    r.close()
    fields = dict(re.findall(r'name="([^"]+)"\s+value="([^"]*)"', html))
    if not fields:
        raise urllib.error.HTTPError(url, 409, "drive interstitial unparsable (private or quota-limited file?)", {}, None)
    fields.setdefault("id", vid); fields.setdefault("export", "download"); fields.setdefault("confirm", "t")
    url2 = "https://drive.usercontent.google.com/download?" + urllib.parse.urlencode(fields)
    req2 = urllib.request.Request(url2, headers=dict(ua, **({"Range": rng} if rng else {})))
    r2 = op.open(req2, timeout=30)
    if "text/html" in str(r2.headers.get("Content-Type", "")):
        r2.close()
        raise urllib.error.HTTPError(url2, 409, "drive keeps answering html - file not publicly streamable", {}, None)
    return r2


def _probe_access(file_id: str, key: str) -> str:
    """'ok' when an ANONYMOUS request can see the file (public: player will work),
    'restricted' when Drive answers 404/403 (private: the player shows 'does not exist')."""
    try:
        url = f"https://www.googleapis.com/drive/v3/files/{urllib.parse.quote(file_id)}?fields=id&key={key}&supportsAllDrives=true"
        with urllib.request.urlopen(url, timeout=8):
            return "ok"
    except urllib.error.HTTPError as e:
        return "restricted" if e.code in (403, 404) else "unknown"
    except Exception:  # noqa: BLE001 - offline etc.: do not scare the user
        return "unknown"


def _videos(force: bool = False, email: str = "", is_admin: bool = True) -> dict:
    """ALL collections' videos (cached 120s), then filtered per user. Access enforcement for
    stream/slide/review reuses the same map via _user_can_watch()."""
    if force or _cache["videos"] is None or time.time() - _cache["t"] >= 120:
        c = _conf()
        allv, errs, modes = {}, [], []
        for col in _collections():
            try:
                cv = _collection_videos(col)
            except PermissionError:
                errs.append(f"{col.get('name', col.get('id'))}: folder not shared publicly (connect Google or share it)")
                cv = []
            except Exception as e:  # noqa: BLE001
                errs.append(f"{col.get('name', col.get('id'))}: listing failed ({type(e).__name__})")
                cv = []
            if cv:
                modes.append(f"{col.get('name', col.get('id'))}: {len(cv)}")
            for v in cv:
                v = dict(v)
                v.pop("_file", None)
                v.setdefault("access", "unknown")
                v["collection"] = col.get("id")
                v["collection_name"] = col.get("name", "")
                allv.setdefault(v["id"], v)
        src = ("oauth" if _oauth_ready() else "api-key" if c.get("drive_api_key") else "public-scan")
        for v in allv.values():
            v["reviews"] = _review_stats(v["id"])
            v["stream"] = v.get("access") != "restricted"
        _cache.update(t=time.time(), videos={
            "videos": list(allv.values()), "mode": f"{len(allv)} video(s) via {src} - " + ("; ".join(modes) or "no sources yet"),
            "error": "; ".join(errs)})
    base = _cache["videos"]
    cols = {c["id"]: c for c in _collections()}
    vis = [v for v in base["videos"]
           if _can_see(cols.get(v.get("collection"), {"visibility": "public"}), email, is_admin)]
    return {"videos": vis, "mode": base["mode"], "error": base["error"]}


def _user_can_watch(video_id: str, email: str, is_admin: bool) -> bool:
    return any(v["id"] == video_id for v in _videos(False, email, is_admin)["videos"])


# ---------------- slide bundles: timestamp -> beat -> SVG ----------------
# A "bundle" is either a render output dir (timeline.json + l4_manifest.json + svgs/)
# or a portable single-file sidecar <name>.review.json (spans + inline svgs) made by
# review/export_sidecar.py - droppable into review/bundles/ or downloaded from Drive.
_BUNDLE_CACHE = {"t": 0.0, "idx": None}


def _bundle_dirs() -> list:
    """Standalone platform: relative dirs resolve against THIS folder; absolute paths welcome
    (point one at the render repo's render_out to index lesson bundles without pushing)."""
    c = _conf()
    dirs = c.get("bundle_dirs") or ["bundles"]
    return [Path(d) if os.path.isabs(str(d)) else HERE / d for d in dirs]


def _norm_title(t: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", str(t).lower())


def _bundle_index(force: bool = False) -> dict:
    if not force and _BUNDLE_CACHE["idx"] is not None and time.time() - _BUNDLE_CACHE["t"] < 120:
        return _BUNDLE_CACHE["idx"]
    idx = {}
    for base in _bundle_dirs():
        if not base.is_dir():
            continue
        for p in sorted(base.iterdir()):
            try:
                if p.is_dir() and (p / "timeline.json").is_file() and (p / "l4_manifest.json").is_file()                         and (p / "svgs").is_dir():
                    idx[p.name] = {"key": p.name, "kind": "dir", "path": str(p), "title": p.name}
                elif p.name.endswith(".review.json") and p.is_file():
                    key = p.name[:-len(".review.json")]
                    idx.setdefault(key, {"key": key, "kind": "sidecar", "path": str(p), "title": key})
            except OSError:
                continue
    _BUNDLE_CACHE.update(t=time.time(), idx=idx)
    return idx


def _load_bundle(key: str):
    """-> {title, spans:[{i,beat_id,start,end}], svg(beat_id)->str} or None."""
    b = _bundle_index().get(key)
    if not b:
        return None
    try:
        if b["kind"] == "sidecar":
            d = json.loads(Path(b["path"]).read_text(encoding="utf-8"))
            svgs = d.get("svgs", {})
            return {"title": d.get("title", key), "spans": d.get("spans", []),
                    "svg": lambda bid: svgs.get(bid)}
        p = Path(b["path"])
        tl = json.loads((p / "timeline.json").read_text(encoding="utf-8"))
        man = json.loads((p / "l4_manifest.json").read_text(encoding="utf-8"))
        ids = [bt.get("beat_id") or bt.get("id") or f"beat_{i}" for i, bt in enumerate(man.get("beats", []))]
        agg = {}
        for c in tl.get("cues", []):
            bi = int(c.get("beat", 0))
            a = agg.setdefault(bi, [1e18, 0.0])
            a[0] = min(a[0], float(c.get("visibleAtS", c.get("audioStartS", 0)) or 0))
            a[1] = max(a[1], float(c.get("audioEndS", 0) or 0))
        spans = []
        for bi in sorted(agg):
            spans.append({"i": bi, "beat_id": ids[bi] if bi < len(ids) else f"beat_{bi}",
                          "start": round(agg[bi][0], 3), "end": round(agg[bi][1], 3)})
        for j in range(len(spans) - 1):        # a beat owns the screen until the next beat appears
            spans[j]["end"] = max(spans[j]["end"], spans[j + 1]["start"])

        def _svg(bid, _p=p):
            f = _p / "svgs" / (re.sub(r"[^A-Za-z0-9_.-]", "_", bid) + ".svg")
            return f.read_text(encoding="utf-8") if f.is_file() else None
        return {"title": key, "spans": spans, "svg": _svg}
    except (OSError, ValueError, KeyError):
        return None


def _bundle_for_video(video_id: str, title: str = ""):
    """config link map first, then normalized-title match (BusinessEthics_Chapter7 ~ 'Business Ethics Chapter 7')."""
    c = _conf()
    key = (c.get("video_bundles") or {}).get(video_id)
    if key:
        return key if key in _bundle_index() else None
    nt = _norm_title(title)
    if not nt:
        return None
    for k, b in _bundle_index().items():
        nk = _norm_title(k)
        if nk and (nk in nt or nt in nk):
            return k
    return None


def _slide_at(key: str, t: float):
    b = _load_bundle(key)
    if not b or not b["spans"]:
        return None
    spans = b["spans"]
    hit = None
    for sp in spans:
        if sp["start"] <= t < sp["end"]:
            hit = sp
            break
    if hit is None:                             # clamp: before first -> first, after last -> last
        hit = spans[0] if t < spans[0]["start"] else spans[-1]
    return {"found": True, "bundle": key, "beat_id": hit["beat_id"], "index": hit["i"] + 1,
            "total": len(spans), "start": hit["start"], "end": hit["end"],
            "svg": b["svg"](hit["beat_id"])}


def _review_stats(video_id: str) -> dict:
    d = REVIEW_DIR / re.sub(r"[^A-Za-z0-9_-]", "_", video_id)
    if not d.is_dir():
        return {"count": 0, "avg": None}
    scores, n = [], 0
    for f in sorted(d.glob("*.json")):
        try:
            r = json.loads(f.read_text(encoding="utf-8"))
            n += 1
            if isinstance(r.get("ratings", {}).get("overall"), (int, float)):
                scores.append(float(r["ratings"]["overall"]))
        except (OSError, ValueError):
            continue
    return {"count": n, "avg": round(sum(scores) / len(scores), 2) if scores else None}


def _parse_ts(t) -> float:
    p = [x for x in str(t or "").strip().split(":") if x != ""]
    try:
        p = [int(x) for x in p]
    except ValueError:
        return -1.0
    if not p:
        return -1.0
    return float(p[0] * 3600 + p[1] * 60 + p[2] if len(p) == 3 else p[0] * 60 + p[1] if len(p) == 2 else p[0])


def _enrich_moments(payload: dict, vid: str) -> list:
    """Attach the SLIDE identity (beat_id + index) to every timestamped moment, so feedback
    aggregates per slide / per blueprint downstream. Server-side: robust even if the UI changes."""
    moments = [m for m in (payload.get("moments") or []) if str(m.get("note", "")).strip()][:20]
    key = _bundle_for_video(vid, str(payload.get("video_title", "")))
    for m in moments:
        t = _parse_ts(m.get("at"))
        if key and t >= 0:
            hit = _slide_at(key, t)
            if hit:
                m["beat_id"] = hit["beat_id"]
                m["slide_index"] = hit["index"]
    return moments


def _save_review(payload: dict) -> dict:
    vid = _drive_id(str(payload.get("video_id", "")))
    if not vid:
        return {"ok": False, "error": "missing video_id"}
    ratings = payload.get("ratings") or {}
    try:
        overall = float(ratings.get("overall"))
        assert 1 <= overall <= 5
    except (TypeError, ValueError, AssertionError):
        return {"ok": False, "error": "overall rating (1-5) is required"}
    answers = payload.get("answers") or {}
    if not any(str(v).strip() for v in answers.values()):
        return {"ok": False, "error": "answer at least one written question - that is the point"}
    rec = {
        "video_id": vid,
        "video_title": str(payload.get("video_title", ""))[:300],
        "reviewer": {k: str((payload.get("reviewer") or {}).get(k, ""))[:200] for k in ("name", "role", "email")},
        "ratings": {k: ratings.get(k) for k in ("overall", "clarity", "visuals", "narration", "pacing", "animations", "audio") if ratings.get(k) is not None},
        "signals": {k: payload.get("signals", {}).get(k) for k in ("watch_again", "recommend", "watched_full") if (payload.get("signals") or {}).get(k) is not None},
        "moments": _enrich_moments(payload, vid),
        "answers": {k: str(v)[:4000] for k, v in answers.items() if str(v).strip()},
        "submitted_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
    }
    d = REVIEW_DIR / re.sub(r"[^A-Za-z0-9_-]", "_", vid)
    d.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%d_%H%M%S")
    who = re.sub(r"[^A-Za-z0-9]+", "_", rec["reviewer"]["name"] or "anon")[:40] or "anon"
    (d / f"{stamp}_{who}.json").write_text(json.dumps(rec, indent=1, ensure_ascii=False), encoding="utf-8")
    _cache["videos"] = None                     # stats changed
    return {"ok": True, "saved": f"{d.name}/{stamp}_{who}.json"}


def _esc(t) -> str:
    return (str(t).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))


def _build_report(video_id: str, title: str = "") -> str:
    """Self-contained HTML feedback report for ONE video: ratings summary, every review,
    moments GROUPED BY SLIDE with the slide SVG embedded inline, plus a machine-readable
    JSON block so an analyst (human or AI) can parse it exactly."""
    vid = _drive_id(video_id)
    reviews = _reviews_for(vid)
    key = _bundle_for_video(vid, title)
    bundle = _load_bundle(key) if key else None
    dims = ["overall", "clarity", "visuals", "narration", "pacing", "animations", "audio"]
    avg = {}
    for d in dims:
        xs = [float(r["ratings"][d]) for r in reviews if isinstance(r.get("ratings", {}).get(d), (int, float))]
        avg[d] = round(sum(xs) / len(xs), 2) if xs else None
    by_slide = {}
    for r in reviews:
        who = (r.get("reviewer") or {}).get("name") or "anonymous"
        for mo in r.get("moments", []):
            bid = mo.get("beat_id") or "_unmapped"
            by_slide.setdefault(bid, []).append({"who": who, "at": mo.get("at", ""),
                                                 "note": mo.get("note", ""), "idx": mo.get("slide_index")})
    H = []
    H.append("<!doctype html><html><head><meta charset='utf-8'><title>Feedback report - " + _esc(title or vid) + "</title><style>")
    H.append("body{font:15px/1.6 Segoe UI,system-ui,sans-serif;color:#1c2330;max-width:960px;margin:0 auto;padding:40px 28px;background:#fafbfd}")
    H.append("h1{font-size:26px;margin:0 0 4px}.sub{color:#69707e;margin:0 0 26px}")
    H.append("h2{font-size:18px;margin:34px 0 12px;border-bottom:2px solid #e6e9f0;padding-bottom:6px}")
    H.append("table{border-collapse:collapse;width:100%;font-size:14px}td,th{border:1px solid #e2e6ee;padding:7px 12px;text-align:left}th{background:#f0f2f8}")
    H.append(".slide{background:#fff;border:1px solid #e2e6ee;border-radius:12px;margin:16px 0;overflow:hidden}")
    H.append(".slide .img{background:#0e0f13;padding:0}.slide .img svg{display:block;width:100%;height:auto}")
    H.append(".slide .cap{padding:10px 16px;font-weight:700;font-size:14px;background:#f6f7fb;border-bottom:1px solid #e2e6ee}")
    H.append(".mo{padding:10px 16px;border-top:1px solid #eef0f5;font-size:14px}.mo b{color:#b02a30}.who{color:#69707e;font-size:12.5px}")
    H.append(".ans{background:#fff;border:1px solid #e2e6ee;border-radius:12px;padding:14px 18px;margin:12px 0;font-size:14px}")
    H.append(".q{color:#69707e;font-size:12px;font-weight:700;text-transform:uppercase;letter-spacing:.6px;margin-top:10px}")
    H.append("</style></head><body>")
    H.append("<h1>Feedback report: " + _esc(title or vid) + "</h1>")
    H.append("<p class='sub'>" + str(len(reviews)) + " review(s) &middot; generated " + time.strftime("%Y-%m-%d %H:%M")
             + (" &middot; slides from bundle <b>" + _esc(key) + "</b>" if key else " &middot; no slide bundle linked") + "</p>")
    H.append("<h2>Scores</h2><table><tr>" + "".join(f"<th>{d}</th>" for d in dims) + "</tr><tr>"
             + "".join("<td>" + (str(avg[d]) if avg[d] is not None else "-") + "</td>" for d in dims) + "</tr></table>")
    H.append("<h2>Moments, slide by slide</h2>")
    if not by_slide:
        H.append("<p>No timestamped moments were flagged.</p>")
    order = sorted(by_slide.items(), key=lambda kv: (kv[1][0]["idx"] or 9999) if kv[1] else 9999)
    for bid, moments in order:
        H.append("<div class='slide'>")
        svg = bundle["svg"](bid) if (bundle and bid != "_unmapped") else None
        cap = ("Slide " + str(moments[0].get("idx")) + " &middot; " + _esc(bid)) if bid != "_unmapped" else "Moments without a mapped slide"
        H.append("<div class='cap'>" + cap + "</div>")
        if svg:
            H.append("<div class='img'>" + svg + "</div>")
        for mo in moments:
            H.append("<div class='mo'><b>" + _esc(mo["at"] or "?") + "</b> &middot; <span class='who'>" + _esc(mo["who"])
                     + "</span><br>" + _esc(mo["note"]) + "</div>")
        H.append("</div>")
    H.append("<h2>In their own words</h2>")
    QL = {"first_takeaway": "What stayed with you?", "one_sentence": "In one sentence",
          "felt_off": "What felt off?", "confusion": "Where did you get lost?",
          "one_change": "The ONE change", "anything_else": "Anything else"}
    for r in reviews:
        who = (r.get("reviewer") or {}).get("name") or "anonymous"
        role = (r.get("reviewer") or {}).get("role") or ""
        stars = int(round(float((r.get("ratings") or {}).get("overall") or 0)))
        H.append("<div class='ans'><b>" + _esc(who) + (" (" + _esc(role) + ")" if role else "") + "</b> &middot; "
                 + ("&#9733;" * stars) + " &middot; <span class='who'>" + _esc(r.get("submitted_at", "")) + "</span>")
        for k, q in QL.items():
            v = (r.get("answers") or {}).get(k)
            if v:
                H.append("<div class='q'>" + q + "</div><div>" + _esc(v) + "</div>")
        H.append("</div>")
    machine = {"video_id": vid, "title": title, "avg_ratings": avg, "reviews": reviews,
               "slide_bundle": key, "generated": time.strftime("%Y-%m-%dT%H:%M:%S")}
    H.append("<script type='application/json' id='redtee-report-data'>"
             + json.dumps(machine, ensure_ascii=False).replace("</", "<\/") + "</script>")
    H.append("</body></html>")
    return "".join(H)


def _export_csv() -> str:
    import csv, io as _io
    cols = ["submitted_at", "video_id", "video_title", "reviewer_name", "reviewer_role", "reviewer_email",
            "overall", "clarity", "visuals", "narration", "pacing", "animations", "audio",
            "watch_again", "recommend", "watched_full", "moments", "first_takeaway", "one_sentence",
            "felt_off", "one_change", "confusion", "anything_else"]
    buf = _io.StringIO()
    w = csv.writer(buf)
    w.writerow(cols)
    if REVIEW_DIR.is_dir():
        for f in sorted(REVIEW_DIR.glob("*/*.json")):
            try:
                r = json.loads(f.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            rt, sg, an = r.get("ratings", {}), r.get("signals", {}), r.get("answers", {})
            w.writerow([r.get("submitted_at", ""), r.get("video_id", ""), r.get("video_title", ""),
                        r.get("reviewer", {}).get("name", ""), r.get("reviewer", {}).get("role", ""),
                        r.get("reviewer", {}).get("email", ""),
                        rt.get("overall", ""), rt.get("clarity", ""), rt.get("visuals", ""),
                        rt.get("narration", ""), rt.get("pacing", ""), rt.get("animations", ""), rt.get("audio", ""),
                        sg.get("watch_again", ""), sg.get("recommend", ""), sg.get("watched_full", ""),
                        " | ".join(f"{m.get('at','?')}" + (f" [{m['beat_id']}]" if m.get("beat_id") else "")
                                   + f": {m.get('note','')}" for m in r.get("moments", [])),
                        an.get("first_takeaway", ""), an.get("one_sentence", ""), an.get("felt_off", ""),
                        an.get("one_change", ""), an.get("confusion", ""), an.get("anything_else", "")])
    return buf.getvalue()


def _reviews_for(video_id: str) -> list:
    d = REVIEW_DIR / re.sub(r"[^A-Za-z0-9_-]", "_", _drive_id(video_id))
    out = []
    if d.is_dir():
        for f in sorted(d.glob("*.json"), reverse=True):
            try:
                r = json.loads(f.read_text(encoding="utf-8"))
                r.pop("reviewer", None) if os.environ.get("REDTEE_REVIEW_PUBLIC") else None
                out.append(r)
            except (OSError, ValueError):
                continue
    return out[:50]


LANDING_TEMPLATE = """<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>RedTee Screening Room</title>
<script>(function(){var t;try{t=localStorage.getItem('rt_theme')}catch(e){}
if(!t)t=window.matchMedia&&matchMedia('(prefers-color-scheme: light)').matches?'light':'dark';
document.documentElement.setAttribute('data-theme',t)})()</script><style>
:root{--bg:#07080b;--ink:#f4f4f7;--muted:#8b8f9a;--faint:#5d616b;--red:#e5484d;--red-hi:#ff7d81;--gold:#f5c96b;
  --hair:#ffffff14;--s1:#12131a;--s2:#181923;--spring:cubic-bezier(.34,1.56,.64,1);--ease:cubic-bezier(.22,.61,.36,1);
  --nav-bg:rgba(7,8,11,.68);--nav-bg2:rgba(7,8,11,.86);--overlay:rgba(4,5,7,.72);
  --orbA:rgba(90,20,40,.45);--orbB:rgba(40,18,60,.4);--graind:#ffffff08;
  --gbtn-bg:#fff;--gbtn-ink:#181c24;--gbtn-bd:transparent;
  --filmA:#0e0f14;--filmB:#171823;--filmH:#ffffff10;--stroke-n:#ffffff2a;
  --band-bg:linear-gradient(135deg,#1c0f14,#12080f);--band-bd:#3a1c22;
  --card-sh:0 34px 80px rgba(0,0,0,.6);color-scheme:dark}
[data-theme="light"]{--bg:#f6f6f8;--ink:#1b1e28;--muted:#5d6370;--faint:#9aa0ac;--red:#d63a40;--red-hi:#c92e35;--gold:#a67c1b;
  --hair:#00000012;--s1:#ffffff;--s2:#f0f1f5;
  --nav-bg:rgba(248,248,250,.7);--nav-bg2:rgba(248,248,250,.9);--overlay:rgba(232,233,238,.7);
  --orbA:rgba(229,72,77,.14);--orbB:rgba(120,80,200,.10);--graind:#00000006;
  --gbtn-bg:#1b1e28;--gbtn-ink:#fff;--gbtn-bd:transparent;
  --filmA:#e7e8ee;--filmB:#d9dbe4;--filmH:#00000014;--stroke-n:#00000022;
  --band-bg:linear-gradient(135deg,#fdf0f0,#faf3f6);--band-bd:#f0d4d6;
  --card-sh:0 30px 70px rgba(30,34,50,.16);color-scheme:light}
body{transition:background-color .3s,color .3s}
*{box-sizing:border-box}::selection{background:rgba(229,72,77,.28)}
html{scroll-behavior:smooth}
body{margin:0;background:var(--bg);color:var(--ink);font:16px/1.65 Inter,"Segoe UI",system-ui,sans-serif;
  -webkit-font-smoothing:antialiased;min-height:100vh;overflow-x:hidden}
@keyframes rise{from{opacity:0;transform:translateY(24px)}to{opacity:1;transform:none}}
@keyframes drift1{0%,100%{transform:translate(0,0) scale(1)}50%{transform:translate(60px,40px) scale(1.12)}}
@keyframes drift2{0%,100%{transform:translate(0,0) scale(1.1)}50%{transform:translate(-50px,-30px) scale(1)}}
@keyframes bob{0%,100%{transform:rotate(-2deg) translateY(0)}50%{transform:rotate(-2deg) translateY(-12px)}}
@keyframes bob2{0%,100%{transform:rotate(4deg) translateY(0)}50%{transform:rotate(4deg) translateY(-8px)}}
@keyframes filmscroll{from{background-position-x:0}to{background-position-x:-260px}}
@keyframes beam{0%,100%{opacity:.35}50%{opacity:.7}}
@keyframes twinkle{0%,100%{opacity:.25}50%{opacity:.8}}
.icn{vertical-align:-3px}
.orb{position:fixed;border-radius:50%;filter:blur(90px);z-index:0;pointer-events:none}
.orb.a{width:520px;height:520px;background:var(--orbA);top:-160px;right:-120px;animation:drift1 16s ease-in-out infinite}
.orb.b{width:460px;height:460px;background:var(--orbB);bottom:-180px;left:-140px;animation:drift2 19s ease-in-out infinite}
.grain{position:fixed;inset:0;z-index:0;pointer-events:none;opacity:.5;
  background-image:radial-gradient(var(--graind) 1px,transparent 1px);background-size:3px 3px}
.wrap{position:relative;z-index:1;max-width:1120px;margin:0 auto;padding:0 32px}
.topbar{position:sticky;top:0;z-index:6;width:100%;background:var(--nav-bg);
  backdrop-filter:blur(16px);-webkit-backdrop-filter:blur(16px);border-bottom:1px solid transparent;
  transition:border-color .3s,background .3s;animation:rise .55s var(--ease) both}
.topbar.scrolled{border-bottom-color:var(--hair);background:var(--nav-bg2)}
.navin{display:flex;align-items:center;gap:14px;height:66px;padding:0 26px;max-width:1560px;margin:0 auto}
.logo{width:38px;height:38px;border-radius:11px;background:linear-gradient(135deg,#e5484d,#b52d33);display:grid;place-items:center;font-weight:800;color:#fff;font-size:16px;box-shadow:0 6px 26px rgba(229,72,77,.4);transition:transform .3s var(--spring)}
.logo:hover{transform:rotate(-7deg) scale(1.08)}
.brandname b{font-size:15.5px;letter-spacing:.2px}
.brandname .tag{color:var(--muted);font-size:10.5px;letter-spacing:2.4px;text-transform:uppercase;margin-left:7px}
.navlinks{display:flex;gap:4px;margin-left:26px}
@media(max-width:760px){.navlinks{display:none}}
.navlinks a{color:var(--muted);font-size:13.5px;font-weight:600;text-decoration:none;padding:8px 14px;border-radius:9px;transition:all .2s}
.navlinks a:hover{color:var(--ink);background:#ffffff0a}
.navin .sp{flex:1}
.adminlink{color:var(--muted);font-size:13px;font-weight:650;text-decoration:none;border:1px solid var(--hair);
  border-radius:10px;padding:8px 16px;transition:all .22s var(--ease);cursor:pointer;background:none}
.adminlink:hover{color:var(--ink);border-color:#ffffff30;transform:translateY(-1px)}
.navcta{background:linear-gradient(135deg,var(--red),#b52d33);color:#fff;border:none;border-radius:10px;
  padding:9px 18px;font-size:13px;font-weight:700;cursor:pointer;box-shadow:0 4px 16px rgba(229,72,77,.3);
  transition:transform .2s var(--spring),box-shadow .25s}
.navcta:hover{transform:translateY(-1px);box-shadow:0 8px 24px rgba(229,72,77,.42)}
/* ---- hero ---- */
.hero{display:grid;grid-template-columns:1.1fr .9fr;gap:40px;align-items:center;padding:8vh 0 6vh}
@media(max-width:900px){.hero{grid-template-columns:1fr}.stage3d{display:none}}
.kick{display:inline-flex;align-items:center;gap:8px;border:1px solid var(--hair);background:var(--s1);border-radius:20px;
  padding:7px 16px;font-size:11.5px;letter-spacing:1.8px;text-transform:uppercase;color:var(--gold);animation:rise .6s .08s var(--ease) both}
.kick .dot{width:7px;height:7px;border-radius:50%;background:var(--gold);animation:twinkle 2.4s ease-in-out infinite}
.hero h1{font-size:clamp(36px,5.4vw,60px);line-height:1.06;letter-spacing:-1.8px;font-weight:800;margin:24px 0 18px;animation:rise .6s .16s var(--ease) both}
.hero h1 em{font-style:normal;background:linear-gradient(100deg,var(--red-hi),var(--gold));-webkit-background-clip:text;background-clip:text;color:transparent}
.hero p{color:var(--muted);font-size:16.5px;max-width:480px;margin:0 0 34px;animation:rise .6s .24s var(--ease) both}
.cta{display:flex;gap:13px;flex-wrap:wrap;animation:rise .6s .32s var(--ease) both}
.gbtn{display:inline-flex;align-items:center;gap:12px;background:var(--gbtn-bg);color:var(--gbtn-ink);border:1px solid var(--gbtn-bd);border-radius:13px;
  padding:14px 26px;font-size:15px;font-weight:750;cursor:pointer;text-decoration:none;
  transition:transform .22s var(--spring),box-shadow .25s;box-shadow:0 12px 44px rgba(0,0,0,.45)}
.gbtn:hover{transform:translateY(-2px) scale(1.02);box-shadow:0 18px 56px rgba(0,0,0,.6)}
.gbtn svg{width:19px;height:19px}
.codebtn{background:var(--s1);border:1px solid var(--hair);color:var(--ink);border-radius:13px;padding:14px 22px;
  font-size:14px;font-weight:650;cursor:pointer;transition:all .22s var(--ease)}
.codebtn:hover{border-color:#ffffff30;transform:translateY(-1px)}
.trust{display:flex;gap:22px;margin-top:30px;color:var(--faint);font-size:12.5px;animation:rise .6s .4s var(--ease) both;flex-wrap:wrap}
.trust span{display:inline-flex;gap:7px;align-items:center}
/* ---- hero visual: floating screening composition ---- */
.stage3d{position:relative;height:420px;animation:rise .7s .3s var(--ease) both}
.beam{position:absolute;left:-8%;top:6%;width:120%;height:70%;pointer-events:none;
  background:conic-gradient(from 98deg at 0% 18%,transparent 0deg,rgba(245,201,107,.09) 7deg,rgba(229,72,77,.07) 15deg,transparent 24deg);
  animation:beam 5s ease-in-out infinite}
.mock{position:absolute;background:linear-gradient(160deg,var(--s2),var(--s1));border:1px solid var(--hair);border-radius:18px;
  box-shadow:var(--card-sh)}
.mock.player{right:6%;top:4%;width:78%;aspect-ratio:16/9;overflow:hidden;animation:bob 7s ease-in-out infinite}
.mock.player .slide{position:absolute;inset:0;background:linear-gradient(145deg,#181a24,#0d0e14)}
.mock.player .slide .ttl{position:absolute;left:9%;top:14%;width:44%;height:11px;border-radius:6px;background:#ffffff2e}
.mock.player .slide .ttl.b{top:26%;width:30%;background:#ffffff18}
.mock.player .slide .ring{position:absolute;right:12%;top:20%;width:88px;height:88px;border-radius:50%;
  border:9px solid #2a2d3a;border-top-color:var(--red);border-right-color:var(--gold);transform:rotate(-30deg)}
.mock.player .slide .bar{position:absolute;left:9%;bottom:26%;height:12px;border-radius:6px;background:linear-gradient(90deg,var(--red),var(--gold))}
.mock.player .slide .bar.a{width:52%}
.mock.player .slide .bar.b{bottom:18%;width:34%;opacity:.5}
.mock.player .ctrl{position:absolute;left:0;right:0;bottom:0;height:38px;background:rgba(6,7,10,.8);backdrop-filter:blur(4px);
  display:flex;align-items:center;gap:10px;padding:0 14px}
.mock.player .ctrl .pl{width:0;height:0;border-left:11px solid #fff;border-top:7px solid transparent;border-bottom:7px solid transparent}
.mock.player .ctrl .tr{flex:1;height:4px;border-radius:2px;background:#ffffff22;position:relative}
.mock.player .ctrl .tr::after{content:"";position:absolute;left:0;top:0;bottom:0;width:38%;border-radius:2px;background:var(--red)}
.mock.player .ctrl .tm{color:#cfd2da;font-size:10.5px;font-weight:650}
.mock.review{left:0;bottom:2%;width:60%;padding:16px 18px;animation:bob2 8s ease-in-out infinite}
.mock.review .st{color:var(--gold);letter-spacing:3px;font-size:15px;margin-bottom:9px}
.mock.review .chiprow{display:flex;gap:6px;flex-wrap:wrap}
.mock.review .chip{border:1px solid var(--hair);border-radius:14px;padding:4px 11px;font-size:11px;color:var(--muted)}
.mock.review .chip.on{background:linear-gradient(135deg,var(--red),#b52d33);border-color:transparent;color:#fff}
.mock.review .stamp{margin-top:11px;font-size:11px;color:var(--faint)}
.mock.review .stamp b{color:var(--gold)}
/* ---- film strip divider ---- */
.film{height:56px;margin:20px 0 0;border-top:1px solid var(--hair);border-bottom:1px solid var(--hair);opacity:.85;
  background:
    repeating-linear-gradient(90deg,transparent 0 10px,var(--filmH) 10px 18px,transparent 18px 26px),
    repeating-linear-gradient(90deg,var(--filmA) 0 122px,var(--filmB) 122px 252px,var(--filmA) 252px 260px);
  background-size:260px 12px,260px 100%;background-position:0 6px,0 0;background-repeat:repeat-x;
  animation:filmscroll 9s linear infinite}
/* ---- sections ---- */
.sec{padding:9vh 0 0}
.sec .h{font-size:11.5px;letter-spacing:2.4px;text-transform:uppercase;color:var(--gold);margin-bottom:12px}
.sec h2{font-size:clamp(24px,3.4vw,36px);letter-spacing:-.8px;margin:0 0 34px;font-weight:800}
.feats{display:grid;grid-template-columns:repeat(3,1fr);gap:16px}
@media(max-width:760px){.feats{grid-template-columns:1fr}}
.feat{background:var(--s1);border:1px solid var(--hair);border-radius:20px;padding:26px 28px;position:relative;overflow:hidden;
  transition:transform .28s var(--spring),border-color .25s}
.feat:hover{transform:translateY(-4px);border-color:#ffffff26}
.feat::after{content:"";position:absolute;inset:auto 0 0 0;height:2px;background:linear-gradient(90deg,transparent,var(--red),var(--gold),transparent);opacity:0;transition:opacity .3s}
.feat:hover::after{opacity:1}
.feat .ic{color:var(--red-hi);margin-bottom:12px}
.feat b{display:block;font-size:15.5px;margin-bottom:6px}
.feat span{color:var(--muted);font-size:13.5px;line-height:1.65}
.steps{display:grid;grid-template-columns:repeat(3,1fr);gap:16px;counter-reset:st}
@media(max-width:760px){.steps{grid-template-columns:1fr}}
.step{position:relative;padding:26px 26px 26px 26px;border:1px dashed var(--hair);border-radius:20px}
.step .n{font-size:44px;font-weight:800;color:transparent;-webkit-text-stroke:1.5px var(--stroke-n);line-height:1;margin-bottom:12px}
.step b{display:block;font-size:15px;margin-bottom:6px}
.step span{color:var(--muted);font-size:13.5px}
.band{margin:10vh 0 0;background:var(--band-bg);border:1px solid var(--band-bd);border-radius:26px;
  padding:52px 40px;text-align:center;position:relative;overflow:hidden}
.band::before{content:"";position:absolute;inset:0;background:radial-gradient(500px 200px at 50% -40%,rgba(229,72,77,.25),transparent)}
.band h2{position:relative;font-size:clamp(22px,3vw,32px);letter-spacing:-.6px;margin:0 0 10px}
.band p{position:relative;color:var(--muted);margin:0 0 26px}
.foot{display:flex;align-items:center;gap:14px;color:var(--faint);font-size:12.5px;padding:44px 0 36px}
.foot .sp{flex:1}
.foot button{background:none;border:none;color:var(--faint);font-size:12.5px;cursor:pointer;text-decoration:underline}
/* ---- modals ---- */
.modal{position:fixed;inset:0;background:var(--overlay);backdrop-filter:blur(10px);display:none;place-items:center;z-index:10}
.modal.on{display:grid}
.mcard{position:relative;background:var(--s1);border:1px solid var(--hair);border-radius:22px;padding:36px 40px;
  width:min(92vw,392px);text-align:center;animation:rise .35s var(--spring) both;box-shadow:0 40px 100px rgba(0,0,0,.7)}
.mcard h3{margin:0 0 6px;font-size:18px}
.mcard .who{display:inline-block;font-size:10.5px;letter-spacing:2px;text-transform:uppercase;padding:4px 12px;border-radius:12px;margin-bottom:14px}
.mcard .who.user{background:rgba(245,201,107,.12);color:var(--gold)}
.mcard .who.adm{background:rgba(229,72,77,.14);color:var(--red-hi)}
.mcard p{color:var(--muted);font-size:13px;margin:0 0 18px}
.mcard input{width:100%;background:var(--s2);border:1px solid var(--hair);border-radius:11px;color:var(--ink);
  padding:12px 14px;font-size:14px;margin-bottom:10px;transition:border-color .2s}
.mcard input:focus{outline:none;border-color:var(--red)}
.mcard button.go{width:100%;background:linear-gradient(135deg,var(--red),#b52d33);border:none;border-radius:11px;color:#fff;
  padding:13px;font-weight:750;font-size:14px;cursor:pointer;transition:filter .2s}
.mcard button.go:hover{filter:brightness(1.1)}
.mcard .or2{display:flex;align-items:center;gap:10px;color:var(--faint);font-size:10.5px;letter-spacing:1.6px;margin:14px 0}
.mcard .or2::before,.mcard .or2::after{content:"";flex:1;height:1px;background:var(--hair)}
.mcard .x{position:absolute;top:14px;right:18px;background:none;border:none;color:var(--muted);font-size:18px;cursor:pointer}
.err{color:#ff9ea1;font-size:12.5px;min-height:16px;margin-top:8px}
@media (prefers-reduced-motion: reduce){*{animation-duration:.001s !important;transition-duration:.001s !important}}
</style></head><body>
<div class="orb a"></div><div class="orb b"></div><div class="grain"></div>
<nav class="topbar" id="topbar">
  <div class="navin">
    <div class="logo">R</div>
    <div class="brandname"><b>RedTee</b><span class="tag">Screening room</span></div>
    <div class="navlinks">
      <a href="#feats">Why RedTee</a><a href="#how">How it works</a>
    </div>
    <div class="sp"></div>
    <button class="adminlink themebtn" onclick="toggleTheme()" title="light / dark"></button>
    <button class="adminlink" onclick="openModal('am')"><svg class="icn" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="7.5" cy="15.5" r="4.5"/><path d="M10.8 12.2 21 2M15.5 7.5l3 3"/></svg> Admin sign in</button>
    <button class="navcta" onclick="openModal('cm')">Enter screening room</button>
  </div>
</nav>
<div class="wrap">
  <div class="hero">
    <div>
      <span class="kick"><span class="dot"></span>Private preview &middot; invite only</span>
      <h1>Watch tomorrow's lessons.<br><em>Shape</em> what ships.</h1>
      <p>Your team's training videos, fresh off the assembly line. Watch in a real screening room, flag the exact moment - down to the slide - and file a verdict in two minutes flat.</p>
      <div class="cta">
        __GOOGLE_BTN__
        <button class="codebtn" onclick="openModal('cm')">I have an access code</button>
      </div>
      <div class="trust">
        <span><svg class="icn" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="9"/><path d="M10 8.5v7l6-3.5z"/></svg> native player</span><span><svg class="icn" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="8"/><circle cx="12" cy="12" r="3"/><path d="M12 2v3M12 19v3M2 12h3M19 12h3"/></svg> slide-exact feedback</span><span><svg class="icn" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="5" y="11" width="14" height="9" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/></svg> access-controlled library</span>
      </div>
    </div>
    <div class="stage3d">
      <div class="beam"></div>
      <div class="mock player">
        <div class="slide"><div class="ttl"></div><div class="ttl b"></div><div class="ring"></div><div class="bar a"></div><div class="bar b"></div></div>
        <div class="ctrl"><div class="pl"></div><div class="tr"></div><span class="tm">3:05 / 8:51</span></div>
      </div>
      <div class="mock review">
        <div class="st">★★★★<span style="opacity:.25">★</span></div>
        <div class="chiprow"><span class="chip on">loved it</span><span class="chip on">the visuals</span><span class="chip">too fast</span><span class="chip">audio</span></div>
        <div class="stamp">moment flagged at <b>3:05</b> &middot; slide 7 of 25 &middot; cost_meter</div>
      </div>
    </div>
  </div>
</div>
<div class="film"></div>
<div class="wrap">
  <div class="sec" id="feats">
    <div class="h">Why it does not feel like a form</div>
    <h2>Reviewing that respects your time.</h2>
    <div class="feats">
      <div class="feat"><div class="ic"><svg class="icn" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M20.2 6 3 11l-.9-2.4c-.3-1.1.3-2.2 1.4-2.5l13.5-4c1.1-.3 2.2.3 2.5 1.4zM6.2 5.3l3.1 3.9M12.4 3.4l3.2 4M3 11h18v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/></svg></div><b>A real screening room</b><span>Poster-wall library, native playback, lights-down mode. You only see the collections you have access to.</span></div>
      <div class="feat"><div class="ic"><svg class="icn" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M20 10c0 6-8 12-8 12s-8-6-8-12a8 8 0 0 1 16 0z"/><circle cx="12" cy="10" r="3"/></svg></div><b>Flag the exact moment</b><span>Timestamps fill themselves while you watch, and the actual slide appears under your note - so feedback lands on the right frame, every time.</span></div>
      <div class="feat"><div class="ic"><svg class="icn" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M13 2 3 14h7l-1 8 10-12h-7z"/></svg></div><b>Verdicts in chips</b><span>Tap what fits instead of writing essays. One optional line for anything the chips miss. Median review: about two minutes.</span></div>
    </div>
  </div>
  <div class="sec" id="how">
    <div class="h">How it works</div>
    <h2>Three steps, then you are done.</h2>
    <div class="steps">
      <div class="step"><div class="n">01</div><b>Watch</b><span>Pick a screening from your library. The player knows exactly where you are.</span></div>
      <div class="step"><div class="n">02</div><b>Flag moments</b><span>One tap stamps the timestamp and shows the slide. Tag it: loved it, confusing, too fast.</span></div>
      <div class="step"><div class="n">03</div><b>File the verdict</b><span>Stars, chips, done. Your feedback appears on the maker's dashboard per slide, instantly.</span></div>
    </div>
  </div>
  <div class="band">
    <h2>The next lesson is better because you watched this one.</h2>
    <p>Every review feeds straight back into how the videos get made.</p>
    <div class="cta" style="justify-content:center">__GOOGLE_BTN__<button class="codebtn" onclick="openModal('cm')">Use an access code</button></div>
  </div>
  <div class="foot">
    <span>RedTee - deterministic training video, reviewed by humans.</span>
    <div class="sp"></div>
    <button onclick="openModal('am')">Admin sign in</button>
  </div>
</div>

<div class="modal" id="cm"><div class="mcard">
  <button class="x" onclick="closeModal('cm')">&times;</button>
  <span class="who user">Reviewer</span>
  <h3>Enter the screening room</h3><p>Your email + the access code your admin shared.</p>
  <input id="cemail" type="email" placeholder="you@company.com">
  <input id="ce" type="password" placeholder="access code">
  <button class="go" onclick="codeGo(false)">Start watching</button>
  <div class="err" id="cerr"></div>
</div></div>

<div class="modal" id="am"><div class="mcard">
  <button class="x" onclick="closeModal('am')">&times;</button>
  <span class="who adm">Admin</span>
  <h3>Admin sign in</h3><p>Google (admin-permitted emails only)__ADM_OR__</p>
  __GOOGLE_BTN_ADMIN__
  <div id="admcode">
    <input id="aemail" type="email" placeholder="admin@company.com">
    <input id="ae" type="password" placeholder="admin code">
    <button class="go" onclick="codeGo(true)">Open the admin console</button>
  </div>
  <div class="err" id="aerr"></div>
</div></div>
<script>
function toggleTheme(){var h=document.documentElement;var t=h.getAttribute('data-theme')==='light'?'dark':'light';
h.setAttribute('data-theme',t);try{localStorage.setItem('rt_theme',t)}catch(e){}
document.querySelectorAll('.themebtn').forEach(function(b){b.innerHTML=t==='light'?'<svg class="icn" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z"/></svg>':'<svg class="icn" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/></svg>'})}
document.addEventListener('DOMContentLoaded',function(){var t=document.documentElement.getAttribute('data-theme');
document.querySelectorAll('.themebtn').forEach(function(b){b.innerHTML=t==='light'?'<svg class="icn" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z"/></svg>':'<svg class="icn" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/></svg>'})});
window.addEventListener('scroll',()=>{document.getElementById('topbar').classList.toggle('scrolled',window.scrollY>12)},{passive:true});
function openModal(id){document.getElementById(id).classList.add('on');
  const f=document.getElementById(id==='am'?'aemail':'cemail');if(f)setTimeout(()=>f.focus(),60)}
function closeModal(id){document.getElementById(id).classList.remove('on')}
document.addEventListener('keydown',e=>{if(e.key==='Escape'){closeModal('cm');closeModal('am')}
  if(e.key==='Enter'){if(document.getElementById('am').classList.contains('on'))codeGo(true);
    else if(document.getElementById('cm').classList.contains('on'))codeGo(false)}});
async function codeGo(admin){
  const code=document.getElementById(admin?'ae':'ce').value;
  const email=document.getElementById(admin?'aemail':'cemail').value;
  const err=document.getElementById(admin?'aerr':'cerr');
  const r=await(await fetch('/api/auth',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({code,email})})).json();
  if(!r.ok){err.textContent='that code did not work'+(admin?' - the ADMIN code is different from the access code':' - check with your admin');return}
  if(admin&&!r.admin){err.textContent='that is a reviewer code, not the admin code';return}
  location.href=admin?'/admin':'/';
}
</script></body></html>"""

GOOGLE_BTN = """<a class="gbtn" href="/auth/google"><svg viewBox="0 0 48 48"><path fill="#FFC107" d="M43.6 20.1H42V20H24v8h11.3C33.7 32.7 29.2 36 24 36c-6.6 0-12-5.4-12-12s5.4-12 12-12c3.1 0 5.9 1.2 8 3l5.7-5.7C34.3 6.1 29.4 4 24 4 13 4 4 13 4 24s9 20 20 20 20-9 20-20c0-1.3-.1-2.7-.4-3.9z"/><path fill="#FF3D00" d="M6.3 14.7l6.6 4.8C14.7 15.1 19 12 24 12c3.1 0 5.9 1.2 8 3l5.7-5.7C34.3 6.1 29.4 4 24 4 16.3 4 9.7 8.3 6.3 14.7z"/><path fill="#4CAF50" d="M24 44c5.2 0 9.9-2 13.4-5.2l-6.2-5.2C29.2 35.1 26.7 36 24 36c-5.2 0-9.6-3.3-11.3-8l-6.5 5C9.5 39.6 16.2 44 24 44z"/><path fill="#1976D2" d="M43.6 20.1H42V20H24v8h11.3c-.8 2.3-2.3 4.3-4.1 5.7l6.2 5.2C41 35.4 44 30.2 44 24c0-1.3-.1-2.7-.4-3.9z"/></svg>Continue with Google</a>"""


def LANDING() -> str:
    o = _oauth_conf()
    has_g = bool(o.get("client_id") and o.get("client_secret"))
    btn = GOOGLE_BTN if has_g else ""
    return (LANDING_TEMPLATE
            .replace("__GOOGLE_BTN_ADMIN__", (GOOGLE_BTN.replace(">Continue with Google<", ">Sign in with Google<")
                                              + '<div class="or2">OR THE ADMIN CODE</div>') if has_g else "")
            .replace("__ADM_OR__", " - or the admin code." if has_g else ".")
            .replace("__GOOGLE_BTN__", btn))


LOGIN_PAGE = """<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>
<title>RedTee Screening Room</title>
<script>(function(){var t;try{t=localStorage.getItem('rt_theme')}catch(e){}
if(!t)t=window.matchMedia&&matchMedia('(prefers-color-scheme: light)').matches?'light':'dark';
document.documentElement.setAttribute('data-theme',t)})()</script><style>
:root{--lg-bg:#0a0b0e;--lg-ink:#f2f2f5;--lg-card:#141419;--lg-hair:#ffffff12;--lg-mut:#848791;--lg-in:#0e0e12}
[data-theme="light"]{--lg-bg:#f5f5f7;--lg-ink:#1b1e28;--lg-card:#ffffff;--lg-hair:#00000014;--lg-mut:#5d6370;--lg-in:#eceef2}
body{margin:0;background:var(--lg-bg);color:var(--lg-ink);font:15px/1.6 Inter,'Segoe UI',system-ui,sans-serif;display:grid;place-items:center;min-height:100vh}
.card{background:var(--lg-card);border:1px solid var(--lg-hair);border-radius:22px;padding:40px 44px;max-width:400px;text-align:center;box-shadow:0 30px 90px rgba(0,0,0,.25)}
.logo{width:46px;height:46px;border-radius:13px;background:linear-gradient(135deg,#e5484d,#b52d33);display:grid;place-items:center;font-weight:800;font-size:19px;margin:0 auto 16px}
h1{font-size:19px;margin:0 0 4px}p{color:var(--lg-mut);font-size:13.5px;margin:0 0 22px}
input{width:100%;background:var(--lg-in);border:1px solid var(--lg-hair);border-radius:11px;color:var(--lg-ink);padding:12px 14px;font-size:15px;text-align:center;letter-spacing:2px}
input:focus{outline:none;border-color:#e5484d}
button{width:100%;margin-top:14px;background:linear-gradient(135deg,#e5484d,#b52d33);border:none;border-radius:11px;color:#fff;padding:12px;font-size:14px;font-weight:700;cursor:pointer}
.err{color:#ff9ea1;font-size:12.5px;margin-top:10px;min-height:16px}
</style></head><body><div class='card'><div class='logo'>R</div><h1>Screening room</h1>
<p>Enter your organization's access code to watch and review.</p>
<input id='c' type='password' placeholder='access code' autofocus>
<button onclick='go()'>Enter</button><div class='err' id='e'></div>
<script>
const c=document.getElementById('c');c.addEventListener('keydown',e=>{if(e.key==='Enter')go()});
async function go(){
  const r=await(await fetch('/api/auth',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({code:c.value})})).json();
  if(r.ok)location.reload();else document.getElementById('e').textContent='wrong code, try again';
}
</script></div></body></html>"""


class H(BaseHTTPRequestHandler):
    def _cookies(self) -> dict:
        out = {}
        for part in (self.headers.get("Cookie") or "").split(";"):
            if "=" in part:
                k, v = part.split("=", 1)
                out[k.strip()] = v.strip()
        return out

    def _session(self):
        sid = self._cookies().get("rt_sid", "")
        return _sessions().get(sid)

    def _email(self) -> str:
        se = self._session()
        return (se or {}).get("email", "")

    def _auth_configured(self) -> bool:
        return _auth_on()

    def _authed(self) -> bool:
        if not self._auth_configured():
            return True                                   # open local mode
        if self._session():
            return True
        access, admin = _codes()
        ck = self._cookies()
        if access and ck.get("rt_access") in (_token(access), _token(admin)):
            return True
        return ck.get("rt_invite") in _invites()

    def _is_admin(self) -> bool:
        if not self._auth_configured():
            return True                                   # open local mode
        em = self._email()
        if em and em in _admin_emails():
            return True
        _access, admin = _codes()
        if not admin:
            return False
        ck = self._cookies()
        return ck.get("rt_access") == _token(admin) or ck.get("rt_admin") == _token(admin)

    def _secure(self) -> str:
        """'; Secure' when the request arrived over TLS (behind a proxy that sets
        X-Forwarded-Proto). Keeps plain-http localhost dev working."""
        return "; Secure" if self.headers.get("X-Forwarded-Proto", "").lower() == "https" else ""

    def _json_body(self, cap: int = MAX_JSON_BODY):
        """Read + parse a JSON request body with a size cap. Returns the parsed object,
        or raises ValueError (oversize / bad JSON) which callers turn into a 4xx."""
        n = int(self.headers.get("Content-Length", "0"))
        if n <= 0 or n > cap:
            raise ValueError("empty or oversize body")
        return json.loads(self.rfile.read(n).decode("utf-8"))

    def _send(self, code, body, ctype="application/json"):
        raw = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype + "; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, *a):  # quiet
        pass

    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        if u.path == "/health":
            return self._send(200, json.dumps({"ok": True}))
        q0 = urllib.parse.parse_qs(u.query)
        if u.path == "/" and q0.get("invite", [""])[0] in _invites() and q0.get("invite", [""])[0]:
            tok = q0["invite"][0]
            raw = PAGE.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Set-Cookie", f"rt_invite={tok}; HttpOnly; Path=/; Max-Age=7776000; SameSite=Lax" + self._secure())
            self.end_headers()
            self.wfile.write(raw)
            return None
        _open_paths = ("/auth/google", "/auth/google/cb", "/logout")
        if not self._authed() and u.path not in _open_paths:
            if u.path == "/":
                return self._send(200, LANDING(), "text/html")
            return self._send(401, json.dumps({"error": "auth required"}))
        if u.path == "/":
            return self._send(200, PAGE, "text/html")
        if u.path == "/admin":
            if not self._is_admin():
                return self._send(200, LOGIN_PAGE.replace("organization's access code", "ADMIN code"), "text/html")
            return self._send(200, ADMIN_PAGE, "text/html")
        if u.path == "/api/me":
            se = self._session()
            inv = _invites().get(self._cookies().get("rt_invite", ""))
            ident = None
            if se:
                ident = {"name": se.get("name", ""), "role": "", "email": se.get("email", "")}
            elif inv:
                ident = {k: inv.get(k, "") for k in ("name", "role", "email")}
            return self._send(200, json.dumps({"identity": ident, "admin": self._is_admin(),
                                               "email": (se or {}).get("email", "")}))
        if u.path == "/api/stats":
            if not self._is_admin():
                return self._send(403, json.dumps({"error": "admin required"}))
            return self._send(200, json.dumps(_stats()))
        if u.path == "/api/collections":
            if not self._is_admin():
                return self._send(403, json.dumps({"error": "admin required"}))
            return self._send(200, json.dumps({"collections": _collections()}))
        if u.path == "/api/invites":
            if not self._is_admin():
                return self._send(403, json.dumps({"error": "admin required"}))
            return self._send(200, json.dumps({"invites": [dict(v, token=k) for k, v in _invites().items()]}))
        if u.path == "/api/videos":
            force = "refresh" in urllib.parse.parse_qs(u.query)
            return self._send(200, json.dumps(_videos(force, self._email(), self._is_admin())))
        if u.path == "/api/reviews":
            vid = urllib.parse.parse_qs(u.query).get("video", [""])[0]
            return self._send(200, json.dumps({"reviews": _reviews_for(vid)}))
        if u.path == "/api/bundles":
            idx = _bundle_index("refresh" in urllib.parse.parse_qs(u.query))
            return self._send(200, json.dumps({"bundles": [
                {"key": k, "kind": v["kind"]} for k, v in sorted(idx.items())]}))
        if u.path == "/api/slide":
            q = urllib.parse.parse_qs(u.query)
            vid = _drive_id(q.get("video", [""])[0])
            t = _parse_ts(q.get("t", ["0"])[0])
            title = q.get("title", [""])[0]
            if vid and not _user_can_watch(vid, self._email(), self._is_admin()):
                return self._send(403, json.dumps({"found": False, "reason": "no access"}))
            key = q.get("bundle", [""])[0] or _bundle_for_video(vid, title)
            if not key or t < 0:
                return self._send(200, json.dumps({"found": False,
                                                   "reason": "no lesson bundle linked to this video" if t >= 0 else "bad timestamp"}))
            hit = _slide_at(key, t)
            return self._send(200, json.dumps(hit or {"found": False, "reason": "bundle unreadable"}))
        if u.path == "/api/stream":
            vid = _drive_id(urllib.parse.parse_qs(u.query).get("video", [""])[0])
            key = _conf().get("drive_api_key", "")
            if not vid:
                return self._send(404, json.dumps({"error": "no stream available"}))
            if not _user_can_watch(vid, self._email(), self._is_admin()):
                return self._send(403, json.dumps({"error": "you do not have access to this video"}))
            rng = self.headers.get("Range")
            if vid.startswith("local_"):
                fp = _local_path(vid)
                if not fp or not fp.is_file():
                    return self._send(404, json.dumps({"error": "uploaded video not found"}))
                size = fp.stat().st_size
                start, end = 0, size - 1
                mm = re.match(r"bytes=(\d*)-(\d*)", rng or "")
                if mm and (mm.group(1) or mm.group(2)):
                    if mm.group(1):
                        start = int(mm.group(1))
                        end = int(mm.group(2)) if mm.group(2) else size - 1
                    else:                                   # suffix range: last N bytes
                        start = max(0, size - int(mm.group(2)))
                    end = min(end, size - 1)
                if start > end or start >= size:
                    self.send_response(416)
                    self.send_header("Content-Range", f"bytes */{size}")
                    self.end_headers()
                    return None
                self.send_response(206 if rng else 200)
                self.send_header("Content-Type", "video/webm" if fp.suffix == ".webm" else "video/mp4")
                self.send_header("Accept-Ranges", "bytes")
                self.send_header("Content-Length", str(end - start + 1))
                if rng:
                    self.send_header("Content-Range", f"bytes {start}-{end}/{size}")
                self.end_headers()
                try:
                    with open(fp, "rb") as fh:
                        fh.seek(start)
                        left = end - start + 1
                        while left > 0:
                            chunk = fh.read(min(65536, left))
                            if not chunk:
                                break
                            self.wfile.write(chunk)
                            left -= len(chunk)
                except (BrokenPipeError, ConnectionResetError, OSError):
                    pass
                return None
            try:
                upstream = _stream_upstream(vid, key, rng)
            except urllib.error.HTTPError as e:
                return self._send(e.code, json.dumps({"error": f"drive answered {e.code}"}))
            except Exception as e:  # noqa: BLE001
                return self._send(502, json.dumps({"error": type(e).__name__}))
            try:
                with upstream as r:
                    self.send_response(getattr(r, "status", 200))
                    ct = r.headers.get("Content-Type") or "video/mp4"
                    self.send_header("Content-Type", "video/mp4" if "octet-stream" in ct else ct)
                    for h in ("Content-Length", "Content-Range", "Accept-Ranges"):
                        if r.headers.get(h):
                            self.send_header(h, r.headers[h])
                    if not r.headers.get("Accept-Ranges"):
                        self.send_header("Accept-Ranges", "bytes")
                    self.send_header("Cache-Control", "no-store")
                    self.end_headers()
                    shutil.copyfileobj(r, self.wfile, 64 * 1024)
            except (BrokenPipeError, ConnectionResetError, OSError):
                pass                        # the player seeked/closed mid-stream: normal
            return None
        if u.path == "/auth/google":
            o = _oauth_conf()
            if not (o.get("client_id") and o.get("client_secret")):
                return self._send(400, json.dumps({"error": "Google sign-in not configured yet - ask the admin"}))
            proto = self.headers.get("X-Forwarded-Proto", "http")
            host = self.headers.get("X-Forwarded-Host") or self.headers.get("Host", f"127.0.0.1:{PORT}")
            state = secrets.token_urlsafe(16)
            url = ("https://accounts.google.com/o/oauth2/v2/auth?" + urllib.parse.urlencode({
                "client_id": o["client_id"], "redirect_uri": f"{proto}://{host}/auth/google/cb",
                "response_type": "code", "scope": "openid email profile", "prompt": "select_account",
                "state": state}))
            self.send_response(302)
            self.send_header("Set-Cookie", f"rt_gstate={state}; HttpOnly; Path=/; Max-Age=600; SameSite=Lax" + self._secure())
            self.send_header("Location", url)
            self.end_headers()
            return None
        if u.path == "/auth/google/cb":
            qcb = urllib.parse.parse_qs(u.query)
            code = qcb.get("code", [""])[0]
            state = qcb.get("state", [""])[0]
            if not state or state != self._cookies().get("rt_gstate", ""):
                return self._send(400, json.dumps({"error": "sign-in state mismatch - please try again"}))
            o = _oauth_conf()
            proto = self.headers.get("X-Forwarded-Proto", "http")
            host = self.headers.get("X-Forwarded-Host") or self.headers.get("Host", f"127.0.0.1:{PORT}")
            try:
                body = urllib.parse.urlencode({
                    "client_id": o.get("client_id", ""), "client_secret": o.get("client_secret", ""),
                    "code": code, "grant_type": "authorization_code",
                    "redirect_uri": f"{proto}://{host}/auth/google/cb"}).encode()
                req = urllib.request.Request("https://oauth2.googleapis.com/token", data=body,
                                             headers={"Content-Type": "application/x-www-form-urlencoded"})
                with urllib.request.urlopen(req, timeout=20) as r:
                    d = json.loads(r.read().decode())
                idt = d.get("id_token", "")
                pay = idt.split(".")[1]
                pay += "=" * (-len(pay) % 4)
                import base64 as _b64
                claims = json.loads(_b64.urlsafe_b64decode(pay))
                # Defensive claim checks. The token came directly from Google's token endpoint
                # over TLS (in exchange for our code), so we trust its origin; we still pin the
                # audience + issuer so a token minted for a different client can't be replayed.
                if claims.get("aud") != o.get("client_id"):
                    raise ValueError("id_token audience mismatch")
                if claims.get("iss") not in ("https://accounts.google.com", "accounts.google.com"):
                    raise ValueError("id_token issuer mismatch")
                email = str(claims.get("email", "")).lower()
                if not email:
                    raise ValueError("no email in id_token")
                sid = _new_session(email, str(claims.get("name") or email.split("@")[0]), "google")
                self.send_response(302)
                self.send_header("Set-Cookie", f"rt_sid={sid}; HttpOnly; Path=/; Max-Age=7776000; SameSite=Lax" + self._secure())
                self.send_header("Set-Cookie", "rt_gstate=; Path=/; Max-Age=0")
                self.send_header("Location", "/admin" if email in _admin_emails() else "/")
                self.end_headers()
                return None
            except Exception as e:  # noqa: BLE001
                return self._send(502, json.dumps({"error": f"google sign-in failed ({type(e).__name__})"}))
        if u.path == "/logout":
            sid = self._cookies().get("rt_sid", "")
            d = _sessions()
            if sid in d:
                d.pop(sid, None)
                _save_sessions(d)
            self.send_response(302)
            self.send_header("Set-Cookie", "rt_sid=; Path=/; Max-Age=0")
            self.send_header("Location", "/")
            self.end_headers()
            return None
        if u.path == "/oauth/start":
            if not self._is_admin():
                return self._send(403, json.dumps({"error": "admin required"}))
            o = _oauth_conf()
            if not (o.get("client_id") and o.get("client_secret")):
                return self._send(400, json.dumps({"error": "save client_id + client_secret first (setup card)"}))
            proto = self.headers.get("X-Forwarded-Proto", "http")
            host = self.headers.get("X-Forwarded-Host") or self.headers.get("Host", f"127.0.0.1:{PORT}")
            redirect = f"{proto}://{host}/oauth/callback"
            state = secrets.token_urlsafe(16)
            url = ("https://accounts.google.com/o/oauth2/v2/auth?" + urllib.parse.urlencode({
                "client_id": o["client_id"], "redirect_uri": redirect, "response_type": "code",
                "scope": "https://www.googleapis.com/auth/drive.readonly",
                "access_type": "offline", "prompt": "consent", "state": state}))
            self.send_response(302)
            self.send_header("Set-Cookie", f"rt_dstate={state}; HttpOnly; Path=/; Max-Age=600; SameSite=Lax" + self._secure())
            self.send_header("Location", url)
            self.end_headers()
            return None
        if u.path == "/oauth/callback":
            if not self._is_admin():
                return self._send(403, json.dumps({"error": "admin required"}))
            qcb = urllib.parse.parse_qs(u.query)
            code = qcb.get("code", [""])[0]
            state = qcb.get("state", [""])[0]
            if not state or state != self._cookies().get("rt_dstate", ""):
                return self._send(400, json.dumps({"error": "oauth state mismatch - please retry the connection"}))
            if not code:
                return self._send(400, json.dumps({"error": "no code in callback"}))
            o = _oauth_conf()
            proto = self.headers.get("X-Forwarded-Proto", "http")
            host = self.headers.get("X-Forwarded-Host") or self.headers.get("Host", f"127.0.0.1:{PORT}")
            body = urllib.parse.urlencode({
                "client_id": o.get("client_id", ""), "client_secret": o.get("client_secret", ""),
                "code": code, "grant_type": "authorization_code",
                "redirect_uri": f"{proto}://{host}/oauth/callback"}).encode()
            try:
                req = urllib.request.Request("https://oauth2.googleapis.com/token", data=body,
                                             headers={"Content-Type": "application/x-www-form-urlencoded"})
                with urllib.request.urlopen(req, timeout=20) as r:
                    d = json.loads(r.read().decode())
                rt = d.get("refresh_token")
                if not rt:
                    return self._send(400, json.dumps({"error": "Google returned no refresh_token - remove the app at myaccount.google.com/permissions and connect again"}))
                c = _conf(); c.pop("_error", None)
                g = c.setdefault("google_oauth", {})
                g["refresh_token"] = rt
                CONF_PATH.write_text(json.dumps(c, indent=1, ensure_ascii=False), encoding="utf-8")
                _OAUTH["access"] = d.get("access_token"); _OAUTH["exp"] = time.time() + float(d.get("expires_in", 3600))
                _cache["videos"] = None
                self.send_response(302)
                self.send_header("Location", "/")
                self.end_headers()
                return None
            except urllib.error.HTTPError as e:
                return self._send(502, json.dumps({"error": f"token exchange failed ({e.code})"}))
        if u.path == "/api/thumb":
            vid = _drive_id(urllib.parse.parse_qs(u.query).get("video", [""])[0])
            if not vid or not _oauth_ready():
                return self._send(404, json.dumps({"error": "no thumb"}))
            try:
                with _gapi(f"https://www.googleapis.com/drive/v3/files/{urllib.parse.quote(vid)}"
                           f"?fields=thumbnailLink&supportsAllDrives=true") as r:
                    tl = json.loads(r.read().decode()).get("thumbnailLink")
                if not tl:
                    return self._send(404, json.dumps({"error": "no thumb"}))
                with _gapi(tl) as r2:
                    data = r2.read(2_000_000)
                    self.send_response(200)
                    self.send_header("Content-Type", r2.headers.get("Content-Type", "image/jpeg"))
                    self.send_header("Content-Length", str(len(data)))
                    self.send_header("Cache-Control", "max-age=3600")
                    self.end_headers()
                    self.wfile.write(data)
                    return None
            except Exception:  # noqa: BLE001
                return self._send(404, json.dumps({"error": "thumb fetch failed"}))
        if u.path == "/api/diag":
            folder = urllib.parse.parse_qs(u.query).get("folder", [""])[0]
            if not folder:
                folder = _conf().get("drive_folder_id", "")
            return self._send(200, json.dumps(_diag_folder(folder)))
        if u.path == "/api/report":
            q = urllib.parse.parse_qs(u.query)
            vid = q.get("video", [""])[0]
            title = q.get("title", [""])[0]
            if not _user_can_watch(_drive_id(vid), self._email(), self._is_admin()):
                return self._send(403, json.dumps({"error": "no access"}))
            return self._send(200, _build_report(vid, title), "text/html")
        if u.path == "/api/export.csv":
            if not self._is_admin():
                return self._send(403, json.dumps({"error": "admin required"}))
            return self._send(200, _export_csv(), "text/csv")
        return self._send(404, json.dumps({"error": "not found"}))

    def do_POST(self):
        if self.path == "/api/auth":
            try:
                p = self._json_body()
            except (ValueError, OSError):
                return self._send(400, json.dumps({"ok": False}))
            access, admin = _codes()
            code = str(p.get("code", "")).strip()
            valid = bool(code) and ((access and code == access) or (admin and code == admin))
            if not valid:
                time.sleep(0.6)                     # slow brute force
                return self._send(200, json.dumps({"ok": False}))
            email = str(p.get("email", "")).strip().lower()
            sid = _new_session(email, email.split("@")[0] if email else "reviewer", "code")
            raw = json.dumps({"ok": True, "admin": code == admin and bool(admin)}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            sec = self._secure()
            self.send_header("Set-Cookie", f"rt_access={_token(code)}; HttpOnly; Path=/; Max-Age=7776000; SameSite=Lax" + sec)
            self.send_header("Set-Cookie", f"rt_sid={sid}; HttpOnly; Path=/; Max-Age=7776000; SameSite=Lax" + sec)
            if code == admin:
                self.send_header("Set-Cookie", f"rt_admin={_token(admin)}; HttpOnly; Path=/; Max-Age=7776000; SameSite=Lax" + sec)
            self.end_headers()
            self.wfile.write(raw)
            return None
        if not self._authed():
            return self._send(401, json.dumps({"ok": False, "error": "auth required"}))
        if self.path == "/api/collections":
            if not self._is_admin():
                return self._send(403, json.dumps({"ok": False, "error": "admin required"}))
            try:
                p = self._json_body()
            except (ValueError, OSError):
                return self._send(400, json.dumps({"ok": False, "error": "bad JSON"}))
            c = _conf(); c.pop("_error", None)
            cols = [x for x in _collections()]
            if p.get("delete"):
                cols = [x for x in cols if x.get("id") != p["delete"] or x.get("id") == "col_uploads"]
            elif p.get("update"):
                for x in cols:
                    if x.get("id") == p["update"]:
                        if p.get("visibility") in ("public", "private"):
                            x["visibility"] = p["visibility"]
                        if "allowed_emails" in p:
                            x["allowed_emails"] = [str(e).strip().lower() for e in p["allowed_emails"] if str(e).strip()]
                        if str(p.get("name", "")).strip():
                            x["name"] = str(p["name"]).strip()[:80]
            else:
                fol = _folder_id(str(p.get("folder", "")))
                if not fol:
                    return self._send(400, json.dumps({"ok": False, "error": "paste a Drive folder link"}))
                cols.append({"id": "col_" + secrets.token_hex(4),
                             "name": str(p.get("name", "")).strip()[:80] or "New collection",
                             "type": "drive", "folder_id": fol,
                             "visibility": p.get("visibility") if p.get("visibility") in ("public", "private") else "public",
                             "allowed_emails": [str(e).strip().lower() for e in (p.get("allowed_emails") or []) if str(e).strip()]})
            c["collections"] = cols
            CONF_PATH.write_text(json.dumps(c, indent=1, ensure_ascii=False), encoding="utf-8")
            _cache["videos"] = None
            return self._send(200, json.dumps({"ok": True, "collections": cols}))
        if self.path == "/api/invite":
            if not self._is_admin():
                return self._send(403, json.dumps({"ok": False, "error": "admin code required"}))
            try:
                p = self._json_body()
            except (ValueError, OSError):
                return self._send(400, json.dumps({"ok": False, "error": "bad JSON"}))
            inv = _invites()
            if p.get("revoke"):
                inv.pop(str(p["revoke"]), None)
                _save_invites(inv)
                return self._send(200, json.dumps({"ok": True}))
            name = str(p.get("name", "")).strip()
            if not name:
                return self._send(400, json.dumps({"ok": False, "error": "a name is required"}))
            tok = secrets.token_urlsafe(12)
            inv[tok] = {"name": name[:120], "role": str(p.get("role", "")).strip()[:120],
                        "email": str(p.get("email", "")).strip()[:200],
                        "created": time.strftime("%Y-%m-%d")}
            _save_invites(inv)
            return self._send(200, json.dumps({"ok": True, "token": tok}))
        if self.path.startswith("/api/upload-video"):
            if not self._is_admin():
                return self._send(403, json.dumps({"ok": False, "error": "admin code required"}))
            q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            name = re.sub(r"[^A-Za-z0-9 _.-]", "_", q.get("name", [""])[0]).strip()[:100]
            if not name.lower().endswith((".mp4", ".webm")):
                return self._send(400, json.dumps({"ok": False, "error": "name must end in .mp4 or .webm"}))
            try:
                n = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                n = 0
            if n <= 0 or n > 3 * 1024 * 1024 * 1024:
                return self._send(413, json.dumps({"ok": False, "error": "size must be 1B..3GB"}))
            VIDEO_DIR.mkdir(parents=True, exist_ok=True)
            tmp = VIDEO_DIR / (name + ".part")
            try:
                with open(tmp, "wb") as fh:
                    left = n
                    while left > 0:
                        chunk = self.rfile.read(min(1024 * 1024, left))
                        if not chunk:
                            break
                        fh.write(chunk)
                        left -= len(chunk)
                if left:
                    tmp.unlink(missing_ok=True)
                    return self._send(400, json.dumps({"ok": False, "error": "upload truncated"}))
                tmp.replace(VIDEO_DIR / name)
            except OSError as e:
                tmp.unlink(missing_ok=True)
                return self._send(500, json.dumps({"ok": False, "error": type(e).__name__}))
            _cache["videos"] = None
            return self._send(200, json.dumps({"ok": True, "video": name}))
        if self.path.startswith("/api/bundle"):
            if not self._is_admin():
                return self._send(403, json.dumps({"ok": False, "error": "admin code required"}))
            q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            name = re.sub(r"[^A-Za-z0-9_-]", "_", q.get("name", [""])[0])[:80]
            if not name:
                return self._send(400, json.dumps({"ok": False, "error": "missing ?name="}))
            try:
                n = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                n = 0
            if n <= 0 or n > 80 * 1024 * 1024:
                return self._send(413, json.dumps({"ok": False, "error": "bundle must be 1B..80MB"}))
            raw = self.rfile.read(n)
            try:
                d = json.loads(raw.decode("utf-8"))
                assert isinstance(d.get("spans"), list) and isinstance(d.get("svgs"), dict)
            except (ValueError, AssertionError):
                return self._send(400, json.dumps({"ok": False, "error": "not a valid .review.json sidecar"}))
            bdir = HERE / "bundles"
            bdir.mkdir(parents=True, exist_ok=True)
            (bdir / f"{name}.review.json").write_bytes(raw)
            _BUNDLE_CACHE["idx"] = None
            return self._send(200, json.dumps({"ok": True, "bundle": name, "slides": len(d["spans"])}))
        if self.path == "/api/link":
            if not self._is_admin():
                return self._send(403, json.dumps({"ok": False, "error": "admin code required"}))
            try:
                p = self._json_body()
            except (ValueError, OSError):
                return self._send(400, json.dumps({"ok": False, "error": "bad JSON"}))
            vid = _drive_id(str(p.get("video_id", "")))
            key = str(p.get("bundle", "")).strip()
            if not vid:
                return self._send(400, json.dumps({"ok": False, "error": "missing video_id"}))
            if key and key not in _bundle_index(True):
                return self._send(400, json.dumps({"ok": False, "error": "unknown bundle"}))
            c = _conf(); c.pop("_error", None)
            vb = c.setdefault("video_bundles", {})
            if key:
                vb[vid] = key
            else:
                vb.pop(vid, None)
            CONF_PATH.write_text(json.dumps(c, indent=1, ensure_ascii=False), encoding="utf-8")
            return self._send(200, json.dumps({"ok": True, "linked": key or None}))
        if self.path == "/api/config":
            if not self._is_admin():
                return self._send(403, json.dumps({"ok": False, "error": "admin code required"}))
            try:
                p = self._json_body()
            except (ValueError, OSError):
                return self._send(400, json.dumps({"ok": False, "error": "bad JSON"}))
            c = _conf(); c.pop("_error", None)
            fol = _folder_id(p.get("folder", ""))
            if p.get("folder") and not fol:
                return self._send(400, json.dumps({"ok": False, "error": "that does not look like a Drive folder link"}))
            if fol:
                c["drive_folder_id"] = fol
            if str(p.get("api_key", "")).strip():
                c["drive_api_key"] = str(p["api_key"]).strip()
            if "admin_emails" in p:
                c["admin_emails"] = [e.strip().lower() for e in str(p.get("admin_emails", "")).split(",") if e.strip()]
            if str(p.get("oauth_client_id", "")).strip() or str(p.get("oauth_client_secret", "")).strip():
                g = c.setdefault("google_oauth", {})
                if str(p.get("oauth_client_id", "")).strip():
                    g["client_id"] = str(p["oauth_client_id"]).strip()
                if str(p.get("oauth_client_secret", "")).strip():
                    g["client_secret"] = str(p["oauth_client_secret"]).strip()
            links = [ln.strip() for ln in str(p.get("links", "")).splitlines() if ln.strip()]
            if links:
                vids, bad = [], 0
                for i, ln in enumerate(links):
                    fid = _drive_id(ln)
                    if fid:
                        vids.append({"url": f"https://drive.google.com/file/d/{fid}/view",
                                     "title": f"Lesson {len(vids) + 1}"})
                    else:
                        bad += 1
                c["videos"] = vids
                if bad:
                    c.setdefault("_note", f"{bad} pasted line(s) were not /file/d/ links and were ignored")
            _any = ("admin_emails" in p or fol or links or str(p.get("api_key", "")).strip()
                    or str(p.get("oauth_client_id", "")).strip() or str(p.get("oauth_client_secret", "")).strip())
            if not _any:
                return self._send(400, json.dumps({"ok": False, "error": "paste a folder link, video links, an API key, or OAuth credentials"}))
            CONF_PATH.write_text(json.dumps(c, indent=1, ensure_ascii=False), encoding="utf-8")
            _cache["videos"] = None
            out = _videos(force=True)
            return self._send(200, json.dumps({"ok": True, "found": len(out["videos"]),
                                               "mode": out["mode"], "error": out.get("error", "")}))
        if self.path != "/api/review":
            return self._send(404, json.dumps({"error": "not found"}))
        try:
            payload = self._json_body()
        except (ValueError, OSError):
            return self._send(400, json.dumps({"ok": False, "error": "bad JSON"}))
        vid_chk = _drive_id(str(payload.get("video_id", "")))
        if vid_chk and not _user_can_watch(vid_chk, self._email(), self._is_admin()):
            return self._send(403, json.dumps({"ok": False, "error": "no access to this video"}))
        res = _save_review(payload)
        return self._send(200 if res.get("ok") else 400, json.dumps(res))


def main():
    REVIEW_DIR.mkdir(parents=True, exist_ok=True)
    if not CONF_PATH.exists():
        CONF_PATH.write_text(json.dumps({
            "_how": "EITHER set drive_folder_id + drive_api_key (public folder, listed live), OR list videos manually. Drive files must be 'anyone with the link can view'.",
            "drive_folder_id": "",
            "drive_api_key": "",
            "videos": [{"url": "https://drive.google.com/file/d/PASTE_FILE_ID/view", "title": "My first lesson"}],
        }, indent=1), encoding="utf-8")
    v = _videos()
    print(f"RedTee Review - the screening room")
    print(f"  http://127.0.0.1:{PORT}")
    print(f"  videos: {len(v['videos'])} ({v['mode']})" + (f"  NOTE: {v['error']}" if v.get("error") else ""))
    print(f"  reviews -> {REVIEW_DIR}  |  export -> /api/export.csv")
    access, admin = _codes()
    print(f"  access: {'code required' if access else 'OPEN (set access_code in config.json for an org deployment)'}"
          + (f" | admin code {'set' if admin != access else '= access code'}" if access else ""))
    if access and HOST == "127.0.0.1":
        print("  NOTE: access code is set but host is 127.0.0.1 - run with REDTEE_REVIEW_HOST=0.0.0.0 to serve the org")
    ThreadingHTTPServer((HOST, PORT), H).serve_forever()


ADMIN_PAGE = r"""<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Screening room - admin</title><script>(function(){var t;try{t=localStorage.getItem('rt_theme')}catch(e){}
if(!t)t=window.matchMedia&&matchMedia('(prefers-color-scheme: light)').matches?'light':'dark';
document.documentElement.setAttribute('data-theme',t)})()</script><style>
:root{--bg:#0a0b0e;--s1:#141419;--s0:#0e0e12;--ink:#f2f2f5;--muted:#848791;--red:#e5484d;--gold:#f5c96b;--ok:#3dd68c;--hair:#ffffff12;color-scheme:dark}
[data-theme="light"]{--bg:#f5f5f7;--s1:#ffffff;--s0:#eceef2;--ink:#1b1e28;--muted:#5d6370;--red:#d63a40;--gold:#a67c1b;--ok:#1f9e63;--hair:#00000014;color-scheme:light}
body{transition:background-color .3s,color .3s}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:14.5px/1.6 Inter,"Segoe UI",system-ui,sans-serif;padding:34px}
.wrap{max-width:1180px;margin:0 auto}
h1{font-size:23px;margin:0 0 4px}.sub{color:var(--muted);margin:0 0 26px;font-size:13px}
h2{font-size:12px;letter-spacing:1.6px;text-transform:uppercase;color:var(--muted);margin:30px 0 12px}
.cards{display:grid;grid-template-columns:repeat(3,1fr);gap:14px}
.kpi{background:var(--s1);border:1px solid var(--hair);border-radius:16px;padding:18px 22px}
.kpi .n{font-size:30px;font-weight:800}.kpi .l{color:var(--muted);font-size:12px}
table{border-collapse:collapse;width:100%;font-size:13.5px;background:var(--s1);border-radius:14px;overflow:hidden}
th,td{border-bottom:1px solid var(--hair);padding:10px 14px;text-align:left;vertical-align:top}
th{background:var(--s0);color:var(--muted);font-size:11px;letter-spacing:1px;text-transform:uppercase}
tr:last-child td{border-bottom:none}
.pill{display:inline-block;background:var(--s0);border:1px solid var(--hair);border-radius:14px;padding:2px 10px;font-size:11.5px;color:var(--muted);margin:1px 3px 1px 0}
.pill.bad{color:#ff9ea1;border-color:#5c2226}.pill.good{color:var(--ok)}
a{color:var(--gold);text-decoration:none}a:hover{text-decoration:underline}
.star{color:var(--gold)}
.inv{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:14px}
input{background:var(--s0);border:1px solid var(--hair);border-radius:9px;color:var(--ink);padding:9px 12px;font-size:13px}
button{background:linear-gradient(135deg,var(--red),#b52d33);border:none;border-radius:9px;color:#fff;padding:9px 16px;font-size:13px;font-weight:700;cursor:pointer}
button.ghost{background:none;border:1px solid var(--hair);color:var(--muted)}
.link{font-family:ui-monospace,monospace;font-size:12px;background:var(--s0);border:1px solid var(--hair);border-radius:8px;padding:6px 10px;word-break:break-all}
.note{color:var(--muted);font-size:12px}
</style></head><body><div class="wrap">
<h1>Screening room - admin <button onclick="(function(){var h=document.documentElement;var t=h.getAttribute('data-theme')==='light'?'dark':'light';h.setAttribute('data-theme',t);try{localStorage.setItem('rt_theme',t)}catch(e){}})()" style="float:right;background:none;border:1px solid var(--hair);border-radius:9px;color:var(--muted);padding:6px 12px;font-size:12px;cursor:pointer"><svg class="icn" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/></svg> / <svg class="icn" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z"/></svg> theme</button></h1><p class="sub"><a href="/">&larr; back to the lobby</a> &middot; <a href="/api/export.csv">export all reviews (CSV)</a></p>
<div class="cards" id="kpis"></div>
<h2>Videos</h2><div id="vids"></div>
<h2>Slide hotspots (most flagged moments)</h2><div id="hot"></div>
<h2>Most requested changes</h2><div id="chg"></div>
<h2>Collections (who sees what)</h2>
<p class="note">A collection is a Drive folder (or the uploads bucket). <b>Public</b> = every signed-in person sees it. <b>Private</b> = only the emails you assign.</p>
<div class="inv"><input id="cn" placeholder="collection name"><input id="cf" placeholder="Drive folder link" style="min-width:280px"><button onclick="mkCol()">Add collection</button></div>
<div id="cols"></div>
<h2>Admin emails</h2>
<p class="note">These emails get admin powers when they sign in with Google. Comma-separated.</p>
<div class="inv"><input id="adme" style="min-width:380px" placeholder="you@company.com, colleague@company.com"><button onclick="saveAdmins()">Save</button></div>
<h2>Reviewer invite links</h2>
<div class="inv"><input id="in" placeholder="name"><input id="ir" placeholder="role / team"><input id="ie" placeholder="email (optional)"><button onclick="mkInvite()">Create link</button></div>
<div id="invites"></div>
<script>
const $=s=>document.querySelector(s);
async function load(){
  const st=await(await fetch('/api/stats')).json();
  $('#kpis').innerHTML=[['reviews',st.totals.reviews],['videos reviewed',st.totals.videos],['reviewers',st.totals.reviewers]]
    .map(([l,n])=>'<div class="kpi"><div class="n">'+n+'</div><div class="l">'+l+'</div></div>').join('');
  $('#vids').innerHTML='<table><tr><th>video</th><th>reviews</th><th>avg</th><th>verdicts</th><th>top issues</th><th></th></tr>'+
    st.videos.map(v=>'<tr><td><b>'+esc(v.title)+'</b><div class="note">'+v.moments+' flagged moments</div></td>'+
      '<td>'+v.count+'</td><td class="star">'+(v.avg?v.avg+' ★':'-')+'</td>'+
      '<td>'+Object.entries(v.verdicts).map(([k,n])=>'<span class="pill'+(/must|worth/.test(k)?' good':/not share|needs work/.test(k)?' bad':'')+'">'+esc(k)+' &times;'+n+'</span>').join('')+'</td>'+
      '<td>'+v.top_off.map(([k,n])=>'<span class="pill bad">'+esc(k)+' &times;'+n+'</span>').join('')+'</td>'+
      '<td><a href="/api/report?video='+encodeURIComponent(v.video_id)+'&title='+encodeURIComponent(v.title)+'" target="_blank">report</a></td></tr>').join('')+'</table>';
  $('#hot').innerHTML=st.hotspots.length?'<table><tr><th>video</th><th>slide</th><th>flags</th><th>sample notes</th></tr>'+
    st.hotspots.map(h=>'<tr><td>'+esc(h.video)+'</td><td><b>'+esc(h.beat_id)+'</b></td><td>'+h.count+'</td><td class="note">'+h.notes.map(esc).join('<br>')+'</td></tr>').join('')+'</table>'
    :'<p class="note">No slide-mapped moments yet.</p>';
  $('#chg').innerHTML=st.top_changes.length?st.top_changes.map(([k,n])=>'<span class="pill">'+esc(k)+' &times;'+n+'</span>').join(' '):'<p class="note">Nothing yet.</p>';
  loadInvites(); loadCols();
}
function esc(t){const d=document.createElement('i');d.textContent=t==null?'':String(t);return d.innerHTML}
async function loadInvites(){
  const d=await(await fetch('/api/invites')).json();
  $('#invites').innerHTML=(d.invites||[]).map(i=>'<p><b>'+esc(i.name)+'</b> <span class="note">'+esc(i.role||'')+' '+esc(i.email||'')+' &middot; '+esc(i.created)+'</span><br>'+
    '<span class="link">'+location.origin+'/?invite='+i.token+'</span> '+
    '<button class="ghost" onclick="navigator.clipboard.writeText(location.origin+\'/?invite=\'+\''+i.token+'\');this.textContent=\'copied\'">copy</button> '+
    '<button class="ghost" onclick="revoke(\''+i.token+'\')">revoke</button></p>').join('')||'<p class="note">No invites yet - create one above; the link signs the reviewer in AND fills their identity.</p>';
}
async function mkCol(){
  const r=await(await fetch('/api/collections',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({name:$('#cn').value,folder:$('#cf').value})})).json();
  if(r.ok){$('#cn').value='';$('#cf').value='';loadCols()}else alert(r.error);
}
async function loadCols(){
  const d=await(await fetch('/api/collections')).json();
  $('#cols').innerHTML='<table><tr><th>collection</th><th>type</th><th>visibility</th><th>assigned emails (private only)</th><th></th></tr>'+
    (d.collections||[]).map(c=>'<tr><td><b>'+esc(c.name)+'</b></td><td>'+esc(c.type)+'</td>'+
      '<td><button class="ghost" onclick="setVis(\''+c.id+'\',\''+(c.visibility==='public'?'private':'public')+'\')">'+
      (c.visibility==='public'?'<svg class="icn" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18"/></svg> public':'<svg class="icn" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="5" y="11" width="14" height="9" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/></svg> private')+'</button></td>'+
      '<td>'+(c.visibility==='private'?'<input style="min-width:260px" value="'+esc((c.allowed_emails||[]).join(', '))+'" onchange="setEmails(\''+c.id+'\',this.value)">':'<span class="note">everyone signed in</span>')+'</td>'+
      '<td>'+(c.id!=='col_uploads'?'<button class="ghost" onclick="delCol(\''+c.id+'\')">remove</button>':'')+'</td></tr>').join('')+'</table>';
}
async function setVis(id,v){await fetch('/api/collections',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({update:id,visibility:v})});loadCols()}
async function setEmails(id,v){await fetch('/api/collections',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({update:id,allowed_emails:v.split(',')})});loadCols()}
async function delCol(id){if(confirm('Remove this collection from the library?')){await fetch('/api/collections',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({delete:id})});loadCols()}}
async function saveAdmins(){
  const r=await(await fetch('/api/config',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({admin_emails:$('#adme').value}) })).json();
  if(r.ok)alert('saved');else alert(r.error||'failed');
}
async function mkInvite(){
  const r=await(await fetch('/api/invite',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({name:$('#in').value,role:$('#ir').value,email:$('#ie').value})})).json();
  if(r.ok){$('#in').value='';$('#ir').value='';$('#ie').value='';loadInvites()}else alert(r.error);
}
async function revoke(t){await fetch('/api/invite',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({revoke:t})});loadInvites()}
load();
</script></div></body></html>"""


PAGE = r"""<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>RedTee Screening Room</title>
<script>(function(){var t;try{t=localStorage.getItem('rt_theme')}catch(e){}
if(!t)t=window.matchMedia&&matchMedia('(prefers-color-scheme: light)').matches?'light':'dark';
document.documentElement.setAttribute('data-theme',t)})()</script><style>
/* ============ design tokens ============ */
:root{
  --bg:#0a0a0d;--bg-glow:#131018;
  --s0:#0e0e12;--s1:#141419;--s2:#1a1a21;--s3:#212129;      /* surface ladder */
  --ink:#f2f2f5;--ink2:#b9bcc6;--muted:#84879199;--muted-solid:#848791;--faint:#6b6e78;
  --red:#e5484d;--red-hi:#ff7d81;--red-deep:#b52d33;
  --gold:#f5c96b;--gold-dim:#8a7442;--ok:#3dd68c;
  --hair:#ffffff12;--hair-hi:#ffffff24;
  --glow:rgba(229,72,77,.20);--glow-soft:rgba(229,72,77,.09);
  --r-s:8px;--r-m:14px;--r-l:22px;
  --sh1:0 1px 2px rgba(0,0,0,.5);--sh2:0 8px 30px rgba(0,0,0,.45);--sh3:0 30px 90px rgba(0,0,0,.6);
  --spring:cubic-bezier(.34,1.56,.64,1);--ease:cubic-bezier(.22,.61,.36,1);
  --t-hero:clamp(26px,3.2vw,40px);--t-title:22px;--t-body:15px;--t-small:13px;--t-micro:11px;
  --nav-bg:rgba(10,10,13,.78);--star-off:#303038;--glowA:#15161d;--glowB:#100d14;
  --acc-bg:#2a1215;--acc-bd:#5c2226;--acc-ink:#ffb3b5;--acc-b:#ffd3d4;--wchip-ink:#ff9ea1;
  color-scheme:dark;
}
[data-theme="light"]{
  --bg:#f5f5f7;--bg-glow:#ececf2;
  --s0:#eceef2;--s1:#ffffff;--s2:#f2f3f6;--s3:#e4e6ec;
  --ink:#1b1e28;--ink2:#3d4250;--muted:#5d637099;--muted-solid:#5d6370;--faint:#9aa0ac;
  --red:#d63a40;--red-hi:#c92e35;--red-deep:#a92a30;
  --gold:#a67c1b;--gold-dim:#d9c08a;--ok:#1f9e63;
  --hair:#00000012;--hair-hi:#00000024;
  --glow:rgba(214,58,64,.18);--glow-soft:rgba(214,58,64,.08);
  --sh1:0 1px 2px rgba(30,34,50,.08);--sh2:0 8px 28px rgba(30,34,50,.12);--sh3:0 24px 70px rgba(30,34,50,.18);
  --nav-bg:rgba(248,248,250,.8);--star-off:#cdd0d8;--glowA:#e9e9f1;--glowB:#efe9ef;
  --acc-bg:#fdecec;--acc-bd:#f2c6c8;--acc-ink:#a03237;--acc-b:#7c2529;--wchip-ink:#b03a3f;
  color-scheme:light;
}
body{transition:background-color .3s,color .3s}
*{box-sizing:border-box}
::selection{background:var(--glow);color:#fff}
body{margin:0;color:var(--ink);font:var(--t-body)/1.6 Inter,"Segoe UI",system-ui,sans-serif;
  background:var(--bg);-webkit-font-smoothing:antialiased;text-rendering:optimizeLegibility;overflow-x:hidden}
body::before{content:"";position:fixed;inset:0;z-index:-1;pointer-events:none;
  background:radial-gradient(900px 480px at 80% -8%,var(--glowA) 0%,transparent 60%),
             radial-gradient(700px 500px at -10% 108%,var(--glowB) 0%,transparent 55%)}
::-webkit-scrollbar{width:10px}::-webkit-scrollbar-thumb{background:var(--s3);border-radius:6px;border:2px solid var(--bg)}
::-webkit-scrollbar-thumb:hover{background:var(--hair-hi)}
@keyframes rise{from{opacity:0;transform:translateY(18px)}to{opacity:1;transform:none}}
@keyframes riseS{from{opacity:0;transform:translateY(9px)}to{opacity:1;transform:none}}
@keyframes popin{0%{opacity:0;transform:scale(.7)}70%{transform:scale(1.05)}100%{opacity:1;transform:scale(1)}}
@keyframes shimmer{from{background-position:-500px 0}to{background-position:500px 0}}
@keyframes burst{0%{transform:scale(1)}40%{transform:scale(1.5) rotate(9deg)}100%{transform:scale(1)}}
@keyframes drawck{to{stroke-dashoffset:0}}
@keyframes ringin{from{transform:scale(.4);opacity:0}to{transform:scale(1);opacity:1}}
@keyframes floaty{0%,100%{transform:translateY(0)}50%{transform:translateY(-8px)}}
@keyframes toastin{0%{opacity:0;transform:translate(-50%,26px) scale(.94)}60%{transform:translate(-50%,-4px) scale(1.01)}100%{opacity:1;transform:translate(-50%,0)}}
@keyframes tbar{from{width:100%}to{width:0}}
@keyframes confetti{0%{transform:translate(0,0) scale(1);opacity:1}100%{transform:translate(var(--dx),var(--dy)) scale(.4) rotate(340deg);opacity:0}}
@keyframes marquee-glow{0%,100%{opacity:.65}50%{opacity:1}}
@keyframes spin{to{transform:rotate(360deg)}}
@keyframes slidein{from{opacity:0;transform:translateX(-14px);max-height:0}to{opacity:1;transform:none;max-height:80px}}
@keyframes viewin{from{opacity:0;transform:translateY(22px) scale(.992)}to{opacity:1;transform:none}}

/* ============ chrome ============ */
.icn{vertical-align:-3px}
.top{display:flex;align-items:center;gap:16px;padding:15px 34px;position:sticky;top:0;z-index:50;
  background:var(--nav-bg);backdrop-filter:blur(16px);-webkit-backdrop-filter:blur(16px);
  border-bottom:1px solid var(--hair);transition:opacity .5s var(--ease)}
.logo{width:38px;height:38px;border-radius:11px;background:linear-gradient(135deg,var(--red),var(--red-deep));
  display:grid;place-items:center;font-weight:800;font-size:16px;color:#fff;box-shadow:0 4px 18px var(--glow);
  transition:transform .35s var(--spring)}
.logo:hover{transform:rotate(-7deg) scale(1.1)}
.brand h1{font-size:15.5px;margin:0;font-weight:750;letter-spacing:.3px}
.brand .sub{color:var(--muted-solid);font-size:11.5px;letter-spacing:.5px;text-transform:uppercase;margin-top:1px}
.sp{flex:1}
.btn{position:relative;overflow:hidden;background:var(--s1);border:1px solid var(--hair);color:var(--ink);
  border-radius:var(--r-s);padding:9px 16px;font-size:var(--t-small);font-weight:650;cursor:pointer;text-decoration:none;
  transition:transform .18s var(--spring),border-color .22s,box-shadow .25s,background .22s;display:inline-flex;align-items:center;gap:8px}
.btn:hover{border-color:var(--hair-hi);background:var(--s2);transform:translateY(-1px);box-shadow:var(--sh2)}
.btn:active{transform:translateY(0) scale(.965)}
.btn.primary{background:linear-gradient(135deg,var(--red),var(--red-deep));border-color:transparent;color:#fff;box-shadow:0 4px 18px var(--glow)}
.btn.primary:hover{box-shadow:0 10px 30px var(--glow);filter:brightness(1.08)}
.btn.primary:disabled{opacity:.6;cursor:default;transform:none}
.btn.ghost{background:transparent;border-color:transparent;color:var(--ink2)}
.btn.ghost:hover{color:var(--ink);background:var(--s1);box-shadow:none}
.btn:focus-visible,.tx:focus-visible,.seg b:focus-visible{outline:2px solid var(--red);outline-offset:2px}
.ripple{position:absolute;border-radius:50%;background:rgba(255,255,255,.25);transform:scale(0);pointer-events:none;animation:rip .55s var(--ease) forwards}
@keyframes rip{to{transform:scale(3.2);opacity:0}}
.spinner{width:14px;height:14px;border:2px solid rgba(255,255,255,.3);border-top-color:#fff;border-radius:50%;animation:spin .7s linear infinite}
.chip{background:var(--s0);border:1px solid var(--hair);border-radius:20px;padding:2px 11px;font-size:var(--t-micro);color:var(--muted-solid);letter-spacing:.4px}
.chip.gold{color:var(--gold);border-color:var(--gold-dim)}

/* ============ view switching ============ */
.view{display:none;max-width:1360px;margin:0 auto;padding:34px 34px 140px}
.view.on{display:block;animation:viewin .5s var(--ease) both}

/* ============ LOBBY ============ */
.lobby-head{display:flex;align-items:end;gap:20px;margin:8px 0 26px;flex-wrap:wrap}
.lobby-head h2{font-size:var(--t-hero);line-height:1.12;margin:0;font-weight:800;letter-spacing:-.5px}
.lobby-head h2 em{font-style:normal;background:linear-gradient(100deg,var(--red-hi),var(--gold));-webkit-background-clip:text;background-clip:text;color:transparent}
.lobby-head p{color:var(--muted-solid);margin:6px 0 0;font-size:14.5px;max-width:520px}
.lobby-tools{display:flex;gap:10px;align-items:center;margin-left:auto}
.search{background:var(--s1);border:1px solid var(--hair);border-radius:10px;color:var(--ink);
  padding:11px 15px;font-size:14px;width:280px;transition:border-color .25s,box-shadow .25s,width .3s var(--ease)}
.search:focus{outline:none;border-color:var(--red);box-shadow:0 0 0 4px var(--glow-soft);width:330px}
.search::placeholder{color:var(--muted-solid)}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:20px}
.pcard{position:relative;background:var(--s1);border:1px solid var(--hair);border-radius:var(--r-l);overflow:hidden;cursor:pointer;
  transition:transform .28s var(--spring),border-color .25s,box-shadow .3s;animation:rise .5s var(--ease) both}
.pcard:hover{transform:translateY(-5px);border-color:var(--hair-hi);box-shadow:var(--sh3)}
.pcard:hover .marq{opacity:1}
.pcard .poster{position:relative;aspect-ratio:16/9;background:linear-gradient(145deg,#17171d,#0d0d11);display:grid;place-items:center;overflow:hidden}
.pcard .poster::before{content:"";position:absolute;inset:0;
  background:repeating-linear-gradient(115deg,transparent 0 26px,#ffffff05 26px 27px);opacity:.9}
.pcard .slate{position:absolute;inset:0;display:grid;place-items:center;font-size:56px;font-weight:800;
  letter-spacing:3px;color:#ffffff0d;user-select:none;transform:translateY(-6px)}
.pcard .scrim{position:absolute;inset:auto 0 0 0;height:56%;
  background:linear-gradient(to top,rgba(6,6,9,.72),transparent);pointer-events:none}
.pcard .dchip{position:absolute;right:12px;bottom:11px;z-index:2;background:rgba(8,8,11,.75);border:1px solid var(--hair);
  backdrop-filter:blur(4px);border-radius:7px;padding:2px 9px;font-size:11.5px;font-weight:650;color:var(--ink2)}
.pcard .poster img{position:absolute;inset:0;width:100%;height:100%;object-fit:cover;opacity:.85;transition:transform .5s var(--ease),opacity .3s}
.pcard:hover .poster img{transform:scale(1.05);opacity:1}
.pcard .playbtn{position:relative;z-index:2;width:58px;height:58px;border-radius:50%;background:rgba(10,10,13,.66);border:1px solid var(--hair-hi);
  backdrop-filter:blur(6px);display:grid;place-items:center;color:#fff;
  transition:transform .3s var(--spring),background .25s,box-shadow .3s}
.pcard .playbtn svg{display:block;transform:translateX(1.5px)}
.pcard:hover .playbtn{transform:scale(1.14);background:var(--red);box-shadow:0 8px 30px var(--glow)}
.marq{position:absolute;inset:auto 0 0 0;height:3px;background:linear-gradient(90deg,transparent,var(--red),var(--gold),var(--red),transparent);
  opacity:0;transition:opacity .3s;animation:marquee-glow 2.2s ease-in-out infinite}
.pcard .pinfo{padding:16px 18px 17px}
.pcard .pname{font-weight:700;font-size:15.5px;letter-spacing:-.1px;line-height:1.35;display:-webkit-box;
  -webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden;min-height:2.7em}
.pcard .pmeta{display:flex;gap:9px;align-items:center;margin-top:8px;color:var(--muted-solid);font-size:12px}
.pcard .stars-s{color:var(--gold);letter-spacing:1px;font-size:12px}
.skel{border-radius:var(--r-l);border:1px solid var(--hair);aspect-ratio:16/11;
  background:linear-gradient(90deg,var(--s1) 0%,var(--s2) 50%,var(--s1) 100%);background-size:500px 100%;animation:shimmer 1.1s linear infinite}
.empty{background:var(--s1);border:1px dashed var(--hair-hi);border-radius:var(--r-l);padding:40px;color:var(--muted-solid);
  font-size:14px;line-height:1.8;text-align:center;grid-column:1/-1;animation:rise .4s var(--ease) both}
.empty code{background:var(--s0);padding:2px 8px;border-radius:6px;font-size:12.5px;color:var(--ink2)}
.setup{grid-column:1/-1;max-width:640px;margin:20px auto;background:var(--s1);border:1px solid var(--hair);
  border-radius:var(--r-l);padding:34px 38px;animation:rise .45s var(--ease) both;box-shadow:var(--sh2)}
.setup h3{font-size:20px;letter-spacing:-.3px;text-transform:none;color:var(--ink);font-weight:800;margin:0 0 6px}
.setup .lead{color:var(--muted-solid);font-size:13.5px;margin:0 0 22px;line-height:1.7}
.setup label.f{margin-top:16px}
.setup .or{display:flex;align-items:center;gap:12px;color:var(--faint);font-size:11px;letter-spacing:1.6px;margin:20px 0 4px}
.setup .or::before,.setup .or::after{content:"";flex:1;height:1px;background:var(--hair)}
.setup .foot{display:flex;align-items:center;gap:12px;margin-top:22px}
.setup .tip{font-size:12px;color:var(--faint);line-height:1.6;margin-top:14px}

/* ============ SCREENING ============ */
.screen-wrap{max-width:1180px;margin:0 auto}
.backrow{display:flex;align-items:center;gap:12px;margin-bottom:18px}
.nowshow{font-size:var(--t-micro);letter-spacing:2.6px;text-transform:uppercase;color:var(--gold);font-weight:750}
.mtitle{font-size:var(--t-title);font-weight:800;letter-spacing:-.3px;margin:2px 0 0}
.theater{position:relative;border-radius:var(--r-l);overflow:hidden;background:#000;box-shadow:var(--sh3);border:1px solid var(--hair)}
.frame{position:relative;width:100%;aspect-ratio:16/9;background:#000}
.frame iframe{position:absolute;inset:0;width:100%;height:100%;border:0;opacity:0;transition:opacity .55s var(--ease)}
.frame iframe.ready{opacity:1}
.frame::after{content:"";position:absolute;inset:0;pointer-events:none;z-index:2;
  box-shadow:inset 0 0 90px 12px rgba(0,0,0,.42);border-radius:inherit}
.frame .loading{position:absolute;inset:0;display:grid;place-items:center}
.frame .loading .spinner{width:36px;height:36px;border-width:3px;border-color:rgba(255,255,255,.12);border-top-color:var(--red)}
.tbar{display:flex;align-items:center;gap:14px;padding:14px 20px;background:var(--s0);border-top:1px solid var(--hair)}
.tbar .chip{flex:none}
.acc-banner{display:none;align-items:center;gap:12px;background:var(--acc-bg);border:1px solid var(--acc-bd);color:var(--acc-ink);
  border-radius:var(--r-m);padding:13px 18px;margin-top:14px;font-size:13.5px;line-height:1.5;animation:riseS .4s var(--ease) both}
.acc-banner.on{display:flex}
.acc-banner b{color:var(--acc-b)}
.acc-banner .btn{flex:none}
.wchip{background:var(--acc-bg);border:1px solid var(--acc-bd);color:var(--wchip-ink);border-radius:20px;padding:1px 9px;font-size:11px;font-weight:650}
.badge{background:var(--s0);border:1px solid var(--hair);border-radius:20px;padding:1px 9px;font-size:11px;color:var(--muted-solid)}
.upnext{display:flex;gap:10px;overflow-x:auto;padding:16px 2px 4px}
.un{flex:none;display:flex;align-items:center;gap:10px;background:var(--s1);border:1px solid var(--hair);border-radius:12px;
  padding:9px 14px;font-size:12.5px;color:var(--ink2);cursor:pointer;max-width:260px;transition:all .22s var(--ease)}
.un:hover{border-color:var(--hair-hi);color:var(--ink);transform:translateY(-2px)}
.un b{white-space:nowrap;overflow:hidden;text-overflow:ellipsis;font-weight:600}
.un .pl{color:var(--red-hi);display:grid;place-items:center}
.un .pl svg{display:block}

/* lights-down: dim everything except the theater */
body.dark2 .top,body.dark2 .backrow,body.dark2 .upnext,body.dark2 .stagebar,body.dark2 .revwrap{opacity:.14;transition:opacity .6s var(--ease)}
body.dark2 .theater{box-shadow:0 0 120px 10px rgba(0,0,0,.9),var(--sh3)}
.revwrap,.stagebar,.upnext,.backrow{transition:opacity .5s var(--ease)}

/* stage bar: watching -> reviewing */
.stagebar{display:flex;align-items:center;gap:16px;background:var(--s1);border:1px solid var(--hair);border-radius:var(--r-m);
  padding:16px 22px;margin-top:20px;animation:riseS .45s var(--ease) both}
.stagebar .msg{flex:1;color:var(--ink2);font-size:14px}
.stagebar .msg b{color:var(--ink)}

/* ============ review panel ============ */
.revwrap{display:none;grid-template-columns:200px minmax(0,1fr);gap:26px;margin-top:26px}
.revwrap.on{display:grid;animation:rise .5s var(--ease) both}
@media(max-width:900px){.revwrap.on{grid-template-columns:1fr}.stepper{display:none}}
.stepper{position:sticky;top:96px;align-self:start;display:flex;flex-direction:column;gap:2px}
.step{display:flex;align-items:center;gap:11px;padding:10px 12px;border-radius:10px;color:var(--muted-solid);
  font-size:13px;font-weight:600;cursor:pointer;border:1px solid transparent;transition:all .22s var(--ease)}
.step .dot{width:9px;height:9px;border-radius:50%;background:var(--s3);border:1.5px solid var(--faint);transition:all .25s var(--spring);flex:none}
.step:hover{color:var(--ink);background:var(--s1)}
.step.here{color:var(--ink);background:var(--s1);border-color:var(--hair)}
.step.here .dot{border-color:var(--red);box-shadow:0 0 0 3px var(--glow-soft)}
.step.donez .dot{background:var(--ok);border-color:var(--ok)}
.filmstrip{margin-top:16px;padding:13px 12px;background:var(--s1);border:1px solid var(--hair);border-radius:var(--r-m)}
.filmstrip .cells{display:flex;gap:4px;margin-bottom:8px}
.filmstrip .cell{flex:1;height:16px;border-radius:3px;background:var(--s3);border:1px solid var(--hair);transition:all .4s var(--ease)}
.filmstrip .cell.lit{background:linear-gradient(135deg,var(--red),var(--gold));border-color:transparent;box-shadow:0 0 10px var(--glow)}
.filmstrip .ftxt{font-size:11.5px;color:var(--muted-solid);font-weight:650;transition:color .3s}
.filmstrip .ftxt.good{color:var(--gold)}
.rev{background:var(--s1);border:1px solid var(--hair);border-radius:var(--r-l);padding:30px 32px;box-shadow:var(--sh1)}
.sec{margin:30px 0 0;padding-top:26px;border-top:1px solid var(--hair);opacity:0;animation:rise .5s var(--ease) both;animation-delay:calc(var(--d,0)*90ms);scroll-margin-top:100px}
.sec:first-of-type{margin-top:0;padding-top:0;border-top:0}
.sec h4{margin:0 0 3px;font-size:16.5px;font-weight:750;letter-spacing:-.2px}
.sec .why{color:var(--muted-solid);font-size:12.5px;margin:0 0 16px}
.grid3{display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px}
@media(max-width:760px){.grid3{grid-template-columns:1fr}}
label.f{display:block;font-size:11.5px;color:var(--muted-solid);font-weight:700;letter-spacing:.3px;margin-bottom:6px;transition:color .2s}
.fw:focus-within label.f{color:var(--red-hi)}
input.tx,textarea.tx{width:100%;background:var(--s0);border:1px solid var(--hair);border-radius:10px;color:var(--ink);
  padding:11px 13px;font-size:14px;font-family:inherit;transition:border-color .22s,box-shadow .22s}
textarea.tx{min-height:76px;resize:vertical}
input.tx:focus,textarea.tx:focus{outline:none;border-color:var(--red);box-shadow:0 0 0 4px var(--glow-soft)}
input.tx::placeholder,textarea.tx::placeholder{color:var(--faint)}
.dim{display:flex;align-items:center;gap:12px;margin-bottom:10px}
.dim .dl{width:132px;font-size:13px;color:var(--ink2);font-weight:600;flex:none}
.stars{display:flex;gap:7px;font-size:34px;cursor:pointer;user-select:none}
.stars span{color:var(--star-off);transition:color .15s,transform .18s var(--spring);display:inline-block}
.stars span.on,.stars span.hov{color:var(--gold);text-shadow:0 0 20px rgba(245,201,107,.4)}
.stars span:hover{transform:scale(1.22) rotate(-6deg)}
.stars span.bang{animation:burst .5s var(--spring)}
.slabel{font-size:12.5px;color:var(--muted-solid);margin-left:10px;min-width:100px;transition:color .2s}
.slabel.set{color:var(--gold);font-weight:650}
.seg{display:flex;gap:6px;flex:1;max-width:430px}
.seg b{flex:1;text-align:center;background:var(--s0);border:1px solid var(--hair);border-radius:9px;padding:7px 0;
  font-size:12.5px;font-weight:650;color:var(--muted-solid);cursor:pointer;transition:all .2s var(--ease);position:relative;overflow:hidden}
.seg b:hover{border-color:var(--hair-hi);color:var(--ink);transform:translateY(-1px)}
.seg b.on{background:linear-gradient(135deg,var(--red),var(--red-deep));border-color:transparent;color:#fff;box-shadow:0 3px 14px var(--glow);animation:popin .3s var(--spring)}
.pillq{margin-bottom:18px}
.pillq .ql{font-size:13px;color:var(--ink2);font-weight:650;margin-bottom:9px}
.pillq .ql em{font-style:normal;color:var(--faint);font-weight:500;font-size:11.5px;margin-left:6px}
.pills{display:flex;gap:8px;flex-wrap:wrap}
.pill{position:relative;overflow:hidden;background:var(--s0);border:1px solid var(--hair);border-radius:20px;
  padding:8px 16px;font-size:13px;font-weight:600;color:var(--muted-solid);cursor:pointer;
  transition:all .2s var(--ease);user-select:none}
.pill:hover{border-color:var(--hair-hi);color:var(--ink);transform:translateY(-1px)}
.pill.on{background:linear-gradient(135deg,var(--red),var(--red-deep));border-color:transparent;color:#fff;
  box-shadow:0 3px 14px var(--glow);animation:popin .28s var(--spring)}
.pill.on.good{background:linear-gradient(135deg,#1f8a5a,#136843);box-shadow:0 3px 14px rgba(61,214,140,.25)}
.mrow{display:flex;gap:10px;margin-bottom:9px;animation:slidein .32s var(--ease) both;flex-wrap:wrap;align-items:center}
.mrow .tags{display:flex;gap:6px;flex-wrap:wrap;flex:1;min-width:220px}
.mrow .tags .pill{padding:6px 13px;font-size:12px}
.mrow .detail{flex-basis:100%;display:none}
.mrow .detail.on{display:block;animation:riseS .3s var(--ease) both}
.mrow.out{transition:all .25s var(--ease);opacity:0;transform:translateX(14px);max-height:0;margin:0;overflow:hidden}
.mrow input.at{width:96px;flex:none;text-align:center}
.mrow .seek{background:none;border:none;color:var(--faint);cursor:pointer;font-size:13px;width:30px;border-radius:8px;transition:all .2s}
.mrow .seek:hover{color:var(--gold);background:var(--glow-soft)}
.mrow .del{background:none;border:none;color:var(--faint);cursor:pointer;font-size:17px;border-radius:8px;width:34px;transition:all .2s}
.mrow .del:hover{color:var(--red-hi);background:var(--glow-soft);transform:scale(1.12)}
.addm{background:none;border:1px dashed var(--hair-hi);border-radius:10px;color:var(--muted-solid);padding:9px 16px;font-size:13px;cursor:pointer;transition:all .22s var(--ease)}
.slidecard{display:none;margin-top:16px;background:var(--s0);border:1px solid var(--hair);border-radius:var(--r-m);overflow:hidden;animation:riseS .35s var(--ease) both}
.slidecard.on{display:block}
.slidecard .simg{aspect-ratio:16/9;background:#0d0e12;display:grid;place-items:center;border-bottom:1px solid var(--hair)}
.slidecard .simg img{width:100%;height:100%;object-fit:contain}
.slidecard .scap{display:flex;align-items:center;gap:10px;padding:10px 15px;font-size:12.5px;color:var(--muted-solid)}
.slidecard .scap b{color:var(--ink);font-weight:700}
.slidecard .scap .chip{margin-left:auto}
.linkrow{display:flex;align-items:center;gap:10px;margin:0 0 14px;font-size:12.5px;color:var(--muted-solid);flex-wrap:wrap}
.linkrow select{background:var(--s0);border:1px solid var(--hair);border-radius:9px;color:var(--ink);padding:7px 10px;font-size:12.5px;max-width:280px}
.addm:hover{border-color:var(--red);color:var(--ink);background:var(--glow-soft);transform:translateY(-1px)}
.footer{display:flex;align-items:center;gap:14px;margin-top:28px}
.hint{color:var(--muted-solid);font-size:12.5px}
.draft{font-size:11.5px;color:var(--faint);margin-left:auto;transition:color .3s}
.draft.saved{color:var(--ok)}

/* past reviews + toast + done */
.pastgrid{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-top:14px}
@media(max-width:760px){.pastgrid{grid-template-columns:1fr}}
.prev{background:var(--s0);border:1px solid var(--hair);border-radius:12px;padding:15px 17px;font-size:13.5px;
  animation:rise .4s var(--ease) both;transition:border-color .2s,transform .2s}
.prev:hover{border-color:var(--hair-hi);transform:translateY(-2px)}
.prev .who{color:var(--muted-solid);font-size:11.5px;margin-bottom:6px}
.prev .stars-s{color:var(--gold);letter-spacing:2px}
.toast{position:fixed;bottom:28px;left:50%;transform:translateX(-50%);background:var(--s2);border:1px solid var(--ok);
  color:var(--ink);border-radius:13px;padding:14px 22px 16px;font-size:14px;display:none;z-index:99;box-shadow:var(--sh3);overflow:hidden}
.toast.show{display:block;animation:toastin .45s var(--spring) both}
.toast.bad{border-color:var(--red)}
.toast .tprog{position:absolute;left:0;bottom:0;height:3px;background:var(--ok);animation:tbar 3.4s linear forwards}
.toast.bad .tprog{background:var(--red)}
.done{text-align:center;padding:46px 20px;background:var(--s1);border:1px solid var(--hair);border-radius:var(--r-l);margin-top:26px;animation:rise .45s var(--ease) both}
.done .ckwrap{width:86px;height:86px;margin:0 auto 6px;position:relative;animation:ringin .5s var(--spring) both}
.done svg circle{stroke:var(--ok);stroke-width:3;fill:none;stroke-dasharray:264;stroke-dashoffset:264;animation:drawck .7s var(--ease) .15s forwards}
.done svg path{stroke:var(--ok);stroke-width:5;fill:none;stroke-linecap:round;stroke-linejoin:round;stroke-dasharray:60;stroke-dashoffset:60;animation:drawck .45s var(--ease) .6s forwards}
.done h4{font-size:19px;margin:14px 0 6px}
.done p{color:var(--muted-solid);margin:0 0 20px}
.conf{position:absolute;width:9px;height:9px;border-radius:2px;left:50%;top:50%;animation:confetti .9s var(--ease) forwards}
@media (prefers-reduced-motion: reduce){*,*::before,*::after{animation-duration:.001s !important;transition-duration:.001s !important}}
</style></head><body>
<div class="top">
  <div class="logo" onclick="goLobby()">R</div>
  <div class="brand"><h1>RedTee Screening Room</h1><div class="sub">private preview</div></div>
  <div class="sp"></div>
  <button class="btn ghost themebtn" onclick="toggleTheme()" title="light / dark"></button>
  <span class="chip" id="whoami" style="display:none"></span>
  <span class="chip" id="modebadge"></span>
  <a class="btn ghost" id="signout" href="/logout" style="display:none">Sign out</a>
  <button class="btn ghost" id="keybtn" style="display:none" onclick="setKey()" title="add or update the Drive API key">&#9881; API key</button>
  <button class="btn ghost" onclick="loadVideos(true)">&#8635; Refresh</button>
  <a class="btn ghost" href="/api/export.csv">&#8681; Export CSV</a>
</div>

<!-- ================= LOBBY ================= -->
<div class="view on" id="v-lobby">
  <div class="lobby-head">
    <div>
      <h2>Tonight's <em>screenings</em></h2>
      <p>Pick a lesson, watch it end to end, then tell us the truth about it. Honest reviews shape the next ones.</p>
    </div>
    <div class="lobby-tools">
      <input class="search" id="q" placeholder="Search the library...  ( / )" oninput="renderLib()">
      <span class="chip" id="libn"></span>
      <input type="file" id="upfile" accept=".mp4,.webm" style="display:none" onchange="uploadVideo(this)">
      <button class="btn" id="upbtn" style="display:none" onclick="document.getElementById('upfile').click()">&#8679; Upload video</button>
      <a class="btn ghost" id="adminlink" href="/admin" style="display:none">Admin</a>
    </div>
  </div>
  <div class="grid" id="cards"></div>
</div>

<!-- ================= SCREENING ================= -->
<div class="view" id="v-screen">
  <div class="screen-wrap">
    <div class="backrow">
      <button class="btn ghost" onclick="goLobby()">&larr; Library</button>
      <div style="flex:1;min-width:0">
        <div class="nowshow">Now showing</div>
        <div class="mtitle" id="ptitle"></div>
      </div>
      <span class="chip" id="pstats"></span>
      <a class="btn ghost" id="repbtn" target="_blank"><svg class="icn" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6M9 13h6M9 17h4"/></svg> Feedback report</a>
      <button class="btn ghost" id="lights" onclick="toggleLights()"><svg class="icn" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z"/></svg> Lights down</button>
    </div>
    <div class="theater">
      <div class="frame">
        <div class="loading" id="loading"><div class="spinner"></div></div>
        <iframe id="pframe" allow="autoplay; fullscreen" allowfullscreen></iframe>
        <video id="pvideo" controls preload="metadata" playsinline style="display:none;position:absolute;inset:0;width:100%;height:100%;background:#000"></video>
      </div>
      <div class="tbar">
        <span class="chip" id="tdur"></span>
        <span class="chip gold" id="poschip" style="display:none"></span>
        <div class="sp"></div>
        <span class="chip" id="tiphint"></span>
        <a class="btn ghost" id="odrive" target="_blank" rel="noopener">Open in Drive &#8599;</a>
      </div>
    </div>
    <div class="acc-banner" id="accbanner">
      <span>&#9888;</span>
      <span style="flex:1">This video is <b>not shared publicly</b>, so the player shows "file does not exist".
        Open it in Drive &rarr; Share &rarr; <b>Anyone with the link</b> (viewer), then hit &#8635; Refresh here.</span>
      <a class="btn" id="accfix" target="_blank" rel="noopener">Open sharing &#8599;</a>
    </div>
    <div class="upnext" id="upnext"></div>

    <div class="stagebar" id="stagebar">
      <div class="msg" id="stagemsg">Watching? Take your time. <b>Jot moments below as they strike you</b> - the full review opens when you are done.</div>
      <button class="btn primary" id="stagebtn" onclick="startReview()">I finished watching &rarr;</button>
    </div>

    <div class="rev" id="watchnotes" style="margin-top:20px">
      <div class="sec" style="--d:0">
        <h4>Moments worth flagging</h4>
        <p class="why">While it is fresh: a slide that confused you, a reveal you loved, audio that dipped. Timestamps like 2:35.</p>
        <div class="linkrow" id="linkrow"></div>
        <div id="moments"></div>
        <button class="addm" onclick="addMoment(true)">+ flag a moment</button>
        <div class="slidecard" id="slidecard">
          <div class="simg"><img id="slideimg" alt="slide preview"></div>
          <div class="scap"><svg class="icn" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M20.2 6 3 11l-.9-2.4c-.3-1.1.3-2.2 1.4-2.5l13.5-4c1.1-.3 2.2.3 2.5 1.4zM6.2 5.3l3.1 3.9M12.4 3.4l3.2 4M3 11h18v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/></svg><span id="slidecap"></span><span class="chip">check this is the slide you mean</span></div>
        </div>
      </div>
    </div>

    <div class="revwrap" id="revwrap">
      <div>
        <div class="stepper" id="stepper"></div>
        <div class="filmstrip"><div class="cells" id="fcells"></div><div class="ftxt" id="ftxt"></div></div>
      </div>
      <div class="rev" id="form">
        <div class="sec" data-step="Who" id="s-who" style="--d:0">
          <h4>Who is watching</h4>
          <p class="why">Remembered on this device, so you only type it once. Email optional.</p>
          <div class="grid3">
            <div class="fw"><label class="f">NAME</label><input class="tx" id="r_name" placeholder="Ada"></div>
            <div class="fw"><label class="f">ROLE / TEAM</label><input class="tx" id="r_role" placeholder="Sales enablement"></div>
            <div class="fw"><label class="f">EMAIL (OPTIONAL)</label><input class="tx" id="r_email" placeholder="ada@company.com"></div>
          </div>
        </div>
        <div class="sec" data-step="Signals" id="s-signals" style="--d:1">
          <h4>Quick signals</h4>
          <p class="why">Gut answers. Do not overthink these.</p>
          <div class="dim"><div class="dl">Watched it...</div><div class="seg" data-sig="watched_full"><b data-v="fully">fully</b><b data-v="most">most of it</b><b data-v="skimmed">skimmed</b></div></div>
          <div class="dim"><div class="dl">Watch another?</div><div class="seg" data-sig="watch_again"><b data-v="yes">yes</b><b data-v="maybe">maybe</b><b data-v="no">no</b></div></div>
          <div class="dim"><div class="dl">Recommend it?</div><div class="seg" data-sig="recommend"><b data-v="yes">yes</b><b data-v="maybe">maybe</b><b data-v="no">no</b></div></div>
        </div>
        <div class="sec" data-step="Scores" id="s-scores" style="--d:2">
          <h4>Scores</h4>
          <p class="why">Overall first, then the parts. 1 = poor, 5 = excellent.</p>
          <div class="dim"><div class="dl">Overall</div><div class="stars" id="stars"><span data-v="1">&#9733;</span><span data-v="2">&#9733;</span><span data-v="3">&#9733;</span><span data-v="4">&#9733;</span><span data-v="5">&#9733;</span></div><span class="slabel" id="slabel"></span></div>
          <div id="dims"></div>
        </div>
        <div class="sec" data-step="In your words" id="s-words" style="--d:3">
          <h4>The verdict</h4>
          <p class="why">Tap what fits - one optional line at the end for anything the chips miss.</p>
          <div class="pillq"><div class="ql">Would you send this to a colleague? <em>pick one</em></div>
            <div class="pills" data-q="pitch" data-single="1">
              <span class="pill good" data-v="must watch">must watch</span>
              <span class="pill good" data-v="worth their time">worth their time</span>
              <span class="pill" data-v="fine, but skippable">fine, but skippable</span>
              <span class="pill" data-v="needs work first">needs work first</span>
              <span class="pill" data-v="would not share it">would not share it</span>
            </div></div>
          <div class="pillq"><div class="ql">What stayed with you? <em>pick any</em></div>
            <div class="pills" data-q="stayed">
              <span class="pill" data-v="the big idea">the big idea</span>
              <span class="pill" data-v="the visuals">the visuals</span>
              <span class="pill" data-v="the examples">the examples</span>
              <span class="pill" data-v="the voice">the voice</span>
              <span class="pill" data-v="a specific slide">a specific slide</span>
              <span class="pill" data-v="the pacing">the pacing</span>
              <span class="pill" data-v="honestly, not much">honestly, not much</span>
            </div></div>
          <div class="pillq"><div class="ql">Did anything feel off? <em>pick any</em></div>
            <div class="pills" data-q="off">
              <span class="pill good" data-v="nothing felt off">nothing felt off</span>
              <span class="pill" data-v="narration sounded robotic">narration sounded robotic</span>
              <span class="pill" data-v="slides too busy">slides too busy</span>
              <span class="pill" data-v="too slow">too slow</span>
              <span class="pill" data-v="too fast">too fast</span>
              <span class="pill" data-v="animations distracting">animations distracting</span>
              <span class="pill" data-v="audio mix">audio mix</span>
              <span class="pill" data-v="content too shallow">content too shallow</span>
              <span class="pill" data-v="content too dense">content too dense</span>
              <span class="pill" data-v="i got lost somewhere">i got lost somewhere</span>
            </div></div>
          <div class="pillq"><div class="ql">The ONE change before showing a customer <em>pick one</em></div>
            <div class="pills" data-q="change" data-single="1">
              <span class="pill good" data-v="nothing major">nothing major</span>
              <span class="pill" data-v="tighten the pacing">tighten the pacing</span>
              <span class="pill" data-v="simplify the slides">simplify the slides</span>
              <span class="pill" data-v="more concrete examples">more concrete examples</span>
              <span class="pill" data-v="better narration voice">better narration voice</span>
              <span class="pill" data-v="stronger opening">stronger opening</span>
              <span class="pill" data-v="clearer takeaways">clearer takeaways</span>
              <span class="pill" data-v="make it shorter">make it shorter</span>
            </div></div>
          <div class="fw"><label class="f">ANYTHING THE CHIPS MISSED? (OPTIONAL)</label>
          <textarea class="tx" id="a_anything_else"></textarea></div>
        </div>
        <div class="footer">
          <button class="btn primary" id="submit" onclick="submitReview()">Submit review</button>
          <span class="hint">Overall score + at least one written answer.</span>
          <span class="draft" id="draft"></span>
        </div>
      </div>
    </div>

    <div class="done" id="thanks" style="display:none">
      <div class="ckwrap" id="ckwrap"><svg viewBox="0 0 90 90" width="86" height="86"><circle cx="45" cy="45" r="42"/><path d="M28 46 l12 12 l24 -26"/></svg></div>
      <h4>Review filed. Thank you.</h4>
      <p>Your feedback goes straight into how the next videos get made.</p>
      <button class="btn primary" onclick="resetForm()">Review again</button>
      <button class="btn" onclick="nextVideo()">Next screening &rarr;</button>
      <button class="btn ghost" onclick="goLobby()">Back to library</button>
    </div>

    <div class="rev" id="pastwrap" style="display:none;margin-top:26px">
      <div class="sec"><h4>What others said</h4><div class="pastgrid" id="pastlist"></div></div>
    </div>
  </div>
</div>
<div class="toast" id="toast"><span id="toastmsg"></span><div class="tprog"></div></div>
<script>
const $=s=>document.querySelector(s);
function toggleTheme(){var h=document.documentElement;var t=h.getAttribute('data-theme')==='light'?'dark':'light';
h.setAttribute('data-theme',t);try{localStorage.setItem('rt_theme',t)}catch(e){}
document.querySelectorAll('.themebtn').forEach(b=>b.innerHTML=t==='light'?'<svg class="icn" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z"/></svg>':'<svg class="icn" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/></svg>')}
document.addEventListener('DOMContentLoaded',()=>{var t=document.documentElement.getAttribute('data-theme');
document.querySelectorAll('.themebtn').forEach(b=>b.innerHTML=t==='light'?'<svg class="icn" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z"/></svg>':'<svg class="icn" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/></svg>')});
let VIDEOS=[], CUR=null, OVERALL=0, LIGHTS=false, IS_ADMIN=false;
const DIMS=[["clarity","Teaching clarity"],["visuals","Slide design"],["narration","Voice + narration"],["pacing","Pacing"],["animations","Animations + reveals"],["audio","Audio mix"]];
const SIGS={}, RATINGS={}, PICKS={pitch:"",stayed:[],off:[],change:""};
const SLBL={1:"rough",2:"needs work",3:"decent",4:"good",5:"excellent"};
const PLAY_SVG='<svg viewBox="0 0 24 24" width="21" height="21" aria-hidden="true"><path d="M8.2 5.6c0-.9 1-1.5 1.8-1l9.4 5.9c.8.5.8 1.6 0 2.1l-9.4 5.9c-.8.5-1.8-.1-1.8-1V5.6z" fill="currentColor"/></svg>';
const PLAY_SVG_S='<svg viewBox="0 0 24 24" width="13" height="13" aria-hidden="true"><path d="M8.2 5.6c0-.9 1-1.5 1.8-1l9.4 5.9c.8.5.8 1.6 0 2.1l-9.4 5.9c-.8.5-1.8-.1-1.8-1V5.6z" fill="currentColor"/></svg>';
async function setKey(){
  const k=prompt('Google Drive API key (adds durations, sharing checks and the most reliable stream).\nLeave empty to keep the current one.');
  if(k===null||!k.trim())return;
  const r=await(await fetch('/api/config',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({api_key:k.trim()})})).json();
  if(r.ok){toast('API key saved - reloading the library');VIDEOS=[];loadVideos(true)}
  else toast(r.error||'could not save',true);
}
async function connectGoogle(){
  const cid=$('#su_cid').value.trim(), sec=$('#su_csec').value.trim(), fol=$('#su_folder').value.trim();
  if(!cid||!sec)return toast('paste the OAuth client id AND secret first',true);
  const r=await(await fetch('/api/config',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({oauth_client_id:cid,oauth_client_secret:sec,folder:fol})})).json();
  if(!r.ok&&r.error)return toast(r.error,true);
  location.href='/oauth/start';
}
async function saveSetup(){
  const btn=$('#su_go'), msg=$('#su_msg');
  btn.disabled=true; btn.innerHTML='<span class="spinner"></span> Scanning...'; msg.textContent='';
  try{
    const r=await(await fetch('/api/config',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({folder:$('#su_folder').value.trim(),api_key:$('#su_key').value.trim(),links:$('#su_links').value})})).json();
    if(!r.ok) throw new Error(r.error||'could not save');
    if(!r.found){
      const folder=$('#su_folder').value.trim();
      if(folder){
        msg.textContent='No videos found - diagnosing...';
        const dg=await(await fetch('/api/diag?folder='+encodeURIComponent(folder))).json();
        throw new Error(dg.verdict||r.error||'no videos found');
      }
      throw new Error(r.error||'saved, but no videos were found - check the folder sharing');
    }
    toast('Connected - found '+r.found+' video'+(r.found>1?'s':''));
    VIDEOS=[]; await loadVideos(true);
  }catch(e){msg.textContent=e.message; toast(e.message,true)}
  btn.disabled=false; btn.innerHTML='Connect & scan';
}
/* ---------- slide linking: timestamp -> beat -> SVG preview ---------- */
let BUNDLE=null, _slideT=null, _slideURL=null;
async function loadLinkRow(){
  const w=$('#linkrow'); if(!CUR){w.innerHTML='';return}
  const probe=await(await fetch('/api/slide?video='+encodeURIComponent(CUR.id)+'&t=0&title='+encodeURIComponent(CUR.title))).json();
  if(probe.found){BUNDLE=probe.bundle;
    w.innerHTML='<span>&#128279;</span><span>slides linked: <b style="color:var(--ink)">'+BUNDLE+'</b> ('+probe.total+' slides) - stamps get a live preview + slide id</span>';
    return}
  BUNDLE=null;
  const bs=await(await fetch('/api/bundles')).json();
  if(!(bs.bundles||[]).length){w.innerHTML='';return}
  w.innerHTML='<span>&#128279;</span><span>link this video to its lesson render for slide previews:</span>'+
    '<select id="bsel">'+bs.bundles.map(b=>'<option value="'+b.key+'">'+b.key+'</option>').join('')+'</select>'+
    '<button class="btn ghost" onclick="linkBundle()">Link</button>';
}
async function linkBundle(){
  const key=$('#bsel').value;
  const r=await(await fetch('/api/link',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({video_id:CUR.id,bundle:key})})).json();
  if(r.ok){toast('Linked to '+key);loadLinkRow()}else toast(r.error,true);
}
let _liveBeat=null,_editingAt=false;
async function _showSlide(ts,live){
  const card=$('#slidecard');
  if(!CUR||!String(ts||'').trim()){if(!live)card.classList.remove('on');return}
  const r=await(await fetch('/api/slide?video='+encodeURIComponent(CUR.id)+'&t='+encodeURIComponent(ts)+'&title='+encodeURIComponent(CUR.title))).json();
  if(!r.found){
    if(live){card.classList.remove('on');return}
    $('#slideimg').removeAttribute('src');
    $('#slidecap').innerHTML='No slide found for <b>'+ts+'</b> - '+(r.reason||'is the right lesson linked above?');
    card.classList.add('on');return;
  }
  if(!r.svg){$('#slidecap').innerHTML='Slide '+r.index+' matched but its SVG file is missing from the bundle';card.classList.add('on');return}
  if(r.beat_id===_liveBeat&&live)return;      // same slide: skip the re-render
  _liveBeat=r.beat_id;
  if(_slideURL)URL.revokeObjectURL(_slideURL);
  _slideURL=URL.createObjectURL(new Blob([r.svg],{type:'image/svg+xml'}));
  $('#slideimg').src=_slideURL;
  $('#slidecap').innerHTML=(live?'<b style="color:var(--gold)">LIVE</b> &middot; ':'')+'Slide <b>'+r.index+'</b> of '+r.total+' &middot; <b>'+r.beat_id+'</b> &middot; '+fmtDur(Math.floor(r.start))+' - '+fmtDur(Math.floor(r.end));
  card.classList.add('on');
}
function slidePreview(ts){
  clearTimeout(_slideT);
  _slideT=setTimeout(()=>_showSlide(ts,false),350);
}
function liveSlideTick(){ // native mode: the card follows the PLAYING video unless a stamp is being edited
  if(MODE!=='video'||!BUNDLE||_editingAt)return;
  const v=$('#pvideo'); if(v.paused&&_liveBeat)return;
  _showSlide(fmtDur(curTimeS()),true);
}

/* ---------- playback position: exact (native video) or approximate (watch timer) ---------- */
let MODE='iframe';                                   // 'video' | 'iframe'
function curTimeS(){
  if(MODE==='video'){const v=$('#pvideo');return Math.floor(v.currentTime||0)}
  return 0;                                          // the Drive iframe hides its clock - stamps are typed
}
function parseTs(t){const p=String(t||'').split(':').map(x=>parseInt(x,10));
  if(p.some(isNaN)||!p.length)return null;
  return p.length===3?p[0]*3600+p[1]*60+p[2]:p.length===2?p[0]*60+p[1]:p[0]}
function seekTo(t){if(MODE!=='video')return;const sec=parseTs(t);if(sec==null)return;
  const v=$('#pvideo');v.currentTime=sec;v.play&&v.play().catch(()=>{});}
setInterval(()=>{ // live position chip (native mode) + LIVE slide tracking
  if(!CUR)return;
  const c=$('#poschip');
  if(MODE==='video'){
    c.style.display='';c.textContent='you are at '+fmtDur(curTimeS());
    liveSlideTick();
  } else c.style.display='none';
},1500);

function esc2(t){const d=document.createElement('i');d.textContent=t==null?'':String(t);return d.innerHTML}
function initials(t){return (t||'').split(/\s+/).filter(Boolean).slice(0,2).map(w=>w[0]).join('').toUpperCase()||'RT'}
const STEPS=["Who","Signals","Scores","In your words"];

document.addEventListener('click',e=>{
  const b=e.target.closest('.btn,.seg b,.addm'); if(!b)return;
  const r=b.getBoundingClientRect(),s=document.createElement('span');
  s.className='ripple';const d=Math.max(r.width,r.height);
  s.style.cssText='width:'+d+'px;height:'+d+'px;left:'+(e.clientX-r.left-d/2)+'px;top:'+(e.clientY-r.top-d/2)+'px';
  b.appendChild(s);setTimeout(()=>s.remove(),560);
});
document.addEventListener('keydown',e=>{
  if(e.key==='/'&&!/INPUT|TEXTAREA/.test(document.activeElement.tagName)){e.preventDefault();goLobby();$('#q').focus()}
  if(e.key==='Escape'){if(LIGHTS)toggleLights();else if(document.activeElement===$('#q')){$('#q').value='';renderLib();$('#q').blur()}}
});
function toast(msg,bad){const t=$('#toast');$('#toastmsg').textContent=msg;t.className='toast show'+(bad?' bad':'');
  clearTimeout(t._h);t._h=setTimeout(()=>t.className='toast',3400)}
function fmtDur(s){if(s==null)return'';const m=Math.floor(s/60),ss=String(s%60).padStart(2,'0');return m+':'+ss}
function stars(n){return '★'.repeat(Math.round(n||0))}

/* ---------- identity + drafts (respect the reviewer's time) ---------- */
function loadIdentity(){try{const i=JSON.parse(localStorage.getItem('rt_reviewer')||'{}');
  $('#r_name').value=i.name||'';$('#r_role').value=i.role||'';$('#r_email').value=i.email||'';}catch(e){}}
function saveIdentity(){localStorage.setItem('rt_reviewer',JSON.stringify({name:$('#r_name').value.trim(),role:$('#r_role').value.trim(),email:$('#r_email').value.trim()}))}
function draftKey(){return 'rt_draft_'+(CUR?CUR.id:'')}
let _draftT=null;
function saveDraft(){clearTimeout(_draftT);_draftT=setTimeout(()=>{
  if(!CUR)return;
  const d={overall:OVERALL,ratings:{...RATINGS},sigs:{...SIGS},
    picks:JSON.parse(JSON.stringify(PICKS)),extra:$('#a_anything_else').value,
    moments:[...document.querySelectorAll('.mrow')].map(r=>({at:r.querySelector('.at').value,note:momentNote(r)}))};
  localStorage.setItem(draftKey(),JSON.stringify(d));
  const el=$('#draft');el.textContent='draft saved';el.className='draft saved';
  setTimeout(()=>{el.className='draft'},1200);
},600)}
function loadDraft(){try{return JSON.parse(localStorage.getItem(draftKey())||'null')}catch(e){return null}}

/* ---------- data ---------- */
async function loadVideos(force){
  const c=$('#cards');
  if(!VIDEOS.length){c.innerHTML='<div class="skel"></div>'.repeat(6)}
  try{
    const d=await(await fetch('/api/videos'+(force?'?refresh=1':''))).json();
    VIDEOS=d.videos||[];
    $('#modebadge').textContent=d.mode.startsWith('drive-folder')?'Drive: '+ (d.mode.match(/\((\d+) found/)||[,VIDEOS.length])[1] +' videos live':'manual manifest';
    if(d.error) toast(d.error,true);
  }catch(e){toast('Could not load the library: '+e.message,true);VIDEOS=[]}
  $('#libn').textContent=VIDEOS.length?VIDEOS.length+' films':'';
  renderLib();
}
function renderLib(){
  const q=($('#q').value||'').toLowerCase();
  const c=$('#cards'); c.innerHTML='';
  const vs=VIDEOS.filter(v=>!q||v.title.toLowerCase().includes(q));
  if(!vs.length){
    if(VIDEOS.length){c.innerHTML='<div class="empty">Nothing matches that search.</div>';return}
    if(!IS_ADMIN){c.innerHTML='<div class="empty">Your library is empty for now.<br><br>Ask your admin to add you to a collection - new screenings will appear here automatically.</div>';return}
    c.innerHTML='<div class="setup">'+
      '<h3>Connect your Drive</h3>'+
      '<p class="lead">Paste your Google Drive <b>folder link</b> - no API key needed. The only requirement: the folder is shared <b>Anyone with the link (Viewer)</b>. Subfolders are scanned too.</p>'+
      '<div class="fw"><label class="f">DRIVE FOLDER LINK</label><input class="tx" id="su_folder" placeholder="https://drive.google.com/drive/folders/1AbC..."></div>'+
      '<div class="or">RECOMMENDED: CONNECT GOOGLE (WORKS WITH PRIVATE FOLDERS + SHARED DRIVES)</div>'+
      '<div class="fw"><label class="f">OAUTH CLIENT ID</label><input class="tx" id="su_cid" placeholder="....apps.googleusercontent.com"></div>'+
      '<div class="fw"><label class="f" style="margin-top:10px">OAUTH CLIENT SECRET</label><input class="tx" id="su_csec" placeholder="GOCSPX-..."></div>'+
      '<div class="foot" style="margin-top:12px"><button class="btn" onclick="connectGoogle()">Save &amp; connect Google &#8599;</button>'+
      '<span class="hint">console.cloud.google.com &rarr; OAuth client (Web) &rarr; redirect URI: <b>'+location.origin+'/oauth/callback</b></span></div>'+
      '<div class="fw"><label class="f" style="margin-top:14px">API KEY (OPTIONAL - adds durations + sharing checks)</label><input class="tx" id="su_key" placeholder="AIza..."></div>'+
      '<div class="or">OR PASTE VIDEO LINKS, ONE PER LINE</div>'+
      '<textarea class="tx" id="su_links" placeholder="https://drive.google.com/file/d/.../view&#10;https://drive.google.com/file/d/.../view"></textarea>'+
      '<div class="foot"><button class="btn primary" id="su_go" onclick="saveSetup()">Connect &amp; scan</button>'+
      '<span class="hint" id="su_msg"></span></div>'+
      '<div class="tip">In Drive: right-click the folder &rarr; Share &rarr; General access &rarr; <b>Anyone with the link</b>. Settings are saved to review/config.json.</div>'+
      '</div>';
    return;
  }
  vs.forEach((v,i)=>{
    const el=document.createElement('div');
    el.className='pcard'; el.style.animationDelay=Math.min(i*55,440)+'ms';
    const rv=v.reviews||{count:0};
    el.innerHTML='<div class="poster"><div class="slate">'+initials(v.title)+'</div>'+(v.thumb?'<img loading="lazy" src="'+v.thumb.replace(/"/g,'')+'" alt="" onerror="this.remove()">':'')+'<div class="playbtn">'+PLAY_SVG+'</div><div class="scrim"></div>'+(v.duration_s?'<span class="dchip">'+fmtDur(v.duration_s)+'</span>':'')+'<div class="marq"></div></div>'+
      '<div class="pinfo"><div class="pname"></div><div class="pmeta">'+
      (rv.count?'<span class="stars-s">'+stars(rv.avg)+'</span><span>'+rv.count+' review'+(rv.count>1?'s':'')+'</span>':'<span>awaiting first review</span>')+
      (v.collection_name?'<span class="badge">'+esc2(v.collection_name)+'</span>':'')+
      (v.access==='restricted'?'<span class="wchip">&#9888; sharing restricted</span>':'')+
      '</div></div>';
    el.querySelector('.pname').textContent=v.title;
    el.onclick=()=>openScreening(v);
    c.appendChild(el);
  });
}

/* ---------- views ---------- */
function show(view){document.querySelectorAll('.view').forEach(x=>x.classList.remove('on'));const v=$(view);void v.offsetWidth;v.classList.add('on');window.scrollTo({top:0,behavior:'smooth'})}
function goLobby(){if(LIGHTS)toggleLights();show('#v-lobby');renderLib()}
function openScreening(v){
  CUR=v; OVERALL=0; Object.keys(RATINGS).forEach(k=>delete RATINGS[k]); Object.keys(SIGS).forEach(k=>delete SIGS[k]);
  $('#ptitle').textContent=v.title;
  const rv=v.reviews||{count:0};
  $('#pstats').textContent=rv.count?stars(rv.avg)+' '+(rv.avg||'')+' - '+rv.count+' review'+(rv.count>1?'s':''):'be the first to review';
  $('#tdur').textContent=v.duration_s?fmtDur(v.duration_s)+' runtime':'';
  const durl='https://drive.google.com/file/d/'+encodeURIComponent(v.id)+'/view';
  $('#odrive').href=durl; $('#accfix').href=durl;
  $('#repbtn').href='/api/report?video='+encodeURIComponent(v.id)+'&title='+encodeURIComponent(v.title);
  $('#accbanner').classList.toggle('on',v.access==='restricted');
  $('#loading').style.display='grid';
  const f=$('#pframe'), pv=$('#pvideo');
  pv.pause&&pv.pause(); pv.removeAttribute('src'); pv.load&&pv.load();
  function useIframe(){
    MODE='iframe'; pv.style.display='none'; f.style.display='';
    f.classList.remove('ready');
    f.onload=()=>{f.classList.add('ready');$('#loading').style.display='none'};
    f.src='https://drive.google.com/file/d/'+encodeURIComponent(v.id)+'/preview';
    $('#tiphint').textContent='type the time shown in the player when flagging - an API key unlocks exact auto-stamps';
  }
  if(v.stream){
    MODE='video'; f.style.display='none'; f.removeAttribute('src'); pv.style.display='';
    pv.onerror=()=>{toast('Direct stream unavailable - falling back to the Drive player',true);useIframe()};
    pv.onloadeddata=()=>{$('#loading').style.display='none'};
    pv.src='/api/stream?video='+encodeURIComponent(v.id);
    $('#tiphint').textContent='flag a moment below - the timestamp fills itself from the player';
  } else {
    useIframe();
  }
  // stage reset
  $('#stagebar').style.display='flex';
  $('#watchnotes').style.display='block';
  $('#revwrap').classList.remove('on');
  $('#thanks').style.display='none';
  buildForm();
  const d=loadDraft();
  if(d){restoreDraft(d);const pk=d.picks||{};
    if(d.overall||pk.pitch||pk.change||(pk.stayed||[]).length||(pk.off||[]).length||(d.extra||'').trim()){startReview(true);toast('Draft restored - pick up where you left off')}}
  renderUpNext(); renderPast(rv.count); loadLinkRow();
  _liveBeat=null; _editingAt=false; $('#slidecard').classList.remove('on');
  show('#v-screen');
}
function renderUpNext(){
  const w=$('#upnext'); w.innerHTML='';
  VIDEOS.filter(v=>!CUR||v.id!==CUR.id).slice(0,8).forEach(v=>{
    const el=document.createElement('div'); el.className='un';
    el.innerHTML='<span class="pl">'+PLAY_SVG_S+'</span><b></b>';
    el.querySelector('b').textContent=v.title;
    el.onclick=()=>openScreening(v);
    w.appendChild(el);
  });
}
async function renderPast(count){
  const w=$('#pastwrap');
  if(!count){w.style.display='none';return}
  const d=await(await fetch('/api/reviews?video='+encodeURIComponent(CUR.id))).json();
  const L=$('#pastlist'); L.innerHTML='';
  (d.reviews||[]).slice(0,8).forEach((r,i)=>{
    const el=document.createElement('div'); el.className='prev'; el.style.animationDelay=(i*60)+'ms';
    const who=(r.reviewer&&r.reviewer.name)?r.reviewer.name:'anonymous';
    const ans=r.answers||{};
    el.innerHTML='<div class="who"><b></b> <span class="stars-s">'+stars((r.ratings||{}).overall)+'</span></div><div class="txt"></div>';
    el.querySelector('b').textContent=who;
    el.querySelector('.txt').textContent=ans.one_sentence||ans.first_takeaway||ans.one_change||Object.values(ans)[0]||'';
    L.appendChild(el);
  });
  w.style.display='block';
}
function toggleLights(){LIGHTS=!LIGHTS;document.body.classList.toggle('dark2',LIGHTS);
  $('#lights').innerHTML=LIGHTS?'<svg class="icn" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M9 18h6M10 22h4M12 2a7 7 0 0 0-4 12.7c.6.5 1 1.4 1 2.3h6c0-.9.4-1.8 1-2.3A7 7 0 0 0 12 2z"/></svg> Lights up':'<svg class="icn" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z"/></svg> Lights down'}
function startReview(quiet){
  $('#stagebar').style.display='none';
  const r=$('#revwrap'); r.classList.add('on');
  if(!quiet){$('#s-who').scrollIntoView({behavior:'smooth',block:'start'})}
  meter();
}

/* ---------- form ---------- */
function buildForm(){
  document.querySelectorAll('#stars span').forEach(s=>{
    s.classList.remove('on','hov','bang');
    s.onmouseenter=()=>{document.querySelectorAll('#stars span').forEach(x=>x.classList.toggle('hov',+x.dataset.v<=+s.dataset.v))};
    s.onmouseleave=()=>{document.querySelectorAll('#stars span').forEach(x=>x.classList.remove('hov'))};
    s.onclick=()=>{OVERALL=+s.dataset.v;
      document.querySelectorAll('#stars span').forEach(x=>{x.classList.toggle('on',+x.dataset.v<=OVERALL);x.classList.remove('bang')});
      void s.offsetWidth;s.classList.add('bang');
      const L=$('#slabel');L.textContent=SLBL[OVERALL];L.className='slabel set';meter();saveDraft()};
  });
  $('#slabel').textContent='';$('#slabel').className='slabel';
  const d=$('#dims'); d.innerHTML='';
  DIMS.forEach(([k,label])=>{
    const row=document.createElement('div'); row.className='dim';
    row.innerHTML='<div class="dl">'+label+'</div><div class="seg" data-dim="'+k+'">'+[1,2,3,4,5].map(n=>'<b data-v="'+n+'">'+n+'</b>').join('')+'</div>';
    d.appendChild(row);
  });
  document.querySelectorAll('.seg[data-dim] b').forEach(b=>{
    b.onclick=()=>{const seg=b.parentElement,k=seg.dataset.dim;RATINGS[k]=+b.dataset.v;seg.querySelectorAll('b').forEach(x=>x.classList.toggle('on',x===b));meter();saveDraft()};
  });
  document.querySelectorAll('.seg[data-sig] b').forEach(b=>{
    b.onclick=()=>{const seg=b.parentElement,k=seg.dataset.sig;SIGS[k]=b.dataset.v;seg.querySelectorAll('b').forEach(x=>x.classList.toggle('on',x===b));meter();saveDraft()};
    b.classList.remove('on');
  });
  $('#moments').innerHTML=''; addMoment(false);
  PICKS.pitch="";PICKS.stayed=[];PICKS.off=[];PICKS.change="";
  document.querySelectorAll('.pills[data-q] .pill').forEach(p=>{
    p.classList.remove('on');
    p.onclick=()=>{
      const g=p.closest('.pills'),q=g.dataset.q,single=g.dataset.single==='1',v=p.dataset.v;
      if(single){
        const was=p.classList.contains('on');
        g.querySelectorAll('.pill').forEach(x=>x.classList.remove('on'));
        if(!was)p.classList.add('on');
        PICKS[q]=p.classList.contains('on')?v:'';
      } else {
        p.classList.toggle('on');
        PICKS[q]=[...g.querySelectorAll('.pill.on')].map(x=>x.dataset.v);
      }
      meter();saveDraft();
    };
  });
  const ae=$('#a_anything_else'); ae.value=''; ae.oninput=()=>{meter();saveDraft()};
  loadIdentity();
  ['r_name','r_role','r_email'].forEach(k=>{$('#'+k).oninput=()=>{meter();saveIdentity()}});
  buildStepper(); buildFilmstrip(); meter();
}
function restoreDraft(d){
  if(d.overall){OVERALL=d.overall;document.querySelectorAll('#stars span').forEach(x=>x.classList.toggle('on',+x.dataset.v<=OVERALL));
    $('#slabel').textContent=SLBL[OVERALL]||'';$('#slabel').className='slabel set'}
  Object.entries(d.ratings||{}).forEach(([k,v])=>{RATINGS[k]=v;
    document.querySelectorAll('.seg[data-dim="'+k+'"] b').forEach(x=>x.classList.toggle('on',+x.dataset.v===v))});
  Object.entries(d.sigs||{}).forEach(([k,v])=>{SIGS[k]=v;
    document.querySelectorAll('.seg[data-sig="'+k+'"] b').forEach(x=>x.classList.toggle('on',x.dataset.v===v))});
  const pk=d.picks||{};
  Object.assign(PICKS,{pitch:pk.pitch||'',stayed:pk.stayed||[],off:pk.off||[],change:pk.change||''});
  document.querySelectorAll('.pills[data-q]').forEach(g=>{
    const q=g.dataset.q,val=PICKS[q];
    g.querySelectorAll('.pill').forEach(p=>p.classList.toggle('on',
      Array.isArray(val)?val.includes(p.dataset.v):val===p.dataset.v));
  });
  if(d.extra)$('#a_anything_else').value=d.extra;
  const ms=(d.moments||[]).filter(m=>(m.note||'').trim());
  if(ms.length){$('#moments').innerHTML='';ms.forEach(m=>{addMoment(false);const r=$('#moments').lastChild;
    r.querySelector('.at').value=m.at||'';
    const dp=r.querySelector('.tags .pill[data-t="_d"]');dp.classList.add('on');
    r.querySelector('.detail').classList.add('on');r.querySelector('.detail input').value=m.note||''})}
}
function buildStepper(){
  const w=$('#stepper'); w.innerHTML='';
  STEPS.forEach((name,i)=>{
    const el=document.createElement('div'); el.className='step'; el.dataset.i=i;
    el.innerHTML='<span class="dot"></span>'+name;
    el.onclick=()=>{document.querySelectorAll('.sec[data-step]')[i].scrollIntoView({behavior:'smooth',block:'start'})};
    w.appendChild(el);
  });
  if(!window._spy){window._spy=true;
    window.addEventListener('scroll',()=>{
      const secs=[...document.querySelectorAll('.sec[data-step]')];
      let idx=0; secs.forEach((s,i)=>{if(s.getBoundingClientRect().top<200)idx=i});
      document.querySelectorAll('.step').forEach((st,i)=>st.classList.toggle('here',i===idx));
    },{passive:true});}
}
function buildFilmstrip(){
  const c=$('#fcells'); c.innerHTML='';
  for(let i=0;i<10;i++){const s=document.createElement('div');s.className='cell';c.appendChild(s)}
}
const MTAGS=["confusing","loved it","too fast","too slow","slides too busy","text unreadable","audio issue","animation glitch"];
function momentNote(row){
  const tags=[...row.querySelectorAll('.tags .pill.on')].filter(p=>p.dataset.t!=='_d').map(p=>p.dataset.t);
  const d=(row.querySelector('.detail input')||{}).value||'';
  return tags.join(', ')+(d.trim()?(tags.length?' - ':'')+d.trim():'');
}
function addMoment(focus){
  const w=$('#moments'); if(w.children.length>=12)return;
  const row=document.createElement('div'); row.className='mrow';
  row.innerHTML='<input class="tx at" placeholder="2:35">'+(MODE==='video'?'<button class="seek" title="jump the player to this timestamp">&#8635;</button>':'')+
    '<div class="tags">'+MTAGS.map(t=>'<span class="pill" data-t="'+t+'">'+t+'</span>').join('')+
    '<span class="pill" data-t="_d">+ detail</span></div>'+
    '<button class="del" title="remove">&times;</button>'+
    '<div class="detail"><input class="tx" placeholder="anything specific about this moment (optional)"></div>';
  row.querySelector('.del').onclick=()=>{row.classList.add('out');setTimeout(()=>{row.remove();meter();saveDraft()},260)};
  row.querySelectorAll('.tags .pill').forEach(p=>{p.onclick=()=>{
    if(p.dataset.t==='_d'){p.classList.toggle('on');row.querySelector('.detail').classList.toggle('on',p.classList.contains('on'));
      if(p.classList.contains('on'))row.querySelector('.detail input').focus()}
    else p.classList.toggle('on');
    meter();saveDraft()}});
  row.querySelector('.detail input').oninput=()=>{meter();saveDraft()};
  const at=row.querySelector('.at');
  at.oninput=()=>{slidePreview(at.value);meter();saveDraft()};
  at.addEventListener('focus',()=>{_editingAt=true;slidePreview(at.value)});
  at.addEventListener('blur',()=>{setTimeout(()=>{_editingAt=false},400)});
  const sk=row.querySelector('.seek'); if(sk)sk.onclick=()=>seekTo(at.value);
  // AUTO-TIMESTAMP: prefill from wherever the reviewer actually is (exact on the native player,
  // watch-timer estimate on the Drive iframe). Editable - it is just a head start.
  w.appendChild(row);
  if(focus){
    const t=curTimeS();
    if(t>0){row.querySelector('.at').value=fmtDur(t);slidePreview(fmtDur(t));row.querySelectorAll('input')[1].focus()}
    else row.querySelector('.at').focus();
  }
}
const FTXT=[[0,'a blank reel'],[25,'first frames lit'],[45,'half the reel'],[70,'nearly a full reel'],[90,'a full reel - submit it']];
function meter(){
  let score=0;
  if(OVERALL)score+=25;
  score+=Math.min(Object.keys(RATINGS).length,6)*5;
  score+=Math.min(Object.keys(SIGS).length,3)*4;
  if(($('#r_name').value||'').trim())score+=6;
  const answered=(PICKS.pitch?1:0)+(PICKS.stayed.length?1:0)+(PICKS.off.length?1:0)+(PICKS.change?1:0)
    +(($('#a_anything_else').value||'').trim()?1:0);
  score+=Math.min(answered,4)*6;
  if([...document.querySelectorAll('.mrow')].some(r=>momentNote(r)))score+=7;
  score=Math.min(100,score);
  const lit=Math.round(score/10);
  document.querySelectorAll('#fcells .cell').forEach((c,i)=>c.classList.toggle('lit',i<lit));
  const t=FTXT.filter(m=>score>=m[0]).pop();
  const el=$('#ftxt'); el.textContent=t[1]+' - '+score+'%'; el.className='ftxt'+(score>=70?' good':'');
  // step done-dots
  const doneMap=[!!($('#r_name').value||'').trim(),Object.keys(SIGS).length>=3,!!OVERALL,answered>0];
  void 0;
  document.querySelectorAll('.step').forEach((st,i)=>st.classList.toggle('donez',doneMap[i]));
}
async function submitReview(){
  if(!CUR) return toast('Pick a video first',true);
  if(!OVERALL) return toast('Give it an overall score (the stars)',true);
  const answers={};
  if(PICKS.pitch)answers.one_sentence=PICKS.pitch;
  if(PICKS.stayed.length)answers.first_takeaway=PICKS.stayed.join(', ');
  if(PICKS.off.length)answers.felt_off=PICKS.off.join(', ');
  if(PICKS.change)answers.one_change=PICKS.change;
  const extra=($('#a_anything_else').value||'').trim(); if(extra)answers.anything_else=extra;
  if(!Object.keys(answers).length) return toast('Tap at least one chip - that is the point',true);
  const moments=[...document.querySelectorAll('.mrow')].map(r=>({at:r.querySelector('.at').value.trim(),note:momentNote(r)})).filter(m=>m.note);
  const payload={video_id:CUR.id,video_title:CUR.title,
    reviewer:{name:$('#r_name').value.trim(),role:$('#r_role').value.trim(),email:$('#r_email').value.trim()},
    ratings:Object.assign({overall:OVERALL},RATINGS),signals:SIGS,moments,answers};
  const btn=$('#submit'); btn.disabled=true; btn.innerHTML='<span class="spinner"></span> Submitting...';
  try{
    const r=await(await fetch('/api/review',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)})).json();
    if(!r.ok) throw new Error(r.error||'save failed');
    localStorage.removeItem(draftKey());
    $('#revwrap').classList.remove('on'); $('#watchnotes').style.display='none';
    const th=$('#thanks'); th.style.display='none'; void th.offsetWidth; th.style.display='block';
    th.scrollIntoView({behavior:'smooth',block:'center'});
    confetti($('#ckwrap'));
    loadVideos(true);
  }catch(e){toast(e.message,true)}
  btn.disabled=false; btn.innerHTML='Submit review';
}
function confetti(host){
  const cols=['#e5484d','#f5c96b','#3dd68c','#5b8def','#ff7d81'];
  for(let i=0;i<14;i++){
    const s=document.createElement('span'); s.className='conf';
    const a=(i/14)*Math.PI*2, r=60+(i%3)*26;
    s.style.cssText='--dx:'+Math.round(Math.cos(a)*r)+'px;--dy:'+Math.round(Math.sin(a)*r-20)+'px;background:'+cols[i%5]+';animation-delay:'+(i%4)*40+'ms';
    host.appendChild(s); setTimeout(()=>s.remove(),1100);
  }
}
function resetForm(){OVERALL=0;$('#thanks').style.display='none';$('#watchnotes').style.display='block';$('#revwrap').classList.add('on');buildForm()}
function nextVideo(){if(!VIDEOS.length)return;const i=VIDEOS.findIndex(v=>CUR&&v.id===CUR.id);const nx=VIDEOS[(i+1)%VIDEOS.length];if(nx)openScreening(nx)}
async function uploadVideo(inp){
  const f=inp.files&&inp.files[0]; if(!f)return;
  const btn=$('#upbtn'); btn.disabled=true; btn.innerHTML='<span class="spinner"></span> Uploading '+Math.round(f.size/1048576)+' MB...';
  try{
    const r=await(await fetch('/api/upload-video?name='+encodeURIComponent(f.name),{method:'POST',body:f})).json();
    if(!r.ok)throw new Error(r.error||'upload failed');
    toast('Uploaded '+r.video+' - it plays in the native player with exact timestamps');
    VIDEOS=[]; await loadVideos(true);
  }catch(e){toast(e.message,true)}
  btn.disabled=false; btn.innerHTML='&#8679; Upload video'; inp.value='';
}
(async()=>{  // invite links sign you in AND introduce you - name lands prefilled
  try{
    const me=await(await fetch('/api/me')).json();
    if(me.identity&&me.identity.name){
      const cur=JSON.parse(localStorage.getItem('rt_reviewer')||'{}');
      if(!cur.name)localStorage.setItem('rt_reviewer',JSON.stringify(me.identity));
    }
    if(me.identity&&me.identity.name){const w=$('#whoami');w.style.display='';w.textContent=me.identity.name+(me.admin?' - ADMIN':'');$('#signout').style.display=''}
    IS_ADMIN=!!me.admin;
    if(me.admin){$('#upbtn').style.display='';$('#adminlink').style.display='';$('#keybtn').style.display=''}
    renderLib();
    if(location.search.includes('invite='))history.replaceState({},'', '/');
  }catch(e){}
})();
loadVideos(false);
</script></body></html>"""


if __name__ == "__main__":
    main()
