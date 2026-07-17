# Deploying the Screening Room centrally

One process, stdlib-only, all state in this folder (config.json, reviews/, bundles/).
Back up = copy the folder. Migrate = move the folder.

## 1. Lock it down first (any deployment)
In `config.json` set:
    "access_code": "something-your-org-shares",
    "admin_code":  "something-only-you-know"
Reviewers enter the access code once (90-day cookie) - or skip codes entirely: open /admin and hand each reviewer a personal magic invite link (signs them in AND prefills their identity; revocable). The admin code additionally unlocks
setup: Drive folder / API key changes, video-bundle linking, and slide-bundle uploads.

## 1.5 Connect Drive the PROPER way (OAuth - do this once)
Your videos land in Drive automatically; OAuth lets the platform read that folder WITHOUT any
public sharing (private folders + Shared Drives both work; reviewers stream through the server):
  1. console.cloud.google.com -> new project -> enable "Google Drive API"
  2. OAuth consent screen: Internal (Workspace) or External+test users
  3. Credentials -> Create OAuth client -> Web application ->
     authorized redirect URI: https://reviews.yourco.com/oauth/callback (or http://127.0.0.1:8712/oauth/callback locally)
  4. In the setup card: paste client id + secret -> "Save & connect Google" -> approve drive.readonly
The refresh token persists in config.json; revoke anytime at myaccount.google.com/permissions.

## 2. Company VM / any Linux box (recommended)
    REDTEE_REVIEW_HOST=0.0.0.0 REDTEE_REVIEW_PORT=8712 python3 server.py
Put nginx/Caddy in front for HTTPS (`caddy reverse-proxy --from reviews.yourco.com --to :8712`).
Systemd unit: ExecStart=/usr/bin/python3 /opt/redtee/review/server.py, plus the two env vars.

## 3. Railway / Render / Fly (no VM)
Use Dockerfile. Mount a persistent volume at /app (state lives there). Set
REDTEE_REVIEW_CODE / REDTEE_REVIEW_ADMIN_CODE as env secrets instead of config values.

## 4. Today, from a laptop (temporary but centralized)
    REDTEE_REVIEW_HOST=0.0.0.0 python review/server.py
    cloudflared tunnel --url http://localhost:8712
Share the generated https URL + the access code. (State still lives on that laptop.)

## Hosting videos ON the server (skip Drive entirely)
The admin sees an "Upload video" button in the lobby (or:
    curl -X POST --data-binary @lesson.mp4 "https://reviews.yourco.com/api/upload-video?name=lesson.mp4" -H "Cookie: <admin cookie>")
Uploaded videos play in the native player (exact timestamps) with zero sharing setup.
Drive stays supported, but nothing depends on it.

## Publishing slides from the render machine
The render machine never has to share a disk with the server:
    python export_sidecar.py render_out/<lesson> https://reviews.yourco.com <admin_code>
This packs timeline + slide SVGs into one sidecar and pushes it to the central server
(POST /api/bundle). Videos come from the shared Drive folder as before.

## What is central after this
videos: Drive folder | slides: pushed sidecars | reviews + config: server volume
Nothing depends on any reviewer's or author's laptop.
