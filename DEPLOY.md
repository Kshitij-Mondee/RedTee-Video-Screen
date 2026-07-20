# Deploying the RedTee Screening Room (Cloud PaaS)

One stdlib-only process. Code ships in the Docker image at `/app`; all persistent state
(config, reviews, uploaded videos, sessions, invites, slide bundles) lives in a volume
mounted at `/data`. Backup = copy the volume. Migrate = move the volume.

> **Why the split matters:** on Railway / Render / Fly a mounted volume starts empty and
> hides whatever the image had at that path. If you mounted the volume at `/app` it would
> shadow `server.py` and the container would fail to start. So code stays in `/app` and the
> volume mounts at `/data`. The server reads `REDTEE_DATA_DIR=/data` (already set in the
> Dockerfile) and keeps all state there.

---

## 0. What you need before you start
- The repo (this folder) pushed to GitHub/GitLab, OR the platform CLI installed.
- Your two access codes decided (already in `config.json`: `access_code` and `admin_code`).
  In the cloud we pass these as **env secrets** instead of relying on the file.
- (Optional) A Google Drive folder id + API key, or OAuth credentials, for the video library.
  You can also skip Drive entirely and upload videos through the admin UI after launch.

## 1. Environment variables (all platforms)
Set these on the service. They override anything in `config.json`:

| Variable                    | Value                          | Purpose                                  |
|-----------------------------|--------------------------------|------------------------------------------|
| `REDTEE_REVIEW_CODE`        | `MondeeAccess`                 | org-wide reviewer access code            |
| `REDTEE_REVIEW_ADMIN_CODE`  | `RedTee_0806`                  | admin code (setup, invites, export)      |
| `REDTEE_DATA_DIR`           | `/data`                        | already set in the Dockerfile; leave as is |
| `REDTEE_REVIEW_HOST`        | `0.0.0.0`                      | already set in the Dockerfile            |
| `REDTEE_REVIEW_PORT`        | `8712`                         | must match the platform's target port    |
| `SUPABASE_URL`              | `https://<project>.supabase.co`| only for free/diskless hosting (section 7) |
| `SUPABASE_SERVICE_KEY`      | service_role key               | only for free/diskless hosting (section 7) |

The platforms all terminate HTTPS at the edge and set `X-Forwarded-Proto: https`, which the
server uses to mark cookies `Secure`. No cert work needed on your side.

---

> Config files are included in the repo: `railway.json` (Railway), `render.yaml` (Render
> Blueprint), and `fly.toml` (Fly.io). Each platform picks up its own file automatically.

## 2A. Railway (simplest)
1. **New Project → Deploy from GitHub repo** (or `railway init` with the CLI). Railway reads
   `railway.json` (Dockerfile build + `/health` check) and builds the image. Volumes and
   variables are set in the dashboard (steps 2–4 below).
2. **Variables** tab → add `REDTEE_REVIEW_CODE`, `REDTEE_REVIEW_ADMIN_CODE`,
   `REDTEE_REVIEW_PORT=8712`. (`REDTEE_DATA_DIR` / `REDTEE_REVIEW_HOST` come from the Dockerfile.)
3. **Volumes** → add a volume, mount path `/data`.
4. **Settings → Networking** → Generate Domain. Set the **target/exposed port to `8712`** so
   Railway routes the public HTTPS domain to the container port.
5. Deploy. Open the generated `https://<app>.up.railway.app` and log in with the admin code at
   `/admin`.

## 2B. Render (FREE tier - uses Supabase snapshots for persistence)
`render.yaml` is configured for the **free** plan with **no disk**. Instead, the app snapshots
its state to Supabase Storage. Do the Supabase setup in section 8 first (5 minutes), then:
1. **New → Blueprint** → connect the repo. Render reads `render.yaml` and provisions the web
   service and the non-secret env vars.
2. Render prompts for the `sync: false` secrets — enter:
   - `REDTEE_REVIEW_CODE` = `MondeeAccess`
   - `REDTEE_REVIEW_ADMIN_CODE` = `RedTee_0806`
   - `SUPABASE_URL` = `https://<your-project>.supabase.co`
   - `SUPABASE_SERVICE_KEY` = your Supabase **service_role** key
3. Apply. Visit `https://<app>.onrender.com` and sign in at `/admin`.

> Want always-on + a real disk instead? Change `plan: free` → `plan: starter` in `render.yaml`
> and add a `disk:` mounted at `/data` (requires a card, ~$7/mo). The Supabase vars then become
> optional.

## 2C. Fly.io
`fly.toml` is already in the repo (internal port 8712, HTTPS forced, `/health` check, and a
`/data` mount). You only need to:
1. Set the app name: edit `app = "redtee-screening-room"` in `fly.toml` to a unique name, or run
   `fly launch --no-deploy` and let it fill that in (keep the existing Dockerfile + fly.toml).
2. Create the volume (same region as the app) and set the secret codes:
   ```
   fly volumes create redtee_data --size 3 --region iad
   fly secrets set REDTEE_REVIEW_CODE=MondeeAccess REDTEE_REVIEW_ADMIN_CODE=RedTee_0806
   ```
3. `fly deploy`. Open `https://<app>.fly.dev` and sign in at `/admin`.

> Note: `fly.toml` sets `min_machines_running = 1` so the app doesn't cold-stop and drop the
> in-memory video cache; lower it to 0 if you want scale-to-zero and don't mind first-hit latency.

---

## 3. First-boot configuration (once, in the browser)
On first start with an empty volume, the server writes a starter `config.json` into `/data`.
Because the codes come from env vars, auth is already ON. Then:

1. Go to `https://<your-domain>/admin` and enter the **admin code**.
2. In the setup card, connect your video library one of three ways:
   - **Google OAuth (best):** paste OAuth client id + secret, click "Save & connect Google",
     approve `drive.readonly`. Private folders and Shared Drives work; nothing needs public
     sharing. Set the authorized redirect URI in Google Cloud to
     `https://<your-domain>/oauth/callback`.
   - **API key + public folder:** paste a Drive folder link and an API key.
   - **Uploads:** skip Drive; use the "Upload video" button in the lobby.
3. (Optional) Add `admin_emails` and per-collection visibility from the admin UI.

## 3.5 Auto-save feedback reports to a Google Drive folder
The server can mirror every review into a Drive folder you choose, so feedback lands in Drive
automatically (no manual CSV exports).

**One-time setup:**
1. Connect Google via OAuth (step 3). The connect flow now requests **write** access
   (`drive.file`) in addition to read. If you connected Google *before* this feature existed,
   click **"Save & connect Google"** again to re-consent — the old read-only token cannot write.
2. Set the destination folder. Paste a Drive folder link into `reports_drive_folder` in
   `config.json`, or POST it to `/api/config` as `reports_folder` (admin). The connected Google
   account must have edit access to that folder. Leave it empty to turn the feature off.

**What gets written (created once, then overwritten in place — no duplicates):**
- `<video>.report.html` — the human-readable feedback report, one per video.
- `<video>.reviews.json` — the raw reviews for that video (machine-readable).
- `all_reviews.csv` — the org-wide spreadsheet of every review.

**When:** automatically (in the background) each time a review is submitted. To backfill the
folder with everything already collected, an admin can POST `/api/push-reports`:
```
curl -X POST https://<your-domain>/api/push-reports -H "Cookie: <admin cookie>"
```
Drive errors never block a review submission — they're logged and skipped.

> Scope note: the app uses least-privilege `drive.file`, so it can only see/overwrite the report
> files it created in that folder — it cannot read your other Drive files.

## 4. Give people access
- **Reviewers:** share the URL + the access code, OR from `/admin` create per-person magic
  invite links (they sign in and prefill identity; revocable).
- **Admins:** hand out the admin code, or add their email to `admin_emails` and have them sign
  in with Google.

## 5. Publishing slides from the render machine
From the RedTee render repo (run locally, pushes over HTTPS):
```
python export_sidecar.py render_out/<lesson> https://<your-domain> <admin_code>
```
This packs timeline + slide SVGs into one sidecar and POSTs it to `/api/bundle` (admin-gated).

## 6. Backups & migration
All state is `config.json`, `reviews/`, `videos/`, `bundles/`, `sessions.json`, `invites.json`.
- **Paid/disk deployments:** it lives on the `/data` volume — snapshot or copy that volume to
  back up; attach it to a new service to migrate.
- **Free/Supabase deployments:** it lives in the `state.tar.gz` object in your Supabase bucket —
  that object *is* your backup. Download it to migrate, or point a new service at the same
  `SUPABASE_URL` + bucket and it restores automatically on boot.

Either way, losing all state loses the auth salt (everyone re-logs in), the Google OAuth refresh
token, and locally-stored reviews — so confirm persistence is wired (volume mounted, or Supabase
vars set) before going live.

## 7. Free hosting with Supabase snapshots (no disk, no card)
On a diskless host the state folder is wiped on every redeploy/spin-down. Set these env vars and
the app will restore its state from a private Supabase Storage bucket on boot, and re-upload it
whenever it changes and on shutdown.

**Supabase setup (once):**
1. Create a free project at supabase.com. Note the **Project URL**
   (`https://<project>.supabase.co`).
2. Project **Settings → API** → copy the **service_role** key (secret — server-side only, never
   ship it to browsers or git).
3. That's it for Supabase — the app auto-creates the `redtee-state` bucket on first boot.

**Env vars on the host:**
| Variable                | Value                                   |
|-------------------------|-----------------------------------------|
| `SUPABASE_URL`          | `https://<project>.supabase.co`         |
| `SUPABASE_SERVICE_KEY`  | the service_role key                    |
| `SUPABASE_BUCKET`       | `redtee-state` (default; optional)      |
| `REDTEE_SNAPSHOT_INTERVAL` | `60` (seconds; optional)             |
| `REDTEE_SNAPSHOT_VIDEOS`   | `1` to also snapshot uploaded videos (large; default off) |

**What is snapshotted:** `config.json` (incl. login salt + Google OAuth token), `reviews/`,
`bundles/`, `sessions.json`, `invites.json`. Uploaded videos are excluded by default (keep them
in Drive, or set `REDTEE_SNAPSHOT_VIDEOS=1` if you must).

**Durability:** state is re-uploaded on change (checked every `INTERVAL` seconds) and once more on
shutdown. Worst case you lose the last ~`INTERVAL` seconds of writes on a hard crash — but review
submissions also push to Drive immediately (section 3.5), so feedback itself is doubly safe. Admins
can force a snapshot anytime with `POST /api/snapshot`.

**Startup logs** will show `snapshot: restored N KB ...` or `snapshot: none found yet (fresh
start)`, and `snapshot: Supabase redtee-state/state.tar.gz every 60s` — a quick way to confirm it's on.

## 8. Security checklist (post-deploy)
- [ ] Confirm the app is reached only over `https://` (all three PaaS enforce this).
- [ ] Confirm `/api/export.csv` returns 403 unless you're signed in with the admin code.
- [ ] Confirm the `/data` volume is mounted (upload a test video; it should survive a redeploy).
- [ ] Rotate `REDTEE_REVIEW_ADMIN_CODE` if it was ever shared outside the admin group.
- [ ] Keep `config.json` out of git (it already is via `.gitignore`).

---

## Local run (for reference)
```
python server.py                    # http://127.0.0.1:8712, state next to server.py
```
Set `REDTEE_DATA_DIR` to relocate state locally too. Without any codes set, local runs are in
OPEN mode (no auth) — fine for a laptop, never for a shared host.
