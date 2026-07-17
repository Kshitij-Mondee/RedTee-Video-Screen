# RedTee Screening Room

A single-file, stdlib-only review platform: your org signs in on a landing page,
watches training videos (Drive collections or server-hosted uploads) in a native
player, flags slide-exact moments, and files two-minute chip-based reviews.
Admins manage collections, visibility, invites and see per-slide feedback
dashboards at /admin.

## Run
    python server.py                       # http://127.0.0.1:8712
    REDTEE_REVIEW_HOST=0.0.0.0 python server.py    # serve the org

First run creates config.json (or copy config.example.json). Set access_code +
admin_code (or admin_emails + Google OAuth) before exposing it. See DEPLOY.md
for VM / Docker / tunnel deployment.

## State = this folder
config.json (settings) - reviews/ (feedback JSON) - videos/ (uploads) -
bundles/ (slide sidecars) - sessions.json / invites.json. Back up by copying
the folder.

## Slides from the render pipeline
From the RedTee render repo:
    python <this folder>/export_sidecar.py render_out/<lesson> <server_url> <admin_code>
or drop a *.review.json into bundles/, or add the render repo's render_out as an
absolute path in config.bundle_dirs.
