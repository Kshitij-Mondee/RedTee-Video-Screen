#!/usr/bin/env python3
"""Pack a lesson's render output into ONE portable sidecar for the screening room:
timestamp->slide spans + every slide SVG inline.

    python review/export_sidecar.py render_out/BusinessEthics_Chapter7
    -> review/bundles/BusinessEthics_Chapter7.review.json

Drop the file into review/bundles/ on any machine running the screening room (or park it
in Drive and download it there). The server treats it exactly like a local render dir.
"""
import json, re, sys, urllib.parse
from pathlib import Path

def main():
    if len(sys.argv) not in (2, 4):
        raise SystemExit(__doc__ + "\nPush to a central server:\n"
                         "    python review/export_sidecar.py <render_dir> <server_url> <admin_code>\n")
    src = Path(sys.argv[1])
    tl = json.loads((src / "timeline.json").read_text(encoding="utf-8"))
    man = json.loads((src / "l4_manifest.json").read_text(encoding="utf-8"))
    ids = [b.get("beat_id") or b.get("id") or f"beat_{i}" for i, b in enumerate(man.get("beats", []))]
    agg = {}
    for c in tl.get("cues", []):
        bi = int(c.get("beat", 0))
        a = agg.setdefault(bi, [1e18, 0.0])
        a[0] = min(a[0], float(c.get("visibleAtS", c.get("audioStartS", 0)) or 0))
        a[1] = max(a[1], float(c.get("audioEndS", 0) or 0))
    spans = [{"i": bi, "beat_id": ids[bi] if bi < len(ids) else f"beat_{bi}",
              "start": round(agg[bi][0], 3), "end": round(agg[bi][1], 3)} for bi in sorted(agg)]
    for j in range(len(spans) - 1):
        spans[j]["end"] = max(spans[j]["end"], spans[j + 1]["start"])
    svgs = {}
    for sp in spans:
        f = src / "svgs" / (re.sub(r"[^A-Za-z0-9_.-]", "_", sp["beat_id"]) + ".svg")
        if f.is_file():
            svgs[sp["beat_id"]] = f.read_text(encoding="utf-8")
    out_dir = Path(__file__).resolve().parent / "bundles"
    out_dir.mkdir(parents=True, exist_ok=True)
    out = out_dir / (src.name + ".review.json")
    body = json.dumps({"title": src.name, "spans": spans, "svgs": svgs}, ensure_ascii=False)
    out.write_text(body, encoding="utf-8")
    print(f"wrote {out}  ({len(spans)} slides, {len(svgs)} svgs, {out.stat().st_size // 1024} KB)")
    if len(sys.argv) == 4:
        import urllib.request
        server, code = sys.argv[2].rstrip("/"), sys.argv[3]
        # authenticate, then push the bundle - one command centralizes the slides
        auth = urllib.request.Request(server + "/api/auth", data=json.dumps({"code": code}).encode(),
                                      headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(auth, timeout=15) as r:
            cookie = "; ".join(c.split(";")[0] for c in r.headers.get_all("Set-Cookie") or [])
            if not json.loads(r.read()).get("ok"):
                raise SystemExit("server rejected the code")
        req = urllib.request.Request(server + "/api/bundle?name=" + urllib.parse.quote(src.name),
                                     data=body.encode(), headers={"Content-Type": "application/json",
                                                                  "Cookie": cookie})
        with urllib.request.urlopen(req, timeout=60) as r:
            print("pushed to", server, "->", r.read().decode())

if __name__ == "__main__":
    main()
