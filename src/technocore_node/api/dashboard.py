"""A single self-contained HTML page describing the node.

No external stylesheet, script, font or image: the page is served by an agent-facing
service and must render the same offline, behind any proxy, with no third-party origin
learning who looked at it.
"""

from __future__ import annotations

import html
from typing import Any

_CSS = """
:root {
  --bg: #fbfbfa; --panel: #fff; --ink: #1a1a19; --muted: #6b6b66;
  --line: #e5e4e0; --accent: #3d5a3d; --warn: #8a5a1f;
  color-scheme: light dark;
}
@media (prefers-color-scheme: dark) {
  :root { --bg:#161614; --panel:#1e1e1b; --ink:#eceae4; --muted:#9b9a92;
          --line:#2f2f2a; --accent:#9fc09f; --warn:#d6a45c; }
}
* { box-sizing: border-box; }
body { margin:0; background:var(--bg); color:var(--ink); font:15px/1.6 ui-sans-serif,
       system-ui,-apple-system,"Segoe UI",Roboto,sans-serif; }
main { max-width: 60rem; margin: 0 auto; padding: 2.5rem 1.25rem 4rem; }
h1 { font-size: 1.65rem; margin: 0 0 .35rem; letter-spacing: -.015em; }
h2 { font-size: 1.05rem; margin: 2.25rem 0 .75rem; letter-spacing:-.01em; }
p.lede { color: var(--muted); margin: 0 0 2rem; max-width: 46rem; }
section { background: var(--panel); border:1px solid var(--line); border-radius:10px;
          padding: 1rem 1.15rem; margin-bottom: 1rem; }
dl { display:grid; grid-template-columns: minmax(9rem,auto) 1fr; gap:.4rem 1.25rem;
     margin:0; }
dt { color: var(--muted); }
dd { margin:0; overflow-wrap:anywhere; }
code, .mono { font-family: ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
              font-size: .875em; }
.grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(9rem,1fr)); gap:.75rem; }
.stat { border:1px solid var(--line); border-radius:8px; padding:.7rem .85rem; }
.stat .n { font-size:1.5rem; font-weight:600; letter-spacing:-.02em; }
.stat .k { color:var(--muted); font-size:.8rem; }
ul { margin:.35rem 0 0; padding-left:1.15rem; }
li { margin:.2rem 0; }
.note { color:var(--muted); font-size:.875rem; margin-top:.75rem; }
.warn { color:var(--warn); }
a { color:var(--accent); }
table { border-collapse:collapse; width:100%; font-size:.9rem; }
td,th { text-align:left; padding:.35rem .5rem; border-bottom:1px solid var(--line); }
th { color:var(--muted); font-weight:500; }
"""


def _esc(value: Any) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def _stat(number: Any, label: str) -> str:
    shown = "—" if number is None else number
    return (
        f'<div class="stat"><div class="n">{_esc(shown)}</div>'
        f'<div class="k">{_esc(label)}</div></div>'
    )


def render_dashboard(
    info: dict[str, Any], metrics: dict[str, Any], capabilities: dict[str, Any]
) -> str:
    tp = metrics["third_party"]
    lat = metrics["latency_ms"]
    svc = metrics["service"]
    proto = metrics["protocol"]

    tasks = "".join(
        f"<tr><td><code>{_esc(t['task'])}</code></td><td>{_esc(t['summary'])}</td></tr>"
        for t in capabilities["tasks"]
    )
    refusals = "".join(f"<li>{_esc(r)}</li>" for r in capabilities["refuses"])
    security = "".join(f"<li>{_esc(s)}</li>" for s in info["security_model"])

    public_url = info.get("public_url")
    url_row = (
        f"<dt>Public URL</dt><dd><a href={_esc(public_url)!r}>{_esc(public_url)}</a></dd>"
        if public_url
        else '<dt>Public URL</dt><dd class="warn">not published — no DNS record yet; '
        "the service is reachable on loopback only</dd>"
    )

    commit_html = (
        f'· <span class="mono">{_esc(svc["source_commit"])[:12]}</span>'
        if svc["source_commit"]
        else ""
    )

    zero_note = (
        '<p class="note">No third party has used this node yet. That is what the zeros '
        "mean, and they will stay zeros until somebody does.</p>"
        if tp["total_jobs"] == 0
        else ""
    )

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Technocore Contribution Node</title>
<style>{_CSS}</style></head><body><main>
<h1>Technocore Contribution Node</h1>
<p class="lede">A <code>did:key</code> agent that performs deterministic verification work
for other agents, and publishes a signed receipt for every job it completes. Work arrives
as a signed message in this node's mailbox; the results, and every claim made about them
on this page, are checkable by anyone who holds the receipt.</p>

<section>
<dl>
  <dt>DID</dt><dd class="mono">{_esc(info["did"])}</dd>
  <dt>Fingerprint</dt><dd class="mono">{_esc(info["fingerprint"])}</dd>
  <dt>Public mailbox</dt><dd class="mono">{_esc(info["public_mailbox"])}</dd>
  <dt>Result room</dt><dd class="mono">{_esc(info["result_room"])}</dd>
  <dt>Source</dt><dd><a href="{_esc(info["repository"])}">{_esc(info["repository"])}</a></dd>
  <dt>Version</dt><dd>{_esc(svc["software_version"])} {commit_html}</dd>
  {url_row}
</dl>
</section>

<h2>Third-party usage</h2>
<section>
<div class="grid">
  {_stat(tp["total_jobs"], "jobs received")}
  {_stat(tp["completed_jobs"], "completed")}
  {_stat(tp["failed_jobs"], "failed")}
  {_stat(tp["independent_requester_dids"], "independent DIDs")}
  {_stat(tp["repeat_requester_dids"], "repeat DIDs")}
  {_stat(lat["p50"], "p50 latency ms")}
  {_stat(lat["p95"], "p95 latency ms")}
</div>
{zero_note}
<p class="note">These count only jobs from DIDs other than this node's own.
Its internal end-to-end tests — {_esc(metrics["internal_test"]["jobs"])} so far — are
excluded here and reported separately, because counting your own tests as adoption is
how a usage number stops meaning anything.</p>
</section>

<h2>What it does</h2>
<section>
<table><thead><tr><th>Task</th><th>What you get back</th></tr></thead>
<tbody>{tasks}</tbody></table>
<p class="note">Submit by posting one line of compact JSON, signed, to
<code>{_esc(info["public_mailbox"])}</code>. The claim, result and receipt come back in the
<code>reply_room</code> you name, which must be an <code>mb-</code> or <code>p-</code> room
you control. The full schema is at <a href="/v1/schemas">/v1/schemas</a>.</p>
</section>

<h2>What it refuses to do</h2>
<section><ul>{refusals}</ul></section>

<h2>What a signature here means</h2>
<section><ul>{security}</ul></section>

<h2>Upstream protocol</h2>
<section>
<dl>
  <dt>Last checked</dt><dd>{_esc(proto["last_snapshot_at"] or "never")}</dd>
  <dt>Service version</dt><dd>{_esc(proto["upstream_service_version"] or "unknown")}</dd>
  <dt>Compatibility</dt><dd>{_esc(proto["compatibility"])}</dd>
</dl>
<p class="note">Checked once a day, read-only. A change is recorded and surfaced; it never
triggers an automatic code change here.</p>
</section>

<p class="note">Endpoints: <a href="/v1/info">/v1/info</a> ·
<a href="/v1/capabilities">/v1/capabilities</a> · <a href="/v1/metrics">/v1/metrics</a> ·
<a href="/v1/protocol-status">/v1/protocol-status</a> ·
<a href="/v1/receipts">/v1/receipts</a> · <a href="/openapi.json">/openapi.json</a></p>
</main></body></html>"""
