"""The one local page a PAUSED CORPUSfm serves to a new browser navigation (packet 1361-01, round 3).

**Why it is a hand-written string and not a template.** Every ordinary page in this application is a
server-rendered shell whose context asks the database questions: who is signed in (USER), what the
landing page and locale are (SETTINGS), whether AI is configured, which docs side the user prefers.
A paused process may ask none of them, so the waiting page carries no context, extends no base
template, imports no auth dependency, and reads no preference. It is a complete, self-contained
document with its own inline CSS and one inline script.

**What it does.** It says why the process is paused and polls the ONE local liveness fact —
``/api/health``'s ``database_ready`` — so the browser reloads itself the moment the gate reopens.
That poll is the only addition to the paused listener surface: no readiness endpoint of its own, no
status API, no diagnostics.

**Three explanations, one state (packet 1361-01, round 7).** The copy distinguishes initialization
in progress, a database that is away with recovery retrying, and a deterministic condition that
needs an administrator. Those are DIAGNOSTIC reasons within the single PAUSED state — they change
what a person is told and nothing else. No phase permits partial operation, none of them makes a
functional surface answer, and the page reads all three from process state it already has.

**Reopening re-enters normal authentication.** The reload re-requests the same URL and lets the
application's own auth decide: a session that is still valid continues, and one that is not is
redirected to sign-in exactly as it would be at any other time. The page asserts nothing about the
prior session, and it carries no session logic of its own.

**What it deliberately does not do.** It offers no retry button that would provoke a database read,
no sign-in form, no navigation into the application, and no diagnostic detail. The precise reason a
box is paused belongs to the server log, the MCP ``get_health`` tool and the installer's own
out-of-band surfaces — the places the Unknowable-Install Principle requires an unreachable box to be
diagnosable from — never to an unauthenticated page.
"""

from __future__ import annotations

_PAGE = """<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CORPUSfm — database unavailable</title>
<style>
  :root {{ color-scheme: dark light; }}
  html, body {{ height: 100%; margin: 0; }}
  body {{
    background: #14171f; color: #d8dce6;
    font: 15px/1.6 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    display: flex; align-items: center; justify-content: center; padding: 24px;
  }}
  .card {{
    max-width: 40rem; width: 100%; background: #1b1f2a; border: 1px solid #2e3340;
    border-radius: 10px; padding: 28px 32px;
  }}
  h1 {{ font-size: 1.25rem; margin: 0 0 12px; color: #f0f2f6; font-weight: 600; }}
  p {{ margin: 0 0 12px; }}
  .muted {{ color: #8b92a5; font-size: 13px; }}
  .dot {{
    display: inline-block; width: 8px; height: 8px; border-radius: 50%;
    background: #d98b3a; margin-right: 8px; vertical-align: middle;
    animation: pulse 1.6s ease-in-out infinite;
  }}
  @keyframes pulse {{ 0%, 100% {{ opacity: 1; }} 50% {{ opacity: .3; }} }}
  .dot.stopped {{ background: #b4544e; animation: none; }}
  .detail {{ border-left: 2px solid #3a4152; padding-left: 12px; color: #b9c0d0; }}
</style>
</head><body>
<main class="card">
  <h1><span class="dot{dot_class}"></span>{heading}</h1>
  {body}
</main>
<script>
(function () {{
  var url = {health_url!r};
  function poll() {{
    fetch(url, {{ cache: "no-store", credentials: "same-origin" }})
      .then(function (r) {{ return r.ok ? r.json() : null; }})
      .then(function (d) {{ if (d && d.database_ready) {{ location.reload(); }} }})
      .catch(function () {{}});
  }}
  setInterval(poll, 5000);
}})();
</script>
</body></html>
"""


#: phase → (heading, body, dot modifier). One entry per diagnostic reason, and the fallback is the
#: outage copy because that is the honest default for a paused process with no better answer.
_COPY = {
    "initializing": (
        "Starting up",
        "<p>CORPUSfm is initializing: it is asserting its FileMaker storage contract and building "
        "its catalog before it serves anything.</p>"
        "<p>This page reloads itself as soon as initialization succeeds. Nothing needs to be "
        "restarted.</p>"
        "<p class=\"muted\">A first start on a large corpus, or one that has to convert stored "
        "records, takes longer than a routine restart. The CORPUSfm server log names each step as "
        "it completes.</p>",
        ""),
    "unavailable": (
        "Database unavailable",
        "<p>CORPUSfm cannot read its FileMaker database, so it is paused. Stored artifacts are "
        "unaffected.</p>"
        "<p>It is waiting for automatic recovery and this page reloads itself as soon as the "
        "database answers again. Nothing needs to be restarted.</p>"
        "<p class=\"muted\">If this persists, check that FileMaker Server and its OData interface "
        "are running on this machine. The CORPUSfm server log records why each attempt failed.</p>",
        ""),
    "build_mismatch": (
        "Fresh installation required",
        "<p>The FileMaker database this CORPUSfm is pointed at was built for a different version of "
        "the application, so it is paused and is <strong>not</strong> retrying. Stored artifacts "
        "are unaffected.</p>"
        "<p class=\"detail\">{detail}</p>"
        "<p class=\"muted\">Once the installation is corrected, restart the CORPUSfm service; "
        "initialization runs again from the beginning. This page will not reload on its own.</p>",
        " stopped"),
    "intervention": (
        "Startup needs attention",
        "<p>CORPUSfm stopped during initialization on a condition that will not clear by itself, so "
        "it is paused and is <strong>not</strong> retrying. Stored artifacts are unaffected.</p>"
        "<p>An administrator needs to correct the condition. The CORPUSfm server log names the "
        "exact step that refused and why.</p>"
        "<p class=\"muted\">Once it is corrected, restart the CORPUSfm service; initialization "
        "runs again from the beginning. This page will not reload on its own.</p>",
        " stopped"),
}


def paused_page_html(health_url: str = "/api/health", phase: str = "unavailable",
                     detail: str = "") -> str:
    """The complete document for one diagnostic ``phase``.

    ``health_url`` is prefixed for the deployment's own route root. An unrecognised phase gets the
    outage copy — the honest default for a paused process with nothing more specific to say.

    ``detail`` is used by the build-mismatch copy ONLY, and it is the guidance sentence the startup
    chain composed from the two builds its probe had already read (packet 1361-01, round 11). It
    keeps the direction distinction the retired `/build-mismatch` page used to make — a database
    older than the code needs a fresh install, a database newer than the code means the wrong code is
    deployed — without this page performing a database read to establish it. Since round 12 retired
    that page, this is the ONLY build-mismatch surface the product has. It is HTML-escaped; every
    other phase's copy is static.
    """
    heading, body, dot_class = _COPY.get(phase) or _COPY["unavailable"]
    if "{detail}" in body:
        from html import escape
        body = body.replace("{detail}", escape(detail or "The CORPUSfm server log names the "
                                                        "installed and expected builds."))
    return _PAGE.format(health_url=health_url, heading=heading, body=body, dot_class=dot_class)
