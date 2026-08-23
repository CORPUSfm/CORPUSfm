#!/bin/bash
# cfm-web-proxy — front CORPUSfm through FileMaker Server's web server at a sub-path.
#
# Co-located deployment: CORPUSfm runs on loopback (127.0.0.1:PORT) under PREFIX, and the
# FMS web server (nginx on FMS 2026, Apache on older FMS) reverse-proxies PREFIX/ to it,
# reusing FMS's existing TLS cert + hostname. This is the OttoFMS pattern (own listener +
# one proxy block). We never touch the cert.
#
# Idempotent + re-runnable (FMS rewrites its web config on upgrades, so the installer
# re-applies this every run). Marker-wrapped so a prior block is cleanly replaced.
# DEFENSIVE: backs up the FMS config, validates before reload, rolls back on failure —
# a bad edit must never break FMS's own :443.
#
# Usage: cfm-web-proxy [check] <prefix> <loopback_port>   e.g. cfm-web-proxy /corpusfm 8533
#   check — report WITHOUT mutating: exit 0 if the proxy is already current (no FMS web-server
#           restart needed), exit 1 if it would change (restart needed). Lets the installer decide
#           up front whether FMS admin credentials are required for this run. (`check` reads config
#           files only — it needs root, but NOT fmsadmin credentials.)
set -euo pipefail

MODE=apply
case "${1:-}" in
  check)  MODE=check;  shift ;;
  remove) MODE=remove; shift ;;   # strip our proxy block + reload (the uninstall companion)
esac

PREFIX="${1:?usage: cfm-web-proxy [check] <prefix> <port>}"
PORT="${2:?usage: cfm-web-proxy [check] <prefix> <port>}"
PREFIX="/${PREFIX#/}"; PREFIX="${PREFIX%/}"          # normalize to /corpusfm (no trailing /)
MARK="CORPUSFM"
FMS="/opt/FileMaker/FileMaker Server"

# Whether to publish the RFC 9728 MCP metadata routes (packet 1175). The installer threads its
# ENABLE_MCP state in via CFM_MCP_ENABLED (1 = MCP installed → publish the host-root metadata routes;
# 0 = --no-mcp → OMIT them, so a re-apply removes any previously-installed ones). Default 1 (MCP
# installs by default); any value other than exactly "0" is treated as enabled.
MCP_ENABLED="${CFM_MCP_ENABLED:-1}"
[[ "$MCP_ENABLED" == "0" ]] || MCP_ENABLED="1"

die() { echo "cfm-web-proxy: $1" >&2; exit 1; }
info() { echo "cfm-web-proxy: $1"; }

[[ "$PORT" =~ ^[0-9]+$ ]] || die "port not numeric: $PORT"

# ── Which web server fronts :443? ────────────────────────────────────────────────
front=""
if ss -ltnp 2>/dev/null | grep -q ':443 .*nginx'; then front="nginx"
elif ss -ltnp 2>/dev/null | grep -qE ':443 .*(httpd|apache2)'; then front="apache"
elif [[ -f "$FMS/NginxServer/conf/fms_nginx.conf" ]]; then front="nginx"
elif [[ -d "$FMS/HTTPServer/conf" ]]; then front="apache"
else
  die "no FileMaker Server web server detected — cannot front CORPUSfm (is FMS installed here?)"
fi
info "FMS web front: $front"

# Reload the FMS web server. IMPORTANT: FMS's nginx does NOT honor reload signals on this
# build (nginx -s reload / SIGHUP hang or no-op) — the only reliable reload is the
# FMS-managed restart, which fully restarts the web server (brief Admin-API/OData/WebDirect
# blip; FileMaker Pro clients on fmnet are unaffected). Validate the config FIRST so a bad
# edit never takes the web server down on restart. Creds from env (FM_ADMIN_USER/PASS) when
# the installer has them; best-effort otherwise with a clear manual-step message.
reload_fms_web() {
  local note="${1:-config reloaded}"
  local fa; fa="$(command -v fmsadmin || true)"
  [[ -z "$fa" ]] && fa="/opt/FileMaker/FileMaker Server/Database Server/bin/fmsadmin"
  local args=(restart httpserver -y)
  [[ -n "${FM_ADMIN_USER:-}" ]] && args+=(-u "$FM_ADMIN_USER")
  [[ -n "${FM_ADMIN_PASS:-}" ]] && args+=(-p "$FM_ADMIN_PASS")
  if timeout 120 "$fa" "${args[@]}" >/dev/null 2>&1; then
    info "FMS web server restarted — $note"
  else
    echo "cfm-web-proxy: config written + validated, but could NOT auto-restart the FMS web" >&2
    echo "  server. Apply it manually:  fmsadmin restart httpserver -y" >&2
  fi
}

# ─────────────────────────────────────────────────────────────────────────────────
apply_nginx() {
  local dir="$FMS/NginxServer/conf"
  local main="$dir/fms_nginx.conf"
  local inc="$dir/corpusfm_https.conf"
  [[ -f "$main" ]] || die "nginx conf not found: $main"

  # The ordinary reverse proxy — always present, independent of MCP.
  local desired; desired="$(cat <<NGINC
location ^~ ${PREFIX}/ {
  proxy_http_version 1.1;
  proxy_set_header Host \$host;
  proxy_set_header X-Forwarded-Proto https;
  proxy_set_header X-Forwarded-Host \$host:\$server_port;
  proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
  proxy_set_header X-Forwarded-Prefix ${PREFIX};
  proxy_buffer_size 128k;
  proxy_buffers 4 256k;
  proxy_busy_buffers_size 256k;
  client_max_body_size 0;
  proxy_read_timeout 600;
  # strip the prefix: the app (uvicorn --root-path ${PREFIX}) routes on the plain path
  # and uses root_path only for URL generation. ${PREFIX}/login -> backend /login.
  proxy_pass http://127.0.0.1:${PORT}/;
}
NGINC
)"

  # RFC 9728 protected-resource metadata (packet 1175) lives at the HOST ROOT, OUTSIDE ${PREFIX}/:
  #   /.well-known/oauth-protected-resource${PREFIX}/mcp  (and its trailing-slash form)
  # so the ^~ ${PREFIX}/ block never sees it. These two EXACT-match locations forward that host-root
  # path UNCHANGED (no prefix strip — proxy_pass with no URI) to the app, which serves the RFC 9728
  # document there (uvicorn --root-path ${PREFIX} still routes the plain path). Additive within
  # CORPUSfm's OWN include — the main fms_nginx.conf gains nothing beyond the include line it already
  # has; exact `location =` is deterministic (no descendant, e.g. .../mcp/x, ever matches), so it
  # cannot shadow or be shadowed by FMS's own rules. Both forms are emitted because the 401 challenge
  # points at the trailing-slash URL but a compliant client may request either. Emitted ONLY when the
  # MCP is enabled — with --no-mcp the app has no /mcp, so these routes are OMITTED (a re-apply then
  # rewrites the include WITHOUT them, removing any previously-installed metadata routes) while the
  # ordinary ${PREFIX}/ proxy above is retained.
  if [[ "$MCP_ENABLED" == "1" ]]; then
    local wk="/.well-known/oauth-protected-resource${PREFIX}/mcp"
    # Packet 1179: the RFC 8414 authorization-server metadata (served only when browser OAuth is
    # enabled at runtime; the app 404s these while it's off — harmless). Stage-A-proven exact forms for
    # issuer <host>${PREFIX}/mcp: the prefixed oauth-authorization-server + its openid-configuration
    # alias. The bare host-root /.well-known/openid-configuration is deliberately NOT claimed here (our
    # FMS proxy forwards the prefix UNCHANGED, so the prefixed forms are the reachable ones; leaving the
    # bare host-root path unclaimed keeps a shared FMS box's neighbor paths untouched).
    local as="/.well-known/oauth-authorization-server${PREFIX}/mcp"
    local oidc="/.well-known/openid-configuration${PREFIX}/mcp"
    desired="${desired}
$(cat <<NGWK
location = ${wk} {
  proxy_http_version 1.1;
  proxy_set_header Host \$host;
  proxy_set_header X-Forwarded-Proto https;
  proxy_set_header X-Forwarded-Host \$host:\$server_port;
  proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
  proxy_set_header X-Forwarded-Prefix ${PREFIX};
  # forward the host-root path UNCHANGED (no trailing URI on proxy_pass = pass the URI as-is).
  proxy_pass http://127.0.0.1:${PORT};
}
location = ${wk}/ {
  proxy_http_version 1.1;
  proxy_set_header Host \$host;
  proxy_set_header X-Forwarded-Proto https;
  proxy_set_header X-Forwarded-Host \$host:\$server_port;
  proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
  proxy_set_header X-Forwarded-Prefix ${PREFIX};
  proxy_pass http://127.0.0.1:${PORT};
}
location = ${as} {
  proxy_http_version 1.1;
  proxy_set_header Host \$host;
  proxy_set_header X-Forwarded-Proto https;
  proxy_set_header X-Forwarded-Host \$host:\$server_port;
  proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
  proxy_set_header X-Forwarded-Prefix ${PREFIX};
  proxy_pass http://127.0.0.1:${PORT};
}
location = ${oidc} {
  proxy_http_version 1.1;
  proxy_set_header Host \$host;
  proxy_set_header X-Forwarded-Proto https;
  proxy_set_header X-Forwarded-Host \$host:\$server_port;
  proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
  proxy_set_header X-Forwarded-Prefix ${PREFIX};
  proxy_pass http://127.0.0.1:${PORT};
}
NGWK
)"
  fi

  # Idempotent: if the include is already identical AND the main config still includes it,
  # nothing changed — skip the FMS web-server restart (it briefly blips OData/WebDirect/Admin-API,
  # so we must not do it on every upgrade). FMS only wipes our block on an FMS upgrade; that
  # leaves the include missing → the check fails → we re-apply + restart. So it self-heals without
  # a needless restart on routine CORPUSfm upgrades.
  if [[ -f "$inc" ]] && printf '%s\n' "$desired" | cmp -s - "$inc" \
     && grep -q "include \"${inc}\"" "$main"; then
    [[ "$MODE" == check ]] && { info "proxy already current — no restart needed"; exit 0; }
    echo "  CORPUSfm proxy already current at ${PREFIX}/ — no web-server restart needed." >&2
    return 0
  fi
  [[ "$MODE" == check ]] && { info "proxy change needed — FMS web-server restart required"; exit 1; }

  # Back up the include too — we overwrite it BEFORE validating the edited main, so if validation
  # fails and we roll main back, we must also restore (or remove) the include; otherwise a
  # rolled-back main that still references it would pick up the changed file on the next restart.
  local inc_bak=""
  [[ -f "$inc" ]] && { inc_bak="$(mktemp)"; cp "$inc" "$inc_bak"; }
  printf '%s\n' "$desired" > "$inc"

  local bak; bak="$(mktemp)"; cp "$main" "$bak"
  # strip any prior marked block, then insert a fresh one after the otto include if present,
  # else after the fms_fac.conf include (a known directive inside the :443 server block).
  local tmp; tmp="$(mktemp)"
  awk -v inc="$inc" -v mark="$MARK" '
    $0 ~ ("### *" mark) { skip = !skip; next }     # toggle: drop lines between ###CORPUSFM markers
    skip { next }
    { print }
  ' "$main" > "$tmp"

  local blk="    ###${MARK}\n    include \"${inc}\";\n    ###${MARK}"
  # Placement matters: OttoFMS wraps its include in a ###OTTO…###OTTO region and a background
  # watcher RE-INJECTS its block if it sees that region modified — so inserting ours INSIDE it
  # (between the otto include and the closing ###OTTO) trips the watcher, which duplicates the
  # /otto/ location and breaks nginx STARTUP (a running instance keeps serving the old config,
  # so it only surfaces on the next reboot — exactly what bit us live on 2026-06-19). Anchor
  # AFTER the closing ###OTTO marker — outside Otto's managed region. Fall back to the bare
  # otto include, then fms_fac, for configs without the markers.
  if grep -q '###OTTO' "$tmp"; then
    awk -v blk="$blk" '
      { print }
      /otto_https\.conf/ { armed=1 }
      armed && /^[[:space:]]*###OTTO[[:space:]]*$/ && !done { printf "%s\n", blk; done=1; armed=0 }
    ' "$tmp" > "$tmp.2"
  elif grep -q 'otto_https.conf' "$tmp"; then
    awk -v blk="$blk" '/otto_https.conf/ && !done { print; printf "%s\n", blk; done=1; next } { print }' "$tmp" > "$tmp.2"
  elif grep -q 'fms_fac.conf' "$tmp"; then
    awk -v blk="$blk" '/fms_fac.conf/ && !done { print; printf "%s\n", blk; done=1; next } { print }' "$tmp" > "$tmp.2"
  else
    die "could not find an anchor (###OTTO / otto / fms_fac) in $main to place the proxy block"
  fi
  mv "$tmp.2" "$tmp"
  grep -q "include \"${inc}\"" "$tmp" || { rm -f "$tmp" "$bak"; die "failed to insert include"; }

  cp "$tmp" "$main"; rm -f "$tmp"
  # Validate the edited config, then roll back if invalid (never break :443 on the restart),
  # else reload via the FMS-managed restart (signals don't work — see reload_fms_web).
  #
  # We can't use `nginx -t` here: it HANGS on this FMS build (so does `-T`). And a plain
  # foreground start would collide with the LIVE FMS nginx on :443. So: foreground-start
  # nginx against FMS's own config and read the outcome —
  #   • rc 124 (ran until the timeout)            → :443 was free, config served fine  → VALID
  #   • stderr says "Address already in use"      → config PARSED ok; only the bind to the
  #                                                  already-served :443 failed          → VALID
  #   • any other [emerg] (duplicate location, …) → a real config error                 → INVALID
  # On a bind failure nginx exits BEFORE writing its pid file, so this never disturbs the
  # running FMS nginx. Run with daemon off so the timeout can reap it.
  local ngx; ngx="$(command -v nginx || echo /usr/sbin/nginx)"
  local out rc
  out="$(timeout 8 "$ngx" -c "$main" -g 'daemon off;' 2>&1)"; rc=$?
  if [[ "$rc" -eq 124 ]] || printf '%s' "$out" | grep -q 'Address already in use'; then
    rm -f "$bak" "$inc_bak"
    reload_fms_web "${PREFIX}/ now proxied to 127.0.0.1:${PORT}"
  else
    cp "$bak" "$main"; rm -f "$bak"
    # Restore the include to its prior content, or remove it if it didn't exist before — so the
    # rolled-back config is exactly what it was, with nothing of ours left behind.
    if [[ -n "$inc_bak" ]]; then cp "$inc_bak" "$inc"; rm -f "$inc_bak"; else rm -f "$inc"; fi
    printf '%s\n' "$out" | grep -i 'emerg' | tail -3 >&2
    die "nginx config test FAILED — rolled back $main (no changes applied)"
  fi
}

# ─────────────────────────────────────────────────────────────────────────────────
# remove_nginx — the uninstall companion to apply_nginx. Strip our ###CORPUSFM block from the main
# config + delete the include, validate (the same foreground-start trick), then reload. Idempotent:
# if no block is present it is a no-op (NO restart). The marker is constant, so PREFIX/PORT are only
# used for messages here.
remove_nginx() {
  local dir="$FMS/NginxServer/conf"
  local main="$dir/fms_nginx.conf"
  local inc="$dir/corpusfm_https.conf"
  [[ -f "$main" ]] || { info "nginx conf not found — nothing to remove"; return 0; }
  if ! grep -q "### *${MARK}" "$main" && [[ ! -f "$inc" ]]; then
    info "no CORPUSfm proxy block present — nothing to remove (no restart)"
    return 0
  fi
  local bak; bak="$(mktemp)"; cp "$main" "$bak"
  local tmp; tmp="$(mktemp)"
  awk -v mark="$MARK" '
    $0 ~ ("### *" mark) { skip = !skip; next }     # drop lines between the ###CORPUSFM markers
    skip { next }
    { print }
  ' "$main" > "$tmp"
  cp "$tmp" "$main"; rm -f "$tmp"; rm -f "$inc"
  local ngx; ngx="$(command -v nginx || echo /usr/sbin/nginx)"
  local out rc
  out="$(timeout 8 "$ngx" -c "$main" -g 'daemon off;' 2>&1)"; rc=$?
  if [[ "$rc" -eq 124 ]] || printf '%s' "$out" | grep -q 'Address already in use'; then
    rm -f "$bak"
    info "CORPUSfm proxy block removed from $main"
    reload_fms_web "CORPUSfm proxy removed from ${PREFIX}/"
  else
    cp "$bak" "$main"; rm -f "$bak"
    printf '%s\n' "$out" | grep -i 'emerg' | tail -3 >&2
    die "nginx config test FAILED after removing the block — rolled back $main"
  fi
}

# ─────────────────────────────────────────────────────────────────────────────────
apply_apache() {
  local conf="$FMS/HTTPServer/conf/extra/httpd-proxy.conf"
  [[ -f "$conf" ]] || die "apache proxy conf not found: $conf"

  # RFC 9728 protected-resource metadata (packet 1175): the host-root path
  #   /.well-known/oauth-protected-resource${PREFIX}/mcp  (+ trailing-slash form)
  # is EXACT-match only — ProxyPassMatch with an anchored `$` so a descendant (.../mcp/x) never
  # matches — forwarded UNCHANGED to the loopback app (the nginx `location =` parity). Emitted ONLY
  # when the MCP is enabled; with --no-mcp these lines are OMITTED (a re-apply rewrites the block
  # without them) while the ordinary ${PREFIX}/ proxy is retained. `\.` keeps `.well-known` literal.
  # Packet 1179: the RFC 8414 authorization-server metadata (Stage-A exact forms for issuer
  # <host>${PREFIX}/mcp) — the prefixed oauth-authorization-server + its openid-configuration alias,
  # each EXACT-match (anchored `$`, no descendant). Served only when browser OAuth is enabled at
  # runtime (the app 404s them while off — harmless). Gated on the same MCP_ENABLED state. The bare
  # host-root /.well-known/openid-configuration is deliberately NOT claimed (see the nginx note).
  local wk_apache=""
  if [[ "$MCP_ENABLED" == "1" ]]; then
    wk_apache="$(cat <<APACHEWK
  ProxyPassMatch "^/\.well-known/oauth-protected-resource${PREFIX}/mcp\$" "http://127.0.0.1:${PORT}/.well-known/oauth-protected-resource${PREFIX}/mcp"
  ProxyPassMatch "^/\.well-known/oauth-protected-resource${PREFIX}/mcp/\$" "http://127.0.0.1:${PORT}/.well-known/oauth-protected-resource${PREFIX}/mcp/"
  ProxyPassMatch "^/\.well-known/oauth-authorization-server${PREFIX}/mcp\$" "http://127.0.0.1:${PORT}/.well-known/oauth-authorization-server${PREFIX}/mcp"
  ProxyPassMatch "^/\.well-known/openid-configuration${PREFIX}/mcp\$" "http://127.0.0.1:${PORT}/.well-known/openid-configuration${PREFIX}/mcp"
APACHEWK
)"
  fi

  local block; block="$(cat <<APACHE
# ${MARK}
<IfModule mod_proxy.c>
  ProxyPreserveHost On
  RequestHeader set X-Forwarded-Proto "https"
  RequestHeader set X-Forwarded-Prefix "${PREFIX}"
${wk_apache:+$wk_apache
}  ProxyPass ${PREFIX}/ http://127.0.0.1:${PORT}/
  ProxyPassReverse ${PREFIX}/ http://127.0.0.1:${PORT}/
</IfModule>
# ${MARK}
APACHE
)"

  # Idempotent: if the existing marked block is already identical, skip the FMS web-server restart
  # (avoid a needless OData/WebDirect/Admin-API blip on every upgrade). The current block is the
  # text between the two `# CORPUSFM` markers; compare it to the desired block.
  local current; current="$(awk -v mark="$MARK" '
    $0 ~ ("# *" mark) { if (!seen) { seen=1; print; next } else { print; exit } }
    seen { print }
  ' "$conf")"
  if [[ -n "$current" ]] && [[ "$current" == "$block" ]]; then
    [[ "$MODE" == check ]] && { info "proxy already current — no restart needed"; exit 0; }
    echo "  CORPUSfm proxy already current at ${PREFIX}/ — no web-server restart needed." >&2
    return 0
  fi
  [[ "$MODE" == check ]] && { info "proxy change needed — FMS web-server restart required"; exit 1; }

  local bak; bak="$(mktemp)"; cp "$conf" "$bak"
  local tmp; tmp="$(mktemp)"
  awk -v mark="$MARK" '
    $0 ~ ("# *" mark) { skip = !skip; next }
    skip { next }
    { print }
  ' "$conf" > "$tmp"
  printf '%s\n' "$block" >> "$tmp"
  cp "$tmp" "$conf"; rm -f "$tmp"
  local httpd; httpd="$(command -v apachectl || command -v apache2ctl || echo "$FMS/HTTPServer/bin/httpd")"
  if timeout 30 "$httpd" -t >/dev/null 2>&1 || timeout 30 "$FMS/HTTPServer/bin/httpd" -t >/dev/null 2>&1; then
    rm -f "$bak"
    reload_fms_web "${PREFIX}/ now proxied to 127.0.0.1:${PORT}"
  else
    cp "$bak" "$conf"; rm -f "$bak"
    die "apache config test FAILED — rolled back $conf (no changes applied)"
  fi
}

# ─────────────────────────────────────────────────────────────────────────────────
# remove_apache — the uninstall companion to apply_apache. Strip our # CORPUSFM block + reload.
remove_apache() {
  local conf="$FMS/HTTPServer/conf/extra/httpd-proxy.conf"
  [[ -f "$conf" ]] || { info "apache proxy conf not found — nothing to remove"; return 0; }
  if ! grep -q "# *${MARK}" "$conf"; then
    info "no CORPUSfm proxy block present — nothing to remove (no restart)"
    return 0
  fi
  local bak; bak="$(mktemp)"; cp "$conf" "$bak"
  local tmp; tmp="$(mktemp)"
  awk -v mark="$MARK" '
    $0 ~ ("# *" mark) { skip = !skip; next }
    skip { next }
    { print }
  ' "$conf" > "$tmp"
  cp "$tmp" "$conf"; rm -f "$tmp"
  local httpd; httpd="$(command -v apachectl || command -v apache2ctl || echo "$FMS/HTTPServer/bin/httpd")"
  if timeout 30 "$httpd" -t >/dev/null 2>&1 || timeout 30 "$FMS/HTTPServer/bin/httpd" -t >/dev/null 2>&1; then
    rm -f "$bak"
    info "CORPUSfm proxy block removed from $conf"
    reload_fms_web "CORPUSfm proxy removed from ${PREFIX}/"
  else
    cp "$bak" "$conf"; rm -f "$bak"
    die "apache config test FAILED after removing the block — rolled back $conf"
  fi
}

if [[ "$MODE" == remove ]]; then
  [[ "$front" == "nginx" ]] && remove_nginx || remove_apache
else
  [[ "$front" == "nginx" ]] && apply_nginx || apply_apache
fi
