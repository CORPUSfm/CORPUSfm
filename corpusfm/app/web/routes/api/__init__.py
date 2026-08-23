"""API sub-routers — all mounted under /api/ in app.py.

Router-level gate enforcement (the API↔page authorization invariant): the JSON APIs must carry the
SAME gate as the page they back — otherwise a direct API call bypasses the nav boundary (the
same lesson as MCP tool visibility). Single-gate routers are gated HERE at the include point (one
auditable place); mixed routers gate per-route in their own file (generate = library_mcp + patching;
settings/users/admin_pki/patch_ops/indexed already gate internally). `require_gate` is soft on a
missing user, so it pairs with each route's own `require_auth` (login → 401, ungated → 403); both
no-op outside server mode (the test/dev path).
"""

from fastapi import APIRouter, Depends

from corpusfm.app.web.auth import require_gate

from .notifications import router as notifications_router
from .upload import router as upload_router
from .generate import router as generate_router
from .library import router as library_router
from .alerts import router as alerts_router
from .jobs import router as jobs_router
from .settings import router as settings_router
from .logs import router as logs_router
from .server import router as server_router
from .merged import router as merged_router
from .addons import router as addons_router
from .admin_pki import router as admin_pki_router
from .tags import router as tags_router
from .patch_ops import router as patch_ops_router
from .diff_history import router as diff_history_router
from .explore_history import router as explore_history_router
from .indexed import router as indexed_router
from .queue import router as queue_router
from .import_queue import router as import_queue_router
from .files import router as files_router
from .users import router as users_router
from .clip import router as clip_router
from .access import router as access_router

def _gate(name: str):
    return [Depends(require_gate(name))]


router = APIRouter()
router.include_router(notifications_router)                                  # status/health — any user
router.include_router(upload_router)                                        # mixed (session/bearer) — gated in-file
router.include_router(generate_router)                                      # mixed (library_mcp + patching) — in-file
router.include_router(library_router, dependencies=_gate("library_mcp"))
router.include_router(alerts_router, dependencies=_gate("automation"))
router.include_router(jobs_router, dependencies=_gate("automation"))
router.include_router(settings_router)                                      # internally _ADMIN + intentional any-user routes
router.include_router(logs_router, dependencies=_gate("settings"))
router.include_router(server_router)                                        # empty (reserved)
router.include_router(merged_router, dependencies=_gate("library_mcp"))
router.include_router(addons_router, dependencies=_gate("library_mcp"))
router.include_router(admin_pki_router)                                     # already router-level settings
router.include_router(tags_router, dependencies=_gate("library_mcp"))
router.include_router(patch_ops_router)                                     # already router-level patching
router.include_router(diff_history_router, dependencies=_gate("library_mcp"))
router.include_router(explore_history_router, dependencies=_gate("library_mcp"))
router.include_router(indexed_router)                                       # already require_any_gate(library_mcp, settings)
router.include_router(queue_router)                                         # view = any authed user; mutate = owner-or-admin (in-file)
router.include_router(import_queue_router, dependencies=_gate("library_mcp"))  # durable import: source/poke/cancel
router.include_router(files_router, dependencies=_gate("automation"))
router.include_router(users_router)                                         # already router/route-level settings
router.include_router(clip_router, dependencies=_gate("library_mcp"))       # clipboard Paste intake (packet 1025)
router.include_router(access_router)                                        # external-auth config — internally _ADMIN (packet 1065)
