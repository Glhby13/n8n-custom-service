#!/usr/bin/env bash
# =============================================================================
# discover.sh — READ-ONLY discovery of the n8n public API (Phase 0B).
#
# * Performs only HTTP GET requests. It never creates, updates, publishes or deletes anything.
# * The API key is read from $N8N_API_KEY or, if unset, from stdin (hidden prompt).
#   It is never printed, never written to disk, never passed on a command line.
# * Prints a Markdown report of response STRUCTURE (field names, types, ownership shape,
#   version ids). It does not print node parameters or any workflow content.
#
# Usage:
#   export N8N_BASE_URL=https://n8n.dev.btn.co.id      # default
#   read -rs N8N_API_KEY && export N8N_API_KEY          # or let the script prompt
#   ./scripts/discover.sh [workflow-id]  > discovery-output.md
#
# Optional: N8N_CA_FILE=/path/ca.pem (extra CA), WORKFLOW_ID=<id> (representative workflow).
# Not covered (needs writes, do it manually on a throw-away workflow): PUT + activate behaviour.
# =============================================================================
set -euo pipefail

export N8N_BASE_URL="${N8N_BASE_URL:-https://n8n.dev.btn.co.id}"
export WORKFLOW_ID="${1:-${WORKFLOW_ID:-}}"

if [ -z "${N8N_API_KEY:-}" ]; then
  if [ -t 0 ]; then
    printf 'n8n API key (input hidden): ' >&2
    IFS= read -rs N8N_API_KEY
    printf '\n' >&2
  else
    IFS= read -r N8N_API_KEY
  fi
fi
if [ -z "${N8N_API_KEY:-}" ]; then
  echo "no API key supplied" >&2
  exit 2
fi
export N8N_API_KEY

exec python3 -I - <<'PY'
import json, os, ssl, sys, urllib.request, urllib.error, collections

BASE = os.environ["N8N_BASE_URL"].rstrip("/") + "/api/v1"
KEY = os.environ.pop("N8N_API_KEY")
ctx = ssl.create_default_context()
if os.environ.get("N8N_CA_FILE"):
    ctx.load_verify_locations(os.environ["N8N_CA_FILE"])

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None

opener = urllib.request.build_opener(NoRedirect, urllib.request.HTTPSHandler(context=ctx))

def get(path):
    req = urllib.request.Request(BASE + path, method="GET",
                                 headers={"X-N8N-API-KEY": KEY, "Accept": "application/json"})
    try:
        with opener.open(req, timeout=20) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, None
    except Exception as e:  # never echo request headers
        return None, type(e).__name__

def typ(v):
    if v is None: return "null"
    return {dict: "object", list: "array", str: "string", bool: "boolean", int: "number", float: "number"}.get(type(v), type(v).__name__)

def keys(o):
    return ", ".join(f"`{k}`:{typ(v)}" for k, v in sorted(o.items())) if isinstance(o, dict) else typ(o)

out = []
p = out.append
p("# n8n API discovery output\n")
p(f"- Base URL: `{BASE}`\n- Method: GET only\n")

# 1. list
st, lst = get("/workflows?limit=50&excludePinnedData=true")
p(f"## 1. GET /workflows -> HTTP {st}\n")
items = (lst or {}).get("data", []) if isinstance(lst, dict) else []
if isinstance(lst, dict):
    p(f"- top-level keys: {keys(lst)}")
    p(f"- items on first page: {len(items)}; nextCursor present: {bool(lst.get('nextCursor'))}")
if items:
    union = collections.Counter(k for it in items for k in it)
    p(f"- keys seen in list items (count/{len(items)}): " + ", ".join(f"`{k}`={c}" for k, c in sorted(union.items())))
    p(f"- list contains `activeVersion`: **{'activeVersion' in union}**; contains `shared`: **{'shared' in union}**")
    pub = [i for i in items if isinstance(i.get("activeVersion"), dict)]
    p(f"- items with activeVersion != null: {len(pub)}; active=true: {sum(1 for i in items if i.get('active'))}; activeVersion null: {sum(1 for i in items if i.get('activeVersion') is None)}")
    drafts = [i for i in pub if i["activeVersion"].get("versionId") != i.get("versionId")]
    p(f"- published items with an unpublished draft (activeVersion.versionId != versionId): {len(drafts)}")
p("")

wid = os.environ.get("WORKFLOW_ID") or next((i["id"] for i in items if isinstance(i.get("activeVersion"), dict)), items[0]["id"] if items else None)

# 2. detail
if wid:
    st, wf = get(f"/workflows/{wid}?excludePinnedData=true")
    p(f"## 2. GET /workflows/{{id}} (id `{wid}`) -> HTTP {st}\n")
    if isinstance(wf, dict):
        p(f"- top-level keys: {keys(wf)}")
        p(f"- active: `{wf.get('active')}`, isArchived: `{wf.get('isArchived')}`")
        p(f"- versionId (draft): `{wf.get('versionId')}`")
        av = wf.get("activeVersion")
        p(f"- activeVersion: {keys(av) if isinstance(av, dict) else 'null'}")
        if isinstance(av, dict):
            p(f"- activeVersion.versionId: `{av.get('versionId')}` (equal to versionId: {av.get('versionId') == wf.get('versionId')})")
        p(f"- settings keys: {keys(wf.get('settings') or {})}")
        nk = collections.Counter(k for n in wf.get("nodes") or [] for k in n)
        p(f"- node keys (count/{len(wf.get('nodes') or [])}): " + ", ".join(f"`{k}`={c}" for k, c in sorted(nk.items())))
        cred_shapes = {tuple(sorted(c.keys())) for n in wf.get("nodes") or [] for c in (n.get("credentials") or {}).values() if isinstance(c, dict)}
        p(f"- credential reference shapes: {sorted(cred_shapes) or 'none'}")
        p("- shared:")
        for s in wf.get("shared") or []:
            pr = s.get("project") or {}
            p(f"  - role `{s.get('role')}`, projectId `{s.get('projectId')}`, project keys: {keys(pr)}, project.type `{pr.get('type')}`, project.name `{pr.get('name')}`")
        p("")
        # 3. version
        if isinstance(av, dict) and av.get("versionId"):
            st, ver = get(f"/workflows/{wid}/{av['versionId']}")
            p(f"## 3. GET /workflows/{{id}}/{{activeVersionId}} -> HTTP {st}\n")
            if isinstance(ver, dict):
                p(f"- keys: {keys(ver)}")
                p(f"- name present: {bool(ver.get('name'))}; equals top-level name: {ver.get('name') == wf.get('name')}")
            p("")
else:
    p("## 2. no workflow available\n")

# 4. projects
st, pj = get("/projects?limit=100")
p(f"## 4. GET /projects -> HTTP {st}\n")
for pr in (pj or {}).get("data", []) if isinstance(pj, dict) else []:
    p(f"- `{pr.get('id')}` type `{pr.get('type')}` name `{pr.get('name')}`")
p("")

# 5. users
st, us = get("/users?limit=100")
p(f"## 5. GET /users -> HTTP {st}\n")
for u in (us or {}).get("data", []) if isinstance(us, dict) else []:
    p(f"- `{u.get('id')}` email `{u.get('email')}` firstName `{u.get('firstName')}` lastName `{u.get('lastName')}` role `{u.get('role')}`")
p("")
p("## Not verified by this script (needs writes)\n")
p("- PUT /workflows/{id} accepted settings/node keys and returned versionId")
p("- POST /workflows/{id}/activate {versionId} -> activeVersion.versionId")
print("\n".join(out))
PY
