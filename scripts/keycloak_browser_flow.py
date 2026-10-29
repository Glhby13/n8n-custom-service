#!/usr/bin/env python3
"""Browser (authorization code) login flow for the n8n client, so that signing in to n8n through SSO (for example from
the portal's n8n card, which opens <n8n>/sso/login) follows the same rules as the Sign in with AD BTN page:

  - a user without the client role n8n-access is refused by Keycloak itself;
  - a user with the client role n8n-admin must give an OTP code, even when a Keycloak SSO session already exists;
  - everybody else with n8n-access goes straight in (silent when a Keycloak session exists).

Flow `n8n-browser` (same pattern as the CloudBeaver / Argo CD flows, without LoA):
  n8n-identify    REQUIRED     Cookie ALTERNATIVE | n8n-forms ALTERNATIVE (Username Password Form REQUIRED)
  n8n-membership  CONDITIONAL  Condition - user role [NEGATE, <client>.n8n-access] REQUIRED -> Deny access REQUIRED
  n8n-admin-otp   CONDITIONAL  Condition - user role [<client>.n8n-admin] REQUIRED -> OTP Form REQUIRED
The flow is bound as the client's "Browser flow" override. The Direct Grant override (Sign in with AD BTN page) is not touched.

Idempotent. Usage:
  python3 -I scripts/keycloak_browser_flow.py --check   read only: report what is missing
  python3 -I scripts/keycloak_browser_flow.py           create / repair the flow and bind it
  python3 -I scripts/keycloak_browser_flow.py --undo    unbind the flow from the client and delete it (browser flow back to the realm default)

Env: KC_URL (default https://auth.lab.local)  KC_REALM (lab)  KC_CLIENT (n8n-lab)  KC_ACCESS_ROLE (n8n-access)  KC_ADMIN_ROLE (n8n-admin)
     KC_ADMIN_USER (admin)  KC_ADMIN_PASSWORD (else lab/SECRETS.md, only when KC_URL is *.lab.local, else asked on the terminal)
     KC_INSECURE=1 only for a self-signed lab certificate.
"""
import getpass
import json
import os
import re
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request

KC = os.environ.get("KC_URL", "https://auth.lab.local").rstrip("/")
REALM = os.environ.get("KC_REALM", "lab")
CLIENT = os.environ.get("KC_CLIENT", "n8n-lab")
ACCESS_ROLE = os.environ.get("KC_ACCESS_ROLE", "n8n-access")
ADMIN_ROLE = os.environ.get("KC_ADMIN_ROLE", "n8n-admin")
CTX = ssl._create_unverified_context() if os.environ.get("KC_INSECURE") == "1" else ssl.create_default_context()

TOP = "n8n-browser"
IDENT, FORMS, MEMBER, ADMINOTP = "n8n-identify", "n8n-forms", "n8n-membership", "n8n-admin-otp"
# (sub-flow alias, requirement) at level 0 and the steps expected inside each, as (display name, requirement)
WANT_TOP = [(IDENT, "REQUIRED"), (MEMBER, "CONDITIONAL"), (ADMINOTP, "CONDITIONAL")]
WANT_STEPS = {
    IDENT: [("Cookie", "ALTERNATIVE"), (FORMS, "ALTERNATIVE"), ("Username Password Form", "REQUIRED")],
    MEMBER: [("Condition - user role", "REQUIRED"), ("Deny access", "REQUIRED")],
    ADMINOTP: [("Condition - user role", "REQUIRED"), ("OTP Form", "REQUIRED")],
}
COND = {  # sub-flow -> (config alias, negate, role)
    MEMBER: (f"{MEMBER}-{ACCESS_ROLE}", "true", f"{CLIENT}.{ACCESS_ROLE}"),
    ADMINOTP: (f"{ADMINOTP}-{ADMIN_ROLE}", "false", f"{CLIENT}.{ADMIN_ROLE}"),
}


def admin_password():
    if os.environ.get("KC_ADMIN_PASSWORD"):
        return os.environ["KC_ADMIN_PASSWORD"]
    secrets = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "SECRETS.md")  # lab layout only
    if KC.split("//", 1)[-1].split("/", 1)[0].split(":", 1)[0].endswith(".lab.local") and os.path.exists(secrets):  # never send the lab password to another host
        for line in open(secrets, encoding="utf8"):
            if "Admin console" in line and "realm `master`" in line:
                cells = re.findall(r"`([^`]+)`", line)
                if len(cells) >= 2:
                    return cells[1]
    return getpass.getpass("Keycloak admin password: ")


def call(method, path, token=None, body=None, form=None):
    data, headers = None, {}
    if form is not None:
        data = urllib.parse.urlencode(form).encode()
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    elif body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = "Bearer " + token
    req = urllib.request.Request(KC + path, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, context=CTX, timeout=30) as r:
            raw = r.read()
            return json.loads(raw) if raw else None
    except urllib.error.HTTPError as e:
        sys.exit(f"{method} {path} -> HTTP {e.code} {e.read()[:200]!r}")


def flow_rows(tok, base):
    """Executions of the top flow, each tagged with the level-0 sub-flow it sits in."""
    rows, cur = [], None
    for e in call("GET", f"{base}/authentication/flows/{urllib.parse.quote(TOP)}/executions", tok):
        name = e.get("displayName") or e.get("providerId")
        if e["level"] == 0:
            cur = name
        e["_name"], e["_in"] = name, cur
        rows.append(e)
    return rows


def ensure_flow(tok, base):
    flows = {f["alias"] for f in call("GET", f"{base}/authentication/flows", tok)}
    p = f"{base}/authentication/flows"
    if TOP not in flows:
        call("POST", p, tok, body={"alias": TOP, "description": "n8n: SSO sign-in only with n8n-access, OTP for n8n-admin", "providerId": "basic-flow", "topLevel": True, "builtIn": False})
        for alias, desc in ((IDENT, "Cookie or username and password"), (MEMBER, "Deny without n8n-access"), (ADMINOTP, "OTP for n8n-admin")):
            call("POST", f"{p}/{TOP}/executions/flow", tok, body={"alias": alias, "type": "basic-flow", "description": desc, "provider": "registration-page-form"})
        call("POST", f"{p}/{IDENT}/executions/execution", tok, body={"provider": "auth-cookie"})
        call("POST", f"{p}/{IDENT}/executions/flow", tok, body={"alias": FORMS, "type": "basic-flow", "description": "", "provider": "registration-page-form"})
        call("POST", f"{p}/{FORMS}/executions/execution", tok, body={"provider": "auth-username-password-form"})
        call("POST", f"{p}/{MEMBER}/executions/execution", tok, body={"provider": "conditional-user-role"})
        call("POST", f"{p}/{MEMBER}/executions/execution", tok, body={"provider": "deny-access-authenticator"})
        call("POST", f"{p}/{ADMINOTP}/executions/execution", tok, body={"provider": "conditional-user-role"})
        call("POST", f"{p}/{ADMINOTP}/executions/execution", tok, body={"provider": "auth-otp-form"})
        print("created flow", TOP)
    want = {(sub, name): req for sub, steps in WANT_STEPS.items() for name, req in steps}
    want.update({(name, name): req for name, req in WANT_TOP})
    for e in flow_rows(tok, base):
        req = want.get((e["_in"], e["_name"]))
        if req and e["requirement"] != req:
            call("PUT", f"{p}/{TOP}/executions", tok, body={**{k: v for k, v in e.items() if not k.startswith("_")}, "requirement": req})
            print(f"  {e['_in']} / {e['_name']}: {e['requirement']} -> {req}")
    for e in flow_rows(tok, base):
        if e.get("providerId") == "conditional-user-role" and e["_in"] in COND and not e.get("authenticationConfig"):
            alias, negate, role = COND[e["_in"]]
            call("POST", f"{base}/authentication/executions/{e['id']}/config", tok, body={"alias": alias, "config": {"negate": negate, "condUserRole": role}})
            print(f"  {e['_in']}: condition role={role} negate={negate}")


def check(tok, base, client, problems):
    for r in (ACCESS_ROLE, ADMIN_ROLE):
        if not any(x["name"] == r for x in call("GET", f"{base}/clients/{client['id']}/roles", tok)):
            problems.append(f"client role {CLIENT}/{r} does not exist")
    flows = {f["alias"]: f for f in call("GET", f"{base}/authentication/flows", tok)}
    if TOP not in flows:
        problems.append(f"flow {TOP} does not exist")
        return
    rows = flow_rows(tok, base)
    seen = {(e["_in"], e["_name"]): e for e in rows}
    print(f"flow {TOP}:")
    for e in rows:
        cfg = ""
        if e.get("authenticationConfig"):
            c = (call("GET", f"{base}/authentication/config/{e['authenticationConfig']}", tok).get("config") or {})
            cfg = f"  role={c.get('condUserRole', '')} negate={c.get('negate', 'false')}"
        print("  " + "  " * e["level"] + f"{e['_name']}  [{e['requirement']}]{cfg}")
    for name, req in WANT_TOP:
        got = seen.get((name, name))
        if not got or got["requirement"] != req:
            problems.append(f"flow {TOP}: {name} must be {req}")
    for sub, steps in WANT_STEPS.items():
        for name, req in steps:
            got = seen.get((sub, name))
            if not got or got["requirement"] != req:
                problems.append(f"flow {TOP}: {sub} / {name} must be {req}")
    for sub, (_, negate, role) in COND.items():
        e = seen.get((sub, "Condition - user role"))
        c = (call("GET", f"{base}/authentication/config/{e['authenticationConfig']}", tok).get("config") or {}) if e and e.get("authenticationConfig") else {}
        if c.get("condUserRole") != role or c.get("negate", "false") != negate:
            problems.append(f"flow {TOP}: {sub} condition must be role={role} negate={negate}")
    bound = (client.get("authenticationFlowBindingOverrides") or {}).get("browser")
    if bound != flows[TOP]["id"]:
        problems.append(f"client {CLIENT}: the browser flow override is not {TOP}")


def main():
    mode = "check" if "--check" in sys.argv else "undo" if "--undo" in sys.argv else "apply"
    tok = call("POST", "/realms/master/protocol/openid-connect/token",
               form=dict(grant_type="password", client_id="admin-cli", username=os.environ.get("KC_ADMIN_USER", "admin"), password=admin_password()))["access_token"]
    base = f"/admin/realms/{REALM}"
    found = call("GET", f"{base}/clients?clientId={CLIENT}", tok)
    if not found:
        sys.exit(f"client {CLIENT} not found in realm {REALM}")
    client = found[0]

    if mode == "undo":
        ov = dict(client.get("authenticationFlowBindingOverrides") or {})
        ov.pop("browser", None)
        client["authenticationFlowBindingOverrides"] = ov
        call("PUT", f"{base}/clients/{client['id']}", tok, body=client)
        flow = next((f for f in call("GET", f"{base}/authentication/flows", tok) if f["alias"] == TOP), None)
        if flow:
            call("DELETE", f"{base}/authentication/flows/{flow['id']}", tok)
        print(f"undone: {CLIENT} uses the realm browser flow again; flow {TOP} deleted")
        return

    if mode == "apply":
        ensure_flow(tok, base)
        flow = next(f for f in call("GET", f"{base}/authentication/flows", tok) if f["alias"] == TOP)
        ov = dict(client.get("authenticationFlowBindingOverrides") or {})
        if ov.get("browser") != flow["id"]:
            ov["browser"] = flow["id"]
            client["authenticationFlowBindingOverrides"] = ov
            call("PUT", f"{base}/clients/{client['id']}", tok, body=client)
            print(f"bound: client {CLIENT} browser flow -> {TOP}")
        client = call("GET", f"{base}/clients?clientId={CLIENT}", tok)[0]

    problems = []
    check(tok, base, client, problems)
    if problems:
        print("\nPROBLEMS:")
        for p in problems:
            print(" -", p)
        sys.exit(1)
    print(f"\nOK: client {CLIENT} signs in through flow {TOP} (n8n-access required, OTP for {ADMIN_ROLE})")


main()
