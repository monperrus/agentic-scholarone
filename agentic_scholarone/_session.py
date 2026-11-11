"""
ScholarOne / ManuscriptCentral client: session, login, navigation and parsing
of the editor-facing web app, driven by its form POSTs.

Auth flow (reconstructed from HAR):
  1. GET  mc.manuscriptcentral.com/<journal>         → AWS sticky-session cookies
  2. POST mc.manuscriptcentral.com/<journal>         → JAVASCRIPT_ENABLED=Y&NEXT_PAGE=LOGIN
  3. POST access.clarivate.com/api/authorize         → JSON creds → {code, redirect_uri}
  4. GET  mc.manuscriptcentral.com/broker/<code>     → sets session cookie, lands on HOME
  5. POST mc.manuscriptcentral.com/<journal>         → NEXT_PAGE=ASSOCIATE_EDITOR_DASHBOARD
                                                        + XIK tokens extracted from HOME html

Navigation:
  All subsequent pages are fetched via GET …/<journal>?PARAMS=xik_…  or
  POST …/<journal> with NEXT_PAGE and hidden XIK fields from the current form.
"""
from __future__ import annotations


import atexit
import os
import sys
import re
import json
from typing import Any
from collections.abc import Callable
try:
    import readline  # noqa: F401 – enables arrow-key history in REPL
except ImportError:  # Windows
    pass
import textwrap
from dataclasses import dataclass, field
from urllib.parse import urljoin

from curl_cffi.requests import Session as CurlSession
from bs4 import BeautifulSoup
from tqdm import tqdm

# ── constants ────────────────────────────────────────────────────────────────

BASE_URL = "https://mc.manuscriptcentral.com"
AUTH_URL = "https://access.clarivate.com/api/authorize"

# NOTE: session uses impersonate="chrome124" for its TLS/JA3 fingerprint, so
# these headers (in particular User-Agent and Accept) must match a real
# Chrome 124 client. curl_cffi auto-derives consistent Sec-Ch-Ua headers from
# the impersonation profile, but User-Agent/Accept given here take priority
# and silently override that — a Firefox UA paired with a Chrome TLS
# fingerprint is an internally-inconsistent client signature that Clarivate's
# bot/device-fingerprint check flags as "unrecognized device" on every login,
# which defeats the "remember this device" 2FA-skip cookie entirely.
HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept": (
        "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,"
        "image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"
    ),
    "Accept-Language": "en-US,en;q=0.9",
    "Upgrade-Insecure-Requests": "1",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-User": "?1",
}

# Local, confidential bookkeeping (gitignored):
#   mc_actions.jsonl — append-only log of every state-changing action
#
# Paper state (status, invited reviewers, decisions, …) is never cached
# locally — ScholarOne is the only reference for it. Query it live instead
# (ae_dashboard, fetch_queue_papers_all_pages, selected_reviewer_rows, …).
STATE_DIR = os.environ.get("MC_STATE_DIR") or os.path.join(
    os.path.expanduser("~"), ".local", "state", "agentic-scholarone")
ACTION_LOG_PATH = os.path.join(STATE_DIR, "mc_actions.jsonl")


# ── work journal ─────────────────────────────────────────────────────────────


def _now_iso() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


class WorkJournal:
    """Append-only log of state-changing actions.

    This is a historical record of what we *did* (one JSON object per line,
    never rewritten) — never a cache of where a paper currently stands.
    ScholarOne is the only reference for paper state; query it live.
    """

    def __init__(self, log_path: str = ACTION_LOG_PATH) -> None:
        self.log_path = log_path

    def log(self, action: str, ms_id: str = "", ok: bool = True, **details) -> dict:
        """Append one state-changing action to the JSONL log.

        Returns the record; never raises — bookkeeping must not break an
        editorial operation that already happened.
        """
        record = {"ts": _now_iso(), "action": action, "ok": bool(ok)}
        if ms_id:
            record["ms_id"] = ms_id
        record.update({k: v for k, v in details.items() if v not in ("", None)})
        try:
            os.makedirs(os.path.dirname(self.log_path) or ".", exist_ok=True)
            with open(self.log_path, "a", encoding="utf-8") as fp:
                fp.write(json.dumps(record, ensure_ascii=False, default=str) + "\n")
        except OSError as exc:
            print(f"[worklog] could not write {self.log_path}: {exc}", file=sys.stderr)
        return record

    def entries(self, ms_id: str = "", action: str = "", limit: int = 0) -> list[dict]:
        """Read back log entries, oldest first; `limit` keeps the last N."""
        rows: list[dict] = []
        try:
            with open(self.log_path, encoding="utf-8") as fp:
                for line in fp:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        row = json.loads(line)
                    except ValueError:
                        continue
                    if ms_id and row.get("ms_id") != ms_id:
                        continue
                    if action and row.get("action") != action:
                        continue
                    rows.append(row)
        except FileNotFoundError:
            return []
        return rows[-limit:] if limit else rows


# ── result types ─────────────────────────────────────────────────────────────


@dataclass
class InviteResult:
    """Structured result from invite_by_email / invite_by_name."""
    ok: bool
    name: str = ""
    status: str = ""
    message: str = ""
    # Non-empty when disambiguation is needed (ok=False, ambiguous=True)
    ambiguous: bool = False
    candidates: list[dict] = field(default_factory=list)
    candidate_details: list[dict] = field(default_factory=list)  # parallel to candidates, holds hist dicts

    def __str__(self) -> str:
        return self.message


# ── session wrapper ───────────────────────────────────────────────────────────

class ScholarOneSession:
    """A logged-in ScholarOne session for one journal.

    Extension points, overridden by a subclass to plug local infrastructure in:

    * ``default_journal`` — journal slug used when none is given (else ``MC_JOURNAL``).
    * ``ms_id_pattern`` — regex of the journal's manuscript ids.
    * ``keyring_service`` — secret-service name for ``password_keyring`` entries.
    * ``state_dir`` — where the action log ``mc_actions.jsonl`` goes.
    * ``two_factor_code_providers()`` — extra automatic sources of the 2FA code.
    * ``invitation_paragraph()`` — a paragraph added to every reviewer invitation.
    """

    default_journal: str = ""
    # ScholarOne ids: journal code, year, then month/sequence/revision, e.g. ABC-2026-04-0342.R1
    ms_id_pattern: str = r"[A-Z][A-Z0-9]+-\d{4}[-.\w]*"
    keyring_service: str = "agentic-scholarone"
    state_dir: str = STATE_DIR

    def __init__(self, journal: str | None = None):
        journal = journal or self.default_journal or os.environ.get("MC_JOURNAL", "")
        if not journal:
            raise ValueError("No journal: pass journal=, set MC_JOURNAL, or put \"journal\" "
                             "in credentials.json (the slug after mc.manuscriptcentral.com/).")
        self.journal = journal
        self.journal_url = f"{BASE_URL}/{journal}"
        self.session = CurlSession(impersonate="chrome124")
        self.session.headers.update(HEADERS)
        self.current_url: str = self.journal_url
        self.current_html: str = ""
        self.history: list[str] = []
        self.debug_enabled = os.environ.get("MC_DEBUG", "").lower() in {"1", "true", "yes", "on"}
        self.reviewer_history_cache: dict[str, dict[str, str]] = {}
        self.reviewer_manuscript_history_cache: dict[str, str] = {}
        self._nav_cache: dict[str, dict] = {}   # ms_id → nav dict; cleared on login
        self.worklog = WorkJournal(os.path.join(self.state_dir, "mc_actions.jsonl"))

    # ── bookkeeping helpers (see WorkJournal) ────────────────────────────

    def log_action(self, action: str, ms_id: str = "", ok: bool = True, **details) -> dict:
        """Record a state-changing action in the JSONL log + per-paper state."""
        return self.worklog.log(action, ms_id=ms_id, ok=ok, journal=self.journal, **details)

    def _debug(self, message: str) -> None:
        if self.debug_enabled:
            print(f"[debug] {message}")

    @classmethod
    def from_credentials(
        cls,
        credentials_path: str = "credentials.json",
    ) -> ScholarOneSession:
        """Create a session and log in from a credentials file in one call.

        Usage::

            mc = ScholarOneSession.from_credentials()
        """
        creds = load_credentials(credentials_path)
        mc = cls(journal=creds.get("journal"))

        # 1. Cheapest path: the previous server session may still be alive —
        #    restore every cookie verbatim and see whether the dashboard opens.
        if mc.resume(creds):
            # The server rotates SESSION/AWSALB on every hit — persist the
            # refreshed jar, otherwise the *next* run resumes with stale
            # cookies and is bounced back to a full (2FA-prone) login.
            mc._save_cookies(credentials_path)
            mc._save_cookies_at_exit(credentials_path)
            print("Session resumed (no login needed).\n")
            return mc

        # 2. Full login.  Session cookies are dropped so the server can build a
        #    clean session, but the *device-trust* cookies (on the Clarivate
        #    domain, hence `all_cookies`) are kept — without them Clarivate
        #    treats every run as an unrecognised device and fires 2FA.
        #    A failed resume() leaves the stale SESSION/AWSALB in the jar, next
        #    to the fresh ones the login gets: ScholarOne then bounces the
        #    credentials POST to its SHOW_SESSION_TIMEOUT cookie gate.  Start
        #    the login from a clean instance.
        mc = cls(journal=creds.get("journal"))
        device_cookies = [
            c for c in mc._saved_cookies(creds)
            if c["name"] not in cls._SESSION_COOKIES
        ]
        # auth_method: "clarivate" (default, Web-of-Science SSO) or "direct"
        # (ScholarOne-native USERID/PASSWORD form).  MC_AUTH overrides the file;
        # with "direct", direct_password (or MC_PASSWORD) is the native password.
        method = os.environ.get("MC_AUTH") or creds.get("auth_method", "clarivate")
        if method == "direct":
            mc.login_direct(
                creds.get("email", ""),
                mc._resolve_password(creds, "direct_password"),
                device_cookies=device_cookies,
                credentials_path=credentials_path,
            )
        else:
            mc.login(
                creds.get("email", ""),
                creds.get("password", ""),
                device_cookies=device_cookies,
                credentials_path=credentials_path,
            )
        mc._save_cookies_at_exit(credentials_path)
        return mc

    def _save_cookies_at_exit(self, credentials_path: str) -> None:
        """Persist the cookie jar once more when the process ends.

        SESSION is stable, but the AWS load-balancer stickiness cookie
        (AWSALB/AWSALBCORS) is reissued on every response; saving the last one
        lets the next run's resume() reach the backend that holds the session.
        """
        atexit.register(self._save_cookies, credentials_path, True)

    @classmethod
    def _resolve_password(cls, creds: dict, direct_key: str = "direct_password") -> str:
        """Resolve a login password, preferring not to keep it in the file.

        Order: ``MC_PASSWORD`` env → ``password_keyring`` (a secret-service
        entry, pulled live so the file stays password-free) → the explicit
        ``direct_key`` → legacy ``password``.  ``password_keyring`` may be a
        bare name (service defaults to ``keyring_service``) or
        ``"service/name"``; ``keyring`` is an optional dependency.
        """
        if os.environ.get("MC_PASSWORD"):
            return os.environ["MC_PASSWORD"]
        ref = creds.get("password_keyring")
        if ref:
            import keyring
            service, _, name = ref.rpartition("/")
            pw = keyring.get_password(service or cls.keyring_service, name)
            if pw:
                return pw
            raise RuntimeError(f"password_keyring '{ref}' resolved to nothing")
        return creds.get(direct_key) or creds.get("password", "")

    @staticmethod
    def _saved_cookies(creds: dict) -> list[dict]:
        """Normalise the credentials file's cookie store to a list of dicts.

        Two on-disk shapes are supported: the legacy ``cookies`` mapping
        (name → value, manuscriptcentral only) and ``all_cookies``, a list of
        ``{name, value, domain, path}`` covering every domain involved in the
        login (notably ``.clarivate.com``, which carries device trust).
        """
        rows = creds.get("all_cookies")
        if isinstance(rows, list) and rows:
            return [r for r in rows if r.get("name")]
        return [
            {"name": name, "value": value,
             "domain": ".mc.manuscriptcentral.com", "path": "/"}
            for name, value in (creds.get("cookies") or {}).items()
        ]

    def _inject_cookies(self, cookies: list[dict]) -> None:
        for c in cookies:
            try:
                self.session.cookies.set(
                    c["name"], c.get("value", ""),
                    domain=c.get("domain") or ".mc.manuscriptcentral.com",
                    path=c.get("path") or "/",
                )
            except Exception:
                continue

    def resume(self, creds: dict) -> bool:
        """Try to reuse the stored session instead of logging in again.

        Returns True when the AE dashboard could be reached with the saved
        cookies alone (`current_html` then holds it), False otherwise — the
        caller falls back to a full `login()`.  Never raises: a dead session
        must simply degrade to a login.

        Only works while the server-side session is still warm (roughly half an
        hour of idleness).

        The probe is a bare POST to ``NEXT_PAGE=ASSOCIATE_EDITOR_DASHBOARD``,
        never a GET of the journal root: that GET is ScholarOne's landing
        page and *ends* the live session (even the one still open in another
        process), so the following dashboard request fails as well.
        """
        cookies = self._saved_cookies(creds)
        if not cookies:
            return False
        self._inject_cookies(cookies)
        # ScholarOne serves its "your browser does not meet our minimum
        # requirements" gate unless this cookie is present — in a browser its
        # own inline JS sets it (`document.cookie = "cookieCheck=1"`).
        self.session.cookies.set("cookieCheck", "1", domain=".mc.manuscriptcentral.com")
        try:
            r = self.session.post(
                self.journal_url,
                data={"NEXT_PAGE": "ASSOCIATE_EDITOR_DASHBOARD", "PAGE_LOADED_FLAG": "Y"},
                headers={"Referer": self.journal_url, "Origin": BASE_URL},
            )
            r.raise_for_status()
            if not self._is_ae_dashboard(r.text):
                return False
            self._update_page(r.url, r.text)
        except Exception as exc:
            self._debug(f"resume failed: {exc}")
            return False
        self._nav_cache.clear()
        return True

    def ping(self, credentials_path: str = "credentials.json") -> bool:
        """Keep the server session alive and persist the refreshed cookies.

        ScholarOne expires a session on *idleness*, so a cheap authenticated
        round-trip every few minutes keeps `resume()` working indefinitely —
        the only way to avoid a 2FA-prone login per process, since Clarivate
        hands out no device-trust cookie we can replay.

        Returns True while the session is alive, False once it is gone.
        """
        try:
            r = self.goto_dashboard()
            if not self._is_ae_dashboard(r.text):
                return False
        except Exception as exc:
            self._debug(f"ping failed: {exc}")
            return False
        self._save_cookies(credentials_path, quiet=True)
        return True

    @staticmethod
    def _is_ae_dashboard(html: str) -> bool:
        """True when `html` looks like a logged-in AE dashboard page."""
        if "access.clarivate.com" in html and "loginid" in html:
            return False
        markers = ("Select Reviewers", "Assign Reviewers", "Associate Editor Dashboard",
                   "ASSOCIATE_EDITOR_DASHBOARD")
        return sum(m in html for m in markers) >= 2

    # ── auth ──────────────────────────────────────────────────────────────────

    # Cookies tied to one server session — exclude when injecting saved cookies
    # before the initial GET so the server can establish a clean new session.
    _SESSION_COOKIES = {"JSESSIONID", "SESSION", "AWSALB", "AWSALBCORS", "__cf_bm", "cookieCheck"}

    def login(self, email: str, password: str,
              device_cookies: dict | list[dict] | None = None,
              credentials_path: str = "credentials.json") -> None:
        # Inject saved device cookies before the first request so Cloudflare
        # sees a returning-user fingerprint (consent/preference cookies) and so
        # Clarivate recognises the device (its trust cookie lives on
        # .clarivate.com — dropping it is what makes 2FA fire on every run).
        # Use the leading-dot domain: that's what the server itself re-issues
        # these cookies under on the very first GET below, so setting them
        # host-only here (no dot) would leave both the stale injected value
        # and the freshly-issued one sitting in the jar as separate entries —
        # sent as two conflicting Cookie header values for the same name.
        if device_cookies:
            if isinstance(device_cookies, dict):   # legacy name → value mapping
                device_cookies = [
                    {"name": k, "value": v, "domain": ".mc.manuscriptcentral.com"}
                    for k, v in device_cookies.items()
                ]
            self._inject_cookies(device_cookies)

        print("[1/3] Fetching initial page …")
        r = self.session.get(self.journal_url)
        r.raise_for_status()

        print("[2/3] Authenticating with Clarivate …")
        self.session.post(
            self.journal_url,
            data={"JAVASCRIPT_ENABLED": "Y", "NEXT_PAGE": "LOGIN", "SHOW_SESSION_TIMEOUT": "N"},
            headers={"Referer": self.journal_url, "Origin": BASE_URL},
        )
        auth_resp = self.session.post(
            AUTH_URL,
            json={"loginid": email, "password": password, "loginAccount": "", "app": "s1m"},
            headers={"Content-Type": "application/json",
                     "Origin": "https://access.clarivate.com",
                     "Referer": "https://access.clarivate.com/login?app=s1m"},
        )
        if not auth_resp.ok:
            # Clarivate answers 404 for every auth failure; the reason is in the body.
            try:
                err = auth_resp.json()
            except ValueError:
                err = {"error": auth_resp.status_code, "error_description": auth_resp.text[:200]}
            raise RuntimeError(
                f"Auth failed ({err.get('error')}): {err.get('error_description')}"
                + (" — reset it at https://access.clarivate.com, then update credentials.json"
                   if err.get("error") == "password_expired" else "")
            )
        auth_data = auth_resp.json()
        if "code" not in auth_data:
            raise RuntimeError(f"Auth failed: {auth_data}")
        code = auth_data["code"]
        print(f"    ✓ Got auth code: {code[:16]}…")

        print("[3/3] Exchanging broker token …")
        broker_url = f"{BASE_URL}/broker/{code}?app=s1m&referrer=s1m_stack1%3Fjournal%3D{self.journal}"
        r = self.session.get(broker_url, headers={"Referer": "https://access.clarivate.com/"},
                             allow_redirects=True)
        r.raise_for_status()
        self._finalize_login(r, credentials_path, email)

    def login_direct(self, email: str, password: str,
                     device_cookies: dict | list[dict] | None = None,
                     credentials_path: str = "credentials.json") -> None:
        """Log in with the ScholarOne-native user id + password form.

        This is the ``USERID``/``PASSWORD`` form on the journal's own login page
        (``mc.manuscriptcentral.com/<journal>``), submitted straight to ScholarOne —
        it never touches ``access.clarivate.com``.  Use it when the account has a
        ScholarOne-native password distinct from (or still valid while) the
        Clarivate / Web-of-Science password is expired.  Same 2FA device-check
        and dashboard-navigation tail as :meth:`login`.
        """
        if device_cookies:
            if isinstance(device_cookies, dict):
                device_cookies = [
                    {"name": k, "value": v, "domain": ".mc.manuscriptcentral.com"}
                    for k, v in device_cookies.items()
                ]
            self._inject_cookies(device_cookies)

        print("[1/2] Fetching login page …")
        self.session.get(self.journal_url)
        r = self.session.post(
            self.journal_url,
            data={"JAVASCRIPT_ENABLED": "Y", "NEXT_PAGE": "LOGIN", "SHOW_SESSION_TIMEOUT": "N"},
            headers={"Referer": self.journal_url, "Origin": BASE_URL},
        )
        r.raise_for_status()
        fields = self._extract_form_data_from(r.text)
        if "USERID" not in fields:
            raise RuntimeError("Login form not found (no USERID field on LOGIN page)")
        # The Log In button runs `setDataAndNextPage(TAG_ACTION, loginAction, HOME)`:
        # the submit carries XIK_TAGACT = the loginAction token and NEXT_PAGE = HOME.
        m = re.search(r"var\s+loginAction\s*=\s*'([^']+)'", r.text)
        if not m:
            raise RuntimeError("loginAction token not found on LOGIN page")
        fields.update({
            "USERID": email,
            "PASSWORD": password,
            "XIK_TAGACT": m.group(1),
            "NEXT_PAGE": "HOME",
            "LOGIN_BAD_USERNAME_OR_PASSWORD": "",
        })

        print("[2/2] Submitting credentials …")
        r = self.session.post(
            self.journal_url, data=fields,
            headers={"Referer": self.journal_url, "Origin": BASE_URL},
            allow_redirects=True,
        )
        r.raise_for_status()
        # A rejected password just re-renders LOGIN with the error flag set.
        if "LOGIN_BAD_USERNAME_OR_PASSWORD" in r.text and 'value="HOME"' not in r.text \
                and not self._is_ae_dashboard(r.text):
            if 'id="USERID"' in r.text:
                raise RuntimeError("Auth failed: ScholarOne rejected the user id or password")
        self._finalize_login(r, credentials_path, email)

    def _finalize_login(self, r, credentials_path: str, email: str) -> None:
        """Shared post-authentication tail: device check, land on the AE
        dashboard, persist cookies.  Used by both login paths."""
        if "UNRECOGNIZED_DEVICE" in r.text:
            r = self._verify_device(r)

        self._update_page(r.url, r.text)

        # Login lands on the multi-journal HOME page.  Navigate into the
        # journal-specific AE dashboard via the JS onclick XIK tokens.
        if 'value="ASSOCIATE_EDITOR_DASHBOARD"' not in r.text:
            r = self._navigate_to_ae_dashboard(r)
            self._update_page(r.url, r.text)

        self._save_cookies(credentials_path)
        self._nav_cache.clear()
        self.log_action("login", email=email)
        print("Login complete.\n")

    def _navigate_to_ae_dashboard(self, r) -> Any:
        """POST from the HOME page to the AE dashboard using XIK tokens
        embedded in the onclick handler of the Editor Center link."""
        import html as _html
        unesc = _html.unescape(r.text)

        m = re.search(
            r"(?:setField|setDataValue)\s*\(\s*['\"]XIK_POSTACT['\"],\s*['\"]([^'\"]+)['\"].*?"
            r"(?:setDataAndNextPageOneDataValue|setDataValue)\s*\(\s*['\"]XIK_CUR_ROLE_ID['\"],\s*['\"]([^'\"]+)['\"]"
            r".*?ASSOCIATE_EDITOR_DASHBOARD",
            unesc, re.DOTALL,
        )
        postact  = m.group(1) if m else ""
        role_id  = m.group(2) if m else ""

        # Journal config XIK from the <select name="XIK_NEW_CONFIG_ID"> options
        soup = BeautifulSoup(r.text, "html.parser")
        config_xik = ""
        sel = soup.find("select", {"name": "XIK_NEW_CONFIG_ID"})
        if sel:
            for opt in sel.find_all("option"):
                if opt.get_text(strip=True).lower().startswith(self.journal.lower()):
                    config_xik = opt.get("value", "")
                    break

        form = self._extract_form_data_from(r.text)
        form["NEXT_PAGE"]        = "ASSOCIATE_EDITOR_DASHBOARD"
        form["PAGE_LOADED_FLAG"] = "Y"
        if postact:
            form["XIK_POSTACT"] = postact
        if role_id:
            form["XIK_CUR_ROLE_ID"] = role_id
        if config_xik:
            form["XIK_NEW_CONFIG_ID"] = config_xik
            form["XIK_CNFID"]         = config_xik
            form["orgs"]              = self.journal

        r2 = self.session.post(
            self.journal_url, data=form,
            headers={"Referer": r.url, "Origin": BASE_URL},
        )
        r2.raise_for_status()
        return r2

    def two_factor_code_providers(self) -> list[Callable[[int], str]]:
        """Automatic sources of the emailed 2FA code, tried in order.

        Each is called with a timeout in seconds and returns the code or "".
        None by default; a subclass adds e.g. a reader of the local mailbox.
        """
        return []

    def _read_2fa_code(self, timeout_s: int = 900) -> str:
        """Obtain the emailed device-verification code.

        Sources, in order, so login also works when nobody is at the
        keyboard (agent / background run):

        1. ``MC_2FA_CODE`` — the code itself.
        2. ``two_factor_code_providers()`` — the fully autonomous path.
        3. ``MC_2FA_CODE_FILE`` — a path polled until it contains the code.
           The device-check email is only sent once the login is already in
           flight, so this works for a background run: start the login, then
           drop the code into that file.
        4. interactive ``input()``.
        """
        import os as _os
        import time as _time

        code = _os.environ.get("MC_2FA_CODE", "").strip()
        if code:
            return code

        for provider in self.two_factor_code_providers():
            code = provider(timeout_s)
            if code:
                return code

        path = _os.environ.get("MC_2FA_CODE_FILE", "").strip()
        if path:
            print(f"[2fa] waiting for the verification code in {path} …", flush=True)
            deadline = _time.time() + timeout_s
            while _time.time() < deadline:
                try:
                    code = open(path).read().strip()
                except OSError:
                    code = ""
                if code:
                    print("[2fa] code received.", flush=True)
                    return code
                _time.sleep(3)
            raise RuntimeError(f"No 2FA code appeared in {path} within {timeout_s}s.")

        return input("\n2FA: enter the verification code from your email: ").strip()

    def _verify_device(self, r) -> Any:
        """Prompt for the emailed verification code, submit it, return the response."""
        import html as _html
        # Extract the XIK tokens the verify button needs
        unesc = _html.unescape(r.text)
        m_verif = re.search(r"verifyUserDevice\s*=\s*'(xik_[^']+)'", unesc)
        verif_xik = m_verif.group(1) if m_verif else ""

        code = self._read_2fa_code()

        form = self._extract_form_data_from(r.text)
        form["TOKEN_VALUE"]        = code
        form["REMEMBER_THIS_DEVICE"] = "on"
        form["PAGE_LOADED_FLAG"]   = "Y"
        form["NEXT_PAGE"]          = "HOME"
        if verif_xik:
            form["XIK_POSTACT"] = verif_xik
        r2 = self.session.post(
            self.journal_url,
            data=form,
            headers={"Referer": r.url, "Origin": BASE_URL},
        )
        r2.raise_for_status()
        if "UNRECOGNIZED_DEVICE_VERIFICATION_CODE_INCORRECT" in r2.text:
            raise RuntimeError("Verification code incorrect.")
        print("    ✓ Device verified.")
        return r2

    def _save_cookies(self, path: str, quiet: bool = False) -> None:
        import json as _json
        try:
            with open(path) as f:
                creds = _json.load(f)
        except FileNotFoundError:
            creds = {}
        # `cookies` stays for backward compatibility; `all_cookies` keeps every
        # domain — the Clarivate device-trust cookies live outside
        # manuscriptcentral.com and are what spares the next run a 2FA prompt.
        creds["cookies"] = {
            c.name: c.value
            for c in self.session.cookies.jar
            if "manuscriptcentral" in c.domain
        }
        creds["all_cookies"] = [
            {"name": c.name, "value": c.value, "domain": c.domain, "path": c.path or "/"}
            for c in self.session.cookies.jar
        ]
        tmp = f"{path}.tmp"
        with open(tmp, "w") as f:
            _json.dump(creds, f, indent=2)
        os.replace(tmp, path)   # atomic: concurrent sessions may write too
        if not quiet:
            print(f"    ✓ Session cookies saved to {path}.")

    # ── navigation ────────────────────────────────────────────────────────────

    def goto_params(self, params_token: str) -> None:
        url = f"{self.journal_url}?PARAMS={params_token}"
        self._fetch_get(url)

    def goto_url(self, url: str) -> None:
        if not url.startswith("http"):
            url = urljoin(self.journal_url, url)
        self._fetch_get(url)

    def _fetch_get(self, url: str) -> None:
        self.history.append(self.current_url)
        r = self.session.get(url, headers={"Referer": self.current_url})
        r.raise_for_status()
        self._update_page(url, r.text)

    def back(self) -> None:
        if not self.history:
            print("No history.")
            return
        url = self.history.pop()
        r = self.session.get(url, headers={"Referer": self.current_url})
        r.raise_for_status()
        self._update_page(url, r.text)

    def _update_page(self, url: str, html: str) -> None:
        self.current_url = url
        self.current_html = html

    # ── page inspection ───────────────────────────────────────────────────────

    def _soup(self) -> BeautifulSoup:
        return BeautifulSoup(self.current_html, "html.parser")

    def page_title(self) -> str:
        soup = self._soup()
        title = soup.find("title")
        return title.get_text(strip=True) if title else "(no title)"

    def page_text(self, max_lines: int = 60) -> str:
        soup = self._soup()
        for tag in soup(["script", "style", "noscript", "head"]):
            tag.decompose()
        text = soup.get_text(separator="\n")
        lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
        snippet = "\n".join(lines[:max_lines])
        if len(lines) > max_lines:
            snippet += f"\n… ({len(lines) - max_lines} more lines, use `text all`)"
        return snippet

    def list_links(self) -> list[tuple[int, str, str]]:
        """Return [(idx, label, href)] for navigable links on the current page."""
        soup = self._soup()
        results = []
        idx = 0
        for a in soup.find_all("a", href=True):
            href = a["href"]
            # Only PARAMS links and direct journal links (skip JS popups, anchors, etc.)
            if "PARAMS=" in href or (self.journal in href and "javascript" not in href):
                label = a.get_text(strip=True) or href[:40]
                results.append((idx, label, href))
                idx += 1
        return results

    def _extract_form_data_from(self, html: str) -> dict:
        form = BeautifulSoup(html, "html.parser").find("form")
        if not form:
            return {}
        return {
            inp["name"]: inp.get("value", "")
            for inp in form.find_all("input")
            if inp.get("name")
        }

    def _extract_form_data(self) -> dict:
        return self._extract_form_data_from(self.current_html)

    def _extract_form_items_from(self, html: str) -> tuple[str, list[tuple[str, str]]]:
        """Return (action, [(name, value), ...]) for all form controls, preserving duplicates."""
        soup = BeautifulSoup(html, "html.parser")
        form = soup.find("form")
        if not form:
            return "", []

        items: list[tuple[str, str]] = []
        for inp in form.find_all("input"):
            name = inp.get("name")
            if name:
                items.append((name, inp.get("value", "")))
        for ta in form.find_all("textarea"):
            name = ta.get("name")
            if name:
                items.append((name, ta.text))
        for sel in form.find_all("select"):
            name = sel.get("name")
            if not name:
                continue
            selected = sel.find_all("option", selected=True)
            if selected:
                for opt in selected:
                    items.append((name, opt.get("value", "")))
            else:
                first = sel.find("option")
                if first:
                    items.append((name, first.get("value", "")))
        return form.get("action", self.journal_url), items

    def show_form_fields(self) -> list[tuple[str, str, str]]:
        """Return [(type, name, value)] for all form fields."""
        soup = self._soup()
        form = soup.find("form")
        if not form:
            return []
        fields = []
        for inp in form.find_all(["input", "select", "textarea"]):
            ftype = inp.get("type", inp.name)
            name = inp.get("name", "")
            value = inp.get("value", "")
            if inp.name == "select":
                selected = inp.find("option", selected=True)
                value = selected["value"] if selected else ""
            fields.append((ftype, name, value))
        return fields

    @staticmethod
    def _reviewer_counts(status: str) -> str:
        """Summarise a queue row's reviewer-status cell.

        ScholarOne writes e.g. ``3 active selections; 3 invited; 3 agreed;
        5 declined; 2 returned``.  Those numbers are cumulative, not disjoint:
        *invited* counts every live selection, *agreed* the subset that
        accepted, *returned* the subset that already submitted a review.  So
        the numbers an editor actually wants are differences:

        * received  = returned
        * waiting   = agreed - returned      (accepted, review still to come)
        * pending   = invited - agreed       (invitation not answered yet)
        """
        def num(word: str) -> int | None:
            m = re.search(rf"(\d+)\s+{word}", status)
            return int(m.group(1)) if m else None

        invited, agreed = num("invited"), num("agreed")
        declined, returned = num("declined"), num("returned")
        if invited is None and agreed is None and declined is None:
            return ""

        invited  = invited or 0
        agreed   = agreed or 0
        returned = returned or 0
        parts = [f"{returned} received", f"{max(agreed - returned, 0)} waiting"]
        if invited - agreed > 0:
            parts.append(f"{invited - agreed} pending")
        if declined:
            parts.append(f"{declined} declined")
        return " / ".join(parts)

    @staticmethod
    def _queue_stage(cell) -> str:
        """The workflow task of a queue row's status cell, e.g.
        ``Make Recommendation (due 28-Oct-2026)`` or
        ``Select Reviewers (due 03-Oct-2026, 18 days overdue)``.

        Needed next to `_reviewer_counts`: once every review is returned,
        ScholarOne drops the counts line and shows only the task.
        """
        span = cell.find("span", class_="pagecontents")
        if span is None:
            return ""
        text = span.get_text(" ", strip=True)
        m = re.match(r"(.+?)\s*\(Due ([^)]+)\)", text)
        if not m:
            return ""
        due = m.group(2)
        late = re.search(r"(\d+ days? overdue)", text)
        return f"{m.group(1)} (due {due}{', ' + late.group(1) if late else ''})"

    def goto_dashboard(self):
        """POST back to the AE dashboard from wherever the session currently is.

        A manuscript details page carries no queue links, so this is the way
        out of one — needed whenever a second manuscript must be reached after
        the first (the dashboard is the only page that lists every queue).
        Updates `current_html` / `current_url` and returns the response.
        """
        form = self._extract_form_data()
        form["NEXT_PAGE"]        = "ASSOCIATE_EDITOR_DASHBOARD"
        form["PAGE_LOADED_FLAG"] = "Y"
        r = self.session.post(
            self.journal_url, data=form,
            headers={"Referer": self.current_url, "Origin": BASE_URL},
        )
        r.raise_for_status()
        self._update_page(r.url, r.text)
        return r

    def _dashboard_link_map(self, html: str) -> dict[str, str]:
        """Extract queue-label → href from a dashboard page."""
        soup = BeautifulSoup(html, "html.parser")
        link_map: dict[str, str] = {}
        for a in soup.find_all("a", href=True):
            label = a.get_text(strip=True)
            href  = a["href"]
            if "PARAMS=" in href and label:
                link_map[label] = href
        return link_map

    def _get_dashboard_link_map(self) -> tuple[dict[str, str], str]:
        """Return (queue-label → href, dashboard-or-current referer URL)."""
        queue_keys = {
            "Select Reviewers",
            "Invite Reviewers",
            "Assign Reviewers",
            "Reviewer Scoring",
            "Overdue Reviewer Response",
            "Overdue Reviewer Scores",
            "Manuscripts Awaiting Revision",
        }
        link_map = self._dashboard_link_map(self.current_html)
        source_url = self.current_url
        if queue_keys.intersection(link_map):
            return link_map, source_url

        side_nav_href = next(
            (
                href
                for label, href in link_map.items()
                if "dashboard" in label.lower() or "associate editor" in label.lower()
            ),
            None,
        )

        if side_nav_href:
            dashboard_url = f"{BASE_URL}/{side_nav_href}"
            r = self.session.get(dashboard_url, headers={"Referer": self.current_url})
            r.raise_for_status()
            return self._dashboard_link_map(r.text), dashboard_url

        # No side-nav link either — typically a manuscript details page, which
        # carries no queue links at all.  POST our way back to the dashboard.
        r = self.goto_dashboard()
        return self._dashboard_link_map(r.text), r.url

    def _fetch_queue_papers(
        self,
        href: str,
        referer: str,
        *,
        include_nav: bool = False,
    ) -> list[dict]:
        """Fetch a dashboard queue and return structured manuscript rows."""
        url = f"{BASE_URL}/{href}"
        r = self.session.get(url, headers={"Referer": referer})
        r.raise_for_status()
        return self._parse_queue_papers(r.text, include_nav=include_nav)

    def _parse_queue_papers(
        self,
        html: str,
        *,
        include_nav: bool = False,
    ) -> list[dict]:
        """Parse a manuscript-list page and return structured manuscript rows."""
        ms_re = re.compile(rf"^({self.ms_id_pattern})")

        def clean_title(title: str) -> str:
            return re.sub(r"\s*\[\s*View Submission\s*\].*", "", title).strip()

        soup = BeautifulSoup(html, "html.parser")
        papers = []
        seen: set[str] = set()
        for row in soup.find_all("tr"):
            cells = row.find_all("td", recursive=False)
            if len(cells) < 4:
                continue
            m = ms_re.match(cells[0].get_text(" ", strip=True))
            if not m:
                continue
            ms_id = m.group(1)
            if ms_id in seen:
                continue
            seen.add(ms_id)
            paper = {
                "ms_id": ms_id,
                "date": cells[2].get_text(strip=True),
                "title": clean_title(cells[1].get_text(" ", strip=True)),
                "counts": self._reviewer_counts(cells[3].get_text(" ", strip=True)),
                "stage": self._queue_stage(cells[3]),
            }
            if include_nav:
                nav = self._find_ms_nav_data(ms_id, html)
                if not nav:
                    continue
                paper["nav"] = nav
            papers.append(paper)
        return papers

    def _queue_page_numbers(self, html: str) -> list[int]:
        numbers = {
            int(match)
            for match in re.findall(r"CURRENT_PAGE_NO'\s*,\s*'(\d+)'", html)
        }
        return sorted(numbers) or [1]

    def _fetch_queue_page_html(self, html: str, page_number: int, referer: str) -> str:
        form = self._extract_form_data_from(html)
        form.update({
            "JUST_PAGED": "TRUE",
            "SEARCH_SHOW_ALL_ATTRIB_LEVELS": "N",
            "CURRENT_PAGE_NO": str(page_number),
            "NEXT_PAGE": form.get("NEXT_PAGE") or "ASSOCIATE_EDITOR_VIEW_MANUSCRIPTS",
            "PAGE_LOADED_FLAG": "Y",
        })
        r = self.session.post(
            self.journal_url,
            data=form,
            headers={"Referer": referer, "Origin": BASE_URL},
        )
        r.raise_for_status()
        return r.text

    def fetch_queue_papers_all_pages(
        self,
        href: str,
        referer: str,
        *,
        include_nav: bool = False,
        max_pages: int = 50,
    ) -> list[dict]:
        """Fetch every visible page for a dashboard queue."""
        url = f"{BASE_URL}/{href}"
        r = self.session.get(url, headers={"Referer": referer})
        r.raise_for_status()
        first_html = r.text

        papers: list[dict] = []
        seen: set[str] = set()
        pages_seen: set[int] = set()
        for page_number in self._queue_page_numbers(first_html)[:max_pages]:
            if page_number in pages_seen:
                continue
            pages_seen.add(page_number)
            page_html = (
                first_html
                if page_number == 1
                else self._fetch_queue_page_html(first_html, page_number, url)
            )
            for paper in self._parse_queue_papers(page_html, include_nav=include_nav):
                if paper["ms_id"] in seen:
                    continue
                seen.add(paper["ms_id"])
                papers.append(paper)
        return papers

    # All queue names an AE may have access to.
    _ALL_QUEUE_KEYS: tuple[str, ...] = (
        "Select Reviewers",
        "Invite Reviewers",
        "Assign Reviewers",
        "Reviewer Scoring",
        "Overdue Reviewer Response",
        "Overdue Reviewer Scores",
        "Manuscripts without Decisions",
        "Manuscripts with Decisions",
        "Manuscripts Awaiting Revision",
    )

    def _nav_post(self, nav: dict, referer: str) -> bool:
        """POST to ASSOCIATE_EDITOR_MANUSCRIPT_DETAILS using a nav dict."""
        form = self._extract_form_data()
        form.update({
            "NEXT_PAGE":        "ASSOCIATE_EDITOR_MANUSCRIPT_DETAILS",
            "PAGE_LOADED_FLAG": "Y",
            "XIK_TAGACT":       nav["tagact"],
            nav["tab_field"]:   nav["tab_value"],
            "XIK_DOCU_ID":      nav["docu_id"],
        })
        r = self.session.post(
            self.journal_url, data=form,
            headers={"Referer": referer, "Origin": BASE_URL},
        )
        r.raise_for_status()
        self._update_page(r.url, r.text)
        return True

    def navigate_to_any_manuscript(self, ms_id: str) -> bool:
        """Navigate to a manuscript details page by searching ALL accessible queues.

        Unlike navigate_to_reviewer_tab (reviewer queues only), this also checks
        'Manuscripts without Decisions', 'Manuscripts with Decisions', and
        'Manuscripts Awaiting Revision', allowing access to papers not currently
        in any reviewer-management queue.

        Nav data is cached per session so repeated calls for the same ms_id skip
        the queue scan entirely.
        """
        # Fast path: already on the right page
        if (ms_id in self.current_html
                and 'value="ASSOCIATE_EDITOR_MANUSCRIPT_DETAILS"' in self.current_html):
            return True

        # Cache hit
        if ms_id in self._nav_cache:
            self._debug(f"[nav-cache] hit for {ms_id}")
            nav = self._nav_cache[ms_id]
            # We need to be on a page that has the form; fetch the dashboard if needed
            if 'value="ASSOCIATE_EDITOR_MANUSCRIPT_DETAILS"' not in self.current_html:
                nav_on_page = self._find_ms_nav_data(ms_id, self.current_html)
                if not nav_on_page:
                    link_map, source_url = self._get_dashboard_link_map()
                    for queue_name in self._ALL_QUEUE_KEYS:
                        href = link_map.get(queue_name)
                        if not href:
                            continue
                        queue_url = f"{BASE_URL}/{href}"
                        r = self.session.get(queue_url, headers={"Referer": source_url})
                        r.raise_for_status()
                        self._update_page(queue_url, r.text)
                        if self._find_ms_nav_data(ms_id, self.current_html):
                            break
            return self._nav_post(nav, self.current_url)

        # Try current page first
        nav = self._find_ms_nav_data(ms_id, self.current_html)
        if nav:
            self._nav_cache[ms_id] = nav
            return self._nav_post(nav, self.current_url)

        link_map, source_url = self._get_dashboard_link_map()
        for queue_name in self._ALL_QUEUE_KEYS:
            href = link_map.get(queue_name)
            if not href:
                continue
            queue_url = f"{BASE_URL}/{href}"
            self._debug(f"[all-queues] checking {queue_name!r} for {ms_id}")
            try:
                r = self.session.get(queue_url, headers={"Referer": source_url})
                r.raise_for_status()
            except Exception as exc:
                self._debug(f"[all-queues] fetch error for {queue_name!r}: {exc}")
                continue
            first_html = r.text
            # Opportunistically cache nav for ALL papers on this page
            for paper in self._parse_queue_papers(first_html, include_nav=True):
                if paper.get("nav"):
                    self._nav_cache.setdefault(paper["ms_id"], paper["nav"])
            pages = self._queue_page_numbers(first_html)
            for page_no in pages:
                page_html = (
                    first_html if page_no == 1
                    else self._fetch_queue_page_html(first_html, page_no, queue_url)
                )
                if page_no > 1:
                    for paper in self._parse_queue_papers(page_html, include_nav=True):
                        if paper.get("nav"):
                            self._nav_cache.setdefault(paper["ms_id"], paper["nav"])
                nav = self._find_ms_nav_data(ms_id, page_html)
                if nav:
                    self._nav_cache[ms_id] = nav
                    self._debug(f"[all-queues] {ms_id} found on page {page_no} of {queue_name!r}")
                    self._update_page(queue_url, page_html)
                    return self._nav_post(nav, queue_url)
        print(f"[all-queues] {ms_id} not found in any accessible queue")
        return False

    def reviewer_dashboard_papers(self) -> list[dict]:
        """Return reviewer-manageable manuscripts from AE dashboard queues."""
        reviewer_queue_keys = (
            "Select Reviewers",
            "Invite Reviewers",
            "Assign Reviewers",
            "Reviewer Scoring",
            "Overdue Reviewer Response",
            "Overdue Reviewer Scores",
        )
        link_map, source_url = self._get_dashboard_link_map()
        papers: list[dict] = []
        seen: set[str] = set()
        for queue_name in reviewer_queue_keys:
            href = link_map.get(queue_name)
            if not href:
                continue
            for paper in self._fetch_queue_papers(href, source_url, include_nav=True):
                if paper["ms_id"] in seen:
                    continue
                seen.add(paper["ms_id"])
                paper["queue"] = queue_name
                papers.append(paper)
        return papers

    def invited_reviewers_papers(self) -> list[dict]:
        """Return papers to scan for invitee history, including decided manuscripts."""
        queue_keys = (
            "Select Reviewers",
            "Invite Reviewers",
            "Assign Reviewers",
            "Reviewer Scoring",
            "Overdue Reviewer Response",
            "Overdue Reviewer Scores",
            "Manuscripts with Decisions",
        )
        link_map, source_url = self._get_dashboard_link_map()
        papers: list[dict] = []
        seen: set[str] = set()
        for queue_name in queue_keys:
            href = link_map.get(queue_name)
            if not href:
                continue
            try:
                queue_papers = self._fetch_queue_papers(href, source_url, include_nav=True)
            except Exception as exc:
                self._debug(f"skipping queue {queue_name!r}: {exc}")
                continue
            for paper in queue_papers:
                if paper["ms_id"] in seen:
                    continue
                seen.add(paper["ms_id"])
                paper["queue"] = queue_name
                papers.append(paper)
        return papers

    def ae_dashboard(self) -> str:
        """Fetch the AE dashboard queues and return a formatted summary."""
        QUEUE_KEYS = {
            "Select Reviewers", "Assign Reviewers",
            "Manuscripts Awaiting Revision",
        }

        # Use the current page if it's already the dashboard (common case after
        # login or after typing `editor` without navigating away).
        link_map = self._dashboard_link_map(self.current_html)

        # If we navigated away, fetch the dashboard via its PARAMS link which is
        # present in every page's side-nav; fall back to a fresh-login POST.
        if not QUEUE_KEYS.intersection(link_map):
            # Try GET via the side-nav "AE Dashboard" link present on all pages
            side_nav_href = next(
                (href for label, href in link_map.items()
                 if "dashboard" in label.lower() or "associate editor" in label.lower()),
                None,
            )
            if side_nav_href:
                url = f"https://mc.manuscriptcentral.com/{side_nav_href}"
                r = self.session.get(url, headers={"Referer": self.current_url})
                r.raise_for_status()
                link_map = self._dashboard_link_map(r.text)

        if not QUEUE_KEYS.intersection(link_map):
            return "Could not load dashboard — try running `login` to re-authenticate."

        MS_RE = re.compile(rf"^({self.ms_id_pattern})")

        def clean_title(t: str) -> str:
            return re.sub(r"\s*\[\s*View Submission\s*\].*", "", t).strip()

        def fetch_queue(href: str) -> list[tuple[str, str, str]]:
            url = f"https://mc.manuscriptcentral.com/{href}"
            r2  = self.session.get(url, headers={"Referer": self.journal_url})
            r2.raise_for_status()
            # Populate nav cache so navigate_to_any_manuscript can skip re-fetching
            for paper in self._parse_queue_papers(r2.text, include_nav=True):
                if paper.get("nav"):
                    self._nav_cache.setdefault(paper["ms_id"], paper["nav"])
            self._update_page(url, r2.text)
            soup2 = BeautifulSoup(r2.text, "html.parser")
            papers = []
            seen: set[str] = set()
            for row in soup2.find_all("tr"):
                cells = row.find_all("td", recursive=False)
                if len(cells) < 4:
                    continue
                m = MS_RE.match(cells[0].get_text(" ", strip=True))
                if not m:
                    continue
                ms_id = m.group(1)
                if ms_id in seen:
                    continue
                seen.add(ms_id)
                title = clean_title(cells[1].get_text(" ", strip=True))
                date  = cells[2].get_text(strip=True)
                papers.append((ms_id, date, title))
            return papers

        # Fetch both reviewer queues and merge, deduplicating by ms_id.
        # fetch_queue stores the last queue page in self.current_html/_url so that
        # navigate_to_any_manuscript can POST from a queue context (not a details page).
        merged: dict[str, tuple[str, str, str]] = {}
        queue_page_url  = self.current_url
        queue_page_html = self.current_html
        for key in ("Select Reviewers", "Assign Reviewers"):
            if key in link_map:
                for ms_id, date, title in fetch_queue(link_map[key]):
                    if ms_id not in merged:
                        merged[ms_id] = (date, title, "")
                if link_map.get(key):
                    queue_page_url  = self.current_url
                    queue_page_html = self.current_html

        awaiting: list[tuple[str, str, str]] = []
        if "Manuscripts Awaiting Revision" in link_map:
            awaiting = fetch_queue(link_map["Manuscripts Awaiting Revision"])

        def reviewer_status_counts(ms_id: str) -> str:
            # Reset to a queue page before navigating so _nav_post works correctly.
            # POSTing from a manuscript details page with a different nav dict silently
            # returns the wrong manuscript.
            self._update_page(queue_page_url, queue_page_html)
            if not self.navigate_to_any_manuscript(ms_id):
                return ""
            rows = self.selected_reviewer_rows()
            pending  = sum(1 for r in rows if r["status"] == "Invited")
            agreed   = sum(1 for r in rows if r["status"] in ("Agreed", "Overdue"))
            declined = sum(1 for r in rows if r["status"] in ("Declined", "Unavailable"))
            received = sum(1 for r in rows if r["status"] not in
                          ("Invited", "Agreed", "Overdue", "Declined", "Unavailable"))
            parts = []
            if received:
                parts.append(f"{received} received")
            if agreed:
                parts.append(f"{agreed} agreed")
            if pending:
                parts.append(f"{pending} pending")
            if declined:
                parts.append(f"{declined} declined")
            return " / ".join(parts)

        # Fetch accurate reviewer counts by navigating to each manuscript's reviewer tab
        for ms_id in list(merged.keys()):
            date, title, _ = merged[ms_id]
            merged[ms_id] = (date, title, reviewer_status_counts(ms_id))

        # Restore to queue page so subsequent editor calls don't start from a manuscript
        self._update_page(queue_page_url, queue_page_html)

        lines = []
        total = 0

        if merged:
            total += len(merged)
            lines.append(f"┌─ Need Reviewers ({len(merged)}) {'─'*60}")
            for ms_id, (date, title, counts) in sorted(merged.items()):
                rev = f"  [{counts}]" if counts else ""
                lines.append(f"│  {ms_id:30}  {date:12}  {title}{rev}")
            lines.append("└" + "─" * 79)

        if awaiting:
            total += len(awaiting)
            lines.append(f"┌─ Awaiting Author Revision ({len(awaiting)}) {'─'*50}")
            for ms_id, date, title in awaiting:
                lines.append(f"│  {ms_id:30}  {date:12}  {title}")
            lines.append("└" + "─" * 79)

        lines.append("")
        lines.append(f"  {total} papers")
        return "\n".join(lines)

    # ── reviewer invitation ───────────────────────────────────────────────────

    def _find_ms_nav_data(self, ms_id: str, html: str) -> dict | None:
        """Return {tagact, tab_field, tab_value, docu_id} for ms_id in html."""
        import html as _html
        unesc = _html.unescape(html)
        idx = unesc.find(ms_id)
        if idx < 0:
            self._debug(f"manuscript {ms_id} not present on page {self.page_title()!r}")
            return None
        window = unesc[idx: idx + 4000]
        m = re.search(
            r"setField\('XIK_TAGACT'\s*,\s*'([^']+)'\)[^;]*;"
            r"[^;]*setField\('(MANUSCRIPT_DETAILS_JUMP_TO_TAB_\d+)'\s*,\s*'([^']+)'\)[^;]*;"
            r"[^;]*setDataAndNextPage\('XIK_DOCU_ID'\s*,\s*'([^']+)'\s*,\s*"
            r"'ASSOCIATE_EDITOR_MANUSCRIPT_DETAILS'\)",
            window,
            re.DOTALL,
        )
        if not m:
            self._debug(f"manuscript {ms_id} found, but detail-link parser did not match")
            return None
        self._debug(f"manuscript {ms_id} navigation data found")
        return {
            "tagact":    m.group(1),
            "tab_field": m.group(2),
            "tab_value": m.group(3),
            "docu_id":   m.group(4),
        }

    def navigate_to_reviewer_tab(self, ms_id: str, nav: dict | None = None) -> bool:
        """Navigate to the manuscript's Select-Reviewers details page."""
        if (
            ms_id in self.current_html
            and 'value="ASSOCIATE_EDITOR_MANUSCRIPT_DETAILS"' in self.current_html
            and (
                "XIK_RP_ID" in self.current_html
                or "XIK_ADD_DOCUMENT_PERSON_ID" in self.current_html
                or "RETURN_TO_SEARCH_FL" in self.current_html
            )
        ):
            self._debug(f"already on manuscript details page for {ms_id}")
            return True

        # Deliberately not consulting _nav_cache here: a nav dict is only valid
        # when POSTed from the listing page it was scraped from.  Reusing a
        # cached one from a manuscript details page silently returns the wrong
        # manuscript, so re-locate the row on a live queue page instead.
        nav = nav or self._find_ms_nav_data(ms_id, self.current_html)
        if not nav:
            # Not on a page that lists queues (typically another manuscript's
            # details page) — hop back to the AE dashboard to get the links.
            link_map, source_url = self._get_dashboard_link_map()
            reviewer_queue_keys = (
                "Select Reviewers",
                "Invite Reviewers",
                "Assign Reviewers",
                "Reviewer Scoring",
                "Overdue Reviewer Response",
                "Overdue Reviewer Scores",
            )
            queue_candidates = [
                (key, href)
                for key, href in link_map.items()
                if key in reviewer_queue_keys
            ]
            if not queue_candidates:
                self._debug("no reviewer queues found on current page")
                return False

            for queue_name, queue_href in queue_candidates:
                queue_url = f"{BASE_URL}/{queue_href}"
                self._debug(f"checking {queue_name!r} queue for manuscript {ms_id}")
                r = self.session.get(queue_url, headers={"Referer": source_url})
                r.raise_for_status()
                self._update_page(queue_url, r.text)
                nav = self._find_ms_nav_data(ms_id, self.current_html)
                if nav:
                    self._debug(f"manuscript {ms_id} located in {queue_name!r} queue")
                    break
            if not nav:
                self._debug(f"manuscript {ms_id} not found in any reviewer queue")
                return False

        self._nav_cache[ms_id] = nav
        return self._nav_post(nav, self.current_url)

    def selected_reviewer_rows(self) -> list[dict[str, str]]:
        """Return structured data for already-selected/invited reviewers.

        Each dict contains: name, status, history, full_history, person_id,
        mc_email, invite_popup, person_details_popup, history_popup,
        institution (always ""), role ("invited").
        Compatible shape with parse_reviewer_candidates() rows.
        """
        soup = self._soup()
        results = []
        seen: set[str] = set()
        for tr in soup.find_all("tr"):
            rp_inp = tr.find("input", {"name": re.compile(r"XIK_RP_ID\d+")})
            if not rp_inp:
                continue
            tds = tr.find_all("td", recursive=False)
            if len(tds) < 3:
                continue
            name_link = tr.find("a", href=re.compile(r"mailpopup"))
            name = name_link.get_text(strip=True) if name_link else ""
            if not name or name in seen:
                continue
            seen.add(name)
            history = re.sub(r"\s+", " ", tds[3].get_text(" ", strip=True)).strip() if len(tds) > 3 else ""
            full_history = history
            # Trim to the first "Invited: DD-Mon-YYYY" part
            history_m = re.search(r"(Invited:\s*\S+)", history)
            history = history_m.group(1) if history_m else history[:40]
            status_text = re.sub(r"\s+", " ", tds[2].get_text(" ", strip=True)).strip()
            status_text = re.sub(r"(Response Select\.\.\..*|invite again)", "", status_text).strip()
            status = ""
            status_m = re.search(
                r"\b(Agreed|Invited|Unavailable|Selected|Declined|Completed|Overdue|Pending)\b",
                status_text,
                re.IGNORECASE,
            )
            if status_m:
                status = status_m.group(1).title()
            if not status:
                first_p = tds[2].find("p", class_="pagecontents")
                if first_p:
                    first_text = first_p.find(string=True, recursive=False)
                    candidate_status = first_text.strip() if first_text else first_p.get_text(strip=True)
                    if candidate_status and candidate_status != "Reviewer List":
                        status = candidate_status
            if not status:
                if history.startswith("Invited:"):
                    status = "Invited"
                elif "Selected:" in history:
                    status = "Selected"
            invite_popup = ""
            invite_link = tr.find("a", href=re.compile(r"email_popup_stay"))
            if invite_link:
                href = invite_link.get("href", "")
                popup_m = re.search(r"popWindow\('([^']+)',\s*'email_popup_stay_[^']+'", href)
                if popup_m:
                    invite_popup = popup_m.group(1)
            person_details_popup = ""
            details_link = tr.find("a", href=re.compile(r"person_details_pop"))
            if details_link:
                href = details_link.get("href", "")
                popup_m = re.search(r"popWindow\('([^']+)',\s*'person_details_pop'", href)
                if popup_m:
                    person_details_popup = popup_m.group(1)
            history_popup = ""
            history_link = next(
                (a for a in tr.find_all("a", href=True) if a.get_text(" ", strip=True) == "view full history"),
                None,
            )
            if history_link:
                href = history_link.get("href", "")
                popup_m = re.search(r"popWindow\('([^']+)',\s*'history_popup'", href)
                if popup_m:
                    history_popup = popup_m.group(1)
            # Extract email from mailpopup href or anywhere in the row
            mc_email = ""
            if name_link:
                em = re.search(
                    r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
                    name_link.get("href", ""),
                )
                if em:
                    mc_email = em.group(0)
            if not mc_email:
                em = re.search(
                    r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
                    tr.get_text(" "),
                )
                if em:
                    mc_email = em.group(0)
            results.append({
                "name": name,
                "status": status[:30],
                "history": history[:30],
                "full_history": full_history,
                # Aligned with parse_reviewer_candidates():
                "person_id": rp_inp.get("value", ""),
                "institution": "",
                "xik": "",
                "role": "invited",
                # Extra fields only present on invited rows:
                "mc_email": mc_email,
                "invite_popup": invite_popup,
                "person_details_popup": person_details_popup,
                "history_popup": history_popup,
            })
        return results

    # Keep the old private name as an alias so internal call-sites keep working.
    _selected_reviewer_rows = selected_reviewer_rows

    def parse_selected_reviewers(self) -> list[tuple[str, str, str]]:
        """Return [(name, status, history)] for already-selected reviewers."""
        return [
            (row["name"], row["status"], row["history"])
            for row in self.selected_reviewer_rows()
        ]

    def person_account_info(self, reviewer_row: dict[str, str]) -> dict[str, str]:
        """Return the "Account Information" tab of a person-details popup.

        Search results and candidate rows carry a name and a popup link but no
        contact details, so this is what tells two same-named MC accounts apart
        before inviting one: keys ``email``, ``institution``, ``department``,
        ``country``, ``orcid``, ``keywords`` (missing keys simply absent).

        The tab is not a link but a form POST from the popup page
        (``PERSON_DETAILS_TAB_NAME=PDT_ACC_INFO``).
        """
        popup = reviewer_row.get("person_details_popup", "")
        if not popup:
            return {}
        popup_url = popup if popup.startswith("http") else f"{BASE_URL}/{popup.lstrip('/')}"
        r = self.session.get(popup_url, headers={"Referer": self.current_url})
        r.raise_for_status()

        form = self._extract_form_data_from(r.text)
        form["PERSON_POPUP_ACCT_TAB_FL"] = "Y"
        form["PERSON_DETAILS_TAB_NAME"] = "PDT_ACC_INFO"
        form["NEXT_PAGE"] = "PERSON_DETAILS_POPUP"
        form["PAGE_LOADED_FLAG"] = "Y"
        r2 = self.session.post(popup_url.split("?")[0], data=form,
                               headers={"Referer": popup_url, "Origin": BASE_URL})
        r2.raise_for_status()
        text = self._html_to_text(r2.text)

        info: dict[str, str] = {}
        labels = {
            "Full Name": "full_name",
            "User ID": "user_id",
            "ID #": "person_id",
            "Primary affiliation": "affiliation",
            "Primary E-Mail Address": "email",
            "Secondary E-Mail Address": "email_secondary",
            "Roles": "roles",
            "Keywords": "keywords",
            "Specialty/Area of Expertise": "expertise",
        }
        # Section headings that follow a field whose value is empty — without
        # them an unfilled "Keywords:" would swallow the next heading as value.
        stops = {"Attributes", "Comments", "External Links", "Flag this account",
                 "Last Five Account Audits", "Password History"}
        lines = text.splitlines()
        for i, line in enumerate(lines):
            key = labels.get(line.strip().rstrip(":"))
            if key and key not in info and i + 1 < len(lines):
                value = lines[i + 1].strip()
                if value and value.rstrip(":") not in labels and value not in stops:
                    info[key] = value.rstrip(",")
        m = re.search(r"\b(\d{4}-\d{4}-\d{4}-[\dX]{4})\b", text)
        if m:
            info["orcid"] = m.group(1)
        return info

    def reviewer_history_analysis(self, reviewer_row: dict[str, str]) -> dict[str, str]:
        """Return ScholarOne reviewer-history aggregates from the person details popup."""
        popup = reviewer_row.get("person_details_popup", "")
        if not popup:
            return {}
        cache_key = reviewer_row.get("person_id") or popup
        cached = self.reviewer_history_cache.get(cache_key)
        if cached is not None:
            return cached

        popup_url = popup if popup.startswith("http") else f"{BASE_URL}/{popup.lstrip('/')}"
        r = self.session.get(popup_url, headers={"Referer": self.current_url})
        r.raise_for_status()
        soup = BeautifulSoup(r.text, "html.parser")

        stats: dict[str, str] = {}
        wanted_labels = {
            "Total number of manuscripts assigned in the past 12 months": "assigned_past_12m",
            "Total number of manuscripts currently assigned": "assigned_current",
            "Total number of reviews completed in the past 12 months": "completed_past_12m",
            "Total number of manuscripts assigned but no review returned": "assigned_no_review_returned",
            "Total number of open invitations (person has been invited, but has not responded to the invitation)": "open_invitations",
            "Total number of invitations in the past 30 days": "invitations_past_30d",
            "Date of last invitation": "last_invitation_date",
            "Number of times Agreed": "times_agreed",
            "Number of times Custom Agreed": "times_custom_agreed",
            "Number of times Late Accept": "times_late_accept",
            "Number of times Bad E-mail": "times_bad_email",
            "Number of times Declined": "times_declined",
            "Number of times No Response": "times_no_response",
            "Number of times Unavailable": "times_unavailable",
            "Average turnaround time": "average_turnaround_time",
            "Average R-Score": "average_r_score",
        }
        for row in soup.find_all("tr"):
            cells = row.find_all("td", recursive=False)
            if len(cells) < 2:
                continue
            value = re.sub(r"\s+", " ", cells[0].get_text(" ", strip=True)).strip()
            label = re.sub(r"\s+", " ", cells[1].get_text(" ", strip=True)).strip()
            if not value or not label:
                continue
            for wanted, key in wanted_labels.items():
                if label.startswith(wanted):
                    stats[key] = value
                    break

        # ORCID: look for an orcid.org link anywhere in the popup
        if "orcid" not in stats:
            orcid_link = soup.find("a", href=re.compile(r"orcid\.org"))
            if orcid_link:
                m_orcid = re.search(
                    r"(\d{4}-\d{4}-\d{4}-\d{3}[\dX])",
                    orcid_link.get("href", "") + " " + orcid_link.get_text(),
                )
                if m_orcid:
                    stats["orcid"] = m_orcid.group(1)

        # Email: scan the full popup text for an address
        if "email" not in stats:
            m_email = re.search(
                r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
                soup.get_text(" "),
            )
            if m_email:
                stats["email"] = m_email.group(0)

        self.reviewer_history_cache[cache_key] = stats
        return stats

    def mc_reviewer_stats(self, email: str = "", name: str = "") -> dict:
        """
        Look up a reviewer in MC by email (preferred) or by name, and return their
        MC person_id, email (when confirmed by email search), average turnaround time,
        and R-score.  Returns {} if not found.
        Requires being on a manuscript reviewer tab first.
        When multiple name matches exist, iterates through all of them to find the
        candidate with actual turnaround data rather than N/A.
        """
        if email:
            candidates = self.search_reviewer_by_email(email)
        elif name:
            candidates = self.search_reviewer_by_name(name)
        else:
            return {}
        if not candidates:
            return {}

        base: dict = {}
        if email:
            base["mc_email"] = email

        # Try each candidate in order; stop at the first with real turnaround data.
        best: dict = {}
        for candidate in candidates:
            r = {**base, "mc_person_id": candidate["person_id"]}
            if not email and candidate.get("mc_email"):
                r["mc_email"] = candidate["mc_email"]
            popup = candidate.get("person_details_popup", "")
            if popup:
                stats = self.reviewer_history_analysis({
                    "person_details_popup": popup,
                    "review_person_id": candidate["person_id"],
                })
                turnaround = stats.get("average_turnaround_time", "")
                r_score = stats.get("average_r_score", "")
                if turnaround and turnaround != "N/A":
                    r["mc_turnaround"] = turnaround
                if r_score and r_score != "N/A":
                    r["mc_r_score"] = r_score
            if not best:
                best = r
            if r.get("mc_turnaround"):
                best = r
                break
        return best

    def reviewer_manuscript_history(self, reviewer_row: dict[str, str]) -> str:
        """Return the manuscript-specific reviewer history popup text."""
        popup = reviewer_row.get("history_popup", "")
        if not popup:
            return ""
        cache_key = popup
        cached = self.reviewer_manuscript_history_cache.get(cache_key)
        if cached is not None:
            return cached

        popup_url = popup if popup.startswith("http") else f"{BASE_URL}/{popup.lstrip('/')}"
        r = self.session.get(popup_url, headers={"Referer": self.current_url})
        r.raise_for_status()
        soup = BeautifulSoup(r.text, "html.parser")
        for tag in soup(["script", "style", "noscript", "head"]):
            tag.decompose()
        text = re.sub(r"\s+", " ", soup.get_text(" ", strip=True)).strip()
        self.reviewer_manuscript_history_cache[cache_key] = text
        return text

    def current_ae_name(self) -> str:
        """Return the current manuscript AE label, e.g. 'Doe, Jane'."""
        soup = self._soup()
        text = re.sub(r"\s+", " ", soup.get_text(" ", strip=True))
        m = re.search(r"\bAE:\s*(.*?)\s+EIC:", text)
        return m.group(1).strip() if m else ""

    @staticmethod
    def _normalize_name(label: str) -> str:
        return re.sub(r"[^a-z0-9]+", "", label.lower())

    @staticmethod
    def _name_sort_key(name: str) -> str:
        """Sort words alphabetically so 'David Lo' and 'Lo, David.' match."""
        words = re.sub(r"[^a-z ]+", "", name.lower()).split()
        return " ".join(sorted(words))

    def _invited_by_editor(self, history_text: str, editor_name: str) -> bool:
        if not history_text:
            return False
        if not editor_name:
            return "Invited by " in history_text
        editor_norm = self._normalize_name(editor_name)
        for match in re.finditer(r"Invited by ([^:]+):", history_text):
            if self._normalize_name(match.group(1)) == editor_norm:
                return True
        return False

    @staticmethod
    def _turnaround_hours(value: str) -> float:
        if not value or value == "N/A":
            return -1.0
        days = 0
        hours = 0
        m_days = re.search(r"(\d+)\s+days?", value, re.IGNORECASE)
        if m_days:
            days = int(m_days.group(1))
        m_hours = re.search(r"(\d+)\s+hours?", value, re.IGNORECASE)
        if m_hours:
            hours = int(m_hours.group(1))
        return float(days * 24 + hours)

    def invited_reviewers_overview(self) -> list[dict[str, object]]:
        """Return unique reviewers invited by the current AE across accessible papers."""
        papers = self.invited_reviewers_papers()
        overview: dict[str, dict[str, Any]] = {}

        for paper in tqdm(papers, desc="Collecting papers", unit="paper", leave=False):
            if not self.navigate_to_reviewer_tab(paper["ms_id"], nav=paper["nav"]):
                continue
            editor_name = self.current_ae_name()
            for reviewer_row in self.selected_reviewer_rows():
                manuscript_history = self.reviewer_manuscript_history(reviewer_row)
                if not self._invited_by_editor(manuscript_history, editor_name):
                    continue
                history_stats = self.reviewer_history_analysis(reviewer_row)
                key = self._normalize_name(reviewer_row["name"])
                entry = overview.get(key)
                if entry is None:
                    entry = {
                        "name": reviewer_row["name"],
                        "average_turnaround_time": history_stats.get("average_turnaround_time", "N/A"),
                        "open_invitations": history_stats.get("open_invitations", "-"),
                        "completed_past_12m": history_stats.get("completed_past_12m", "-"),
                        "last_invitation_date": history_stats.get("last_invitation_date", "-"),
                        "average_r_score": history_stats.get("average_r_score", "-"),
                        "papers": set(),
                    }
                    overview[key] = entry
                entry["papers"].add(paper["ms_id"])

        filtered = [
            item
            for item in overview.values()
            if self._turnaround_hours(str(item["average_turnaround_time"])) > 0
        ]

        return sorted(
            filtered,
            key=lambda item: (
                -self._turnaround_hours(str(item["average_turnaround_time"])),
                str(item["name"]).lower(),
            ),
        )

    def parse_reviewer_candidates(self) -> list[dict]:
        """Return candidate reviewer dicts with name, institution, person_id, xik, person_details_popup."""
        soup = self._soup()
        results = []
        for inp in soup.find_all("input", {"name": "XIK_ADD_DOCUMENT_PERSON_ID"}):
            xik = inp.get("value", "")
            onclick = inp.get("onclick", "")
            m = re.search(r"setSelected\(this,\s*'(\d+)'\)", onclick)
            if not m:
                continue
            person_id = m.group(1)
            row = inp.find_parent("tr")
            if not row:
                continue
            name_span = row.find("span", class_="pagecontents")
            name = name_span.get_text(" ", strip=True).split("\n")[0].strip() if name_span else ""
            institution = ""
            for span in row.find_all("span", class_="pagecontents"):
                text = span.get_text(" ", strip=True)
                if text and text != name and len(text) > 5:
                    institution = text[:60]
                    break
            person_details_popup = ""
            details_link = row.find("a", href=re.compile(r"person_details_pop"))
            if details_link:
                href = details_link.get("href", "")
                popup_m = re.search(r"popWindow\('([^']+)',\s*'person_details_pop'", href)
                if popup_m:
                    person_details_popup = popup_m.group(1)
            mc_email = ""
            em = re.search(
                r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
                row.get_text(" "),
            )
            if em:
                mc_email = em.group(0)
            results.append({
                "name": name,
                "institution": institution,
                "person_id": person_id,
                "xik": xik,
                "person_details_popup": person_details_popup,
                "mc_email": mc_email,
                # Aligned with selected_reviewer_rows():
                "role": "candidate",
                "status": "",
                "history": "",
            })
        return results

    def _post_manuscript_details(self, extra: dict) -> Any:
        """POST to ASSOCIATE_EDITOR_MANUSCRIPT_DETAILS with extra fields merged in."""
        form = self._extract_form_data()
        form.update({"NEXT_PAGE": "ASSOCIATE_EDITOR_MANUSCRIPT_DETAILS",
                      "PAGE_LOADED_FLAG": "Y"})
        form.update(extra)
        r = self.session.post(
            self.journal_url, data=form,
            headers={"Referer": self.current_url, "Origin": BASE_URL},
        )
        r.raise_for_status()
        self._update_page(r.url, r.text)
        return r

    @staticmethod
    def _normalize_person_label(label: str) -> str:
        return re.sub(r"[^a-z0-9]+", "", label.lower())

    def _find_candidate_add_action(self, person_id: str) -> dict | None:
        import html as _html
        _ADD_PAT = (
            r"setField\('XIK_CURRENT_DOCUMENT_TASK_ID','([^']+)'\);"
            r"setField\('CURRENT_DOCUMENT_TASK_ID_FOR_REVIEWER','([^']+)'\);"
            r"setField\('XIK_REVIEWER_SOURCE_RECORD_ID','([^']*)'\);\s*"
            r"setField\('XIK_REVIEWER_SOURCE_TYPE_ID','([^']*)'\);\s*"
            r"setDataAndNextPage\('XIK_TAGACT',\s*'([^']+)'\s*,\s*"
            r"'ASSOCIATE_EDITOR_MANUSCRIPT_DETAILS'\)"
        )
        soup = self._soup()
        candidate_name = ""
        candidate_xik = ""
        for inp in soup.find_all("input", {"name": "XIK_ADD_DOCUMENT_PERSON_ID"}):
            onclick = inp.get("onclick", "")
            selected_m = re.search(r"setSelected\(this,\s*'(\d+)'\)", onclick)
            if not selected_m or selected_m.group(1) != person_id:
                continue
            candidate_xik = inp.get("value", "")
            row = inp.find_parent("tr")
            if not row:
                break
            name_span = row.find("span", class_="pagecontents")
            candidate_name = name_span.get_text(" ", strip=True).split("\n")[0].strip() if name_span else ""
            controls_row = row.find_next_sibling("tr")
            if not controls_row:
                break
            add_m = re.search(_ADD_PAT, _html.unescape(controls_row.decode_contents()), re.DOTALL)
            if add_m:
                return {
                    "name": candidate_name,
                    "person_id": person_id,
                    "person_xik": candidate_xik,
                    "current_document_task_id": add_m.group(1),
                    "current_document_task_for_reviewer": add_m.group(2),
                    "reviewer_source_record_id": add_m.group(3),
                    "reviewer_source_type_id": add_m.group(4),
                    "tagact": add_m.group(5),
                }
            # Per-row Add button absent — multi-result page uses a shared button below.
            break
        if not candidate_name:
            return None
        # Fallback: find the shared "Add Selected" button anywhere on the page.
        add_m = re.search(_ADD_PAT, _html.unescape(self.current_html), re.DOTALL)
        if not add_m:
            return None
        return {
            "name": candidate_name,
            "person_id": person_id,
            "person_xik": candidate_xik,
            "current_document_task_id": add_m.group(1),
            "current_document_task_for_reviewer": add_m.group(2),
            "reviewer_source_record_id": add_m.group(3),
            "reviewer_source_type_id": add_m.group(4),
            "tagact": add_m.group(5),
        }

    def _find_selected_reviewer(self, reviewer_name: str, person_id: str = "") -> dict | None:
        """Locate an added reviewer's row by person id, else by name.

        Search results and manuscript rows label the same person differently —
        "Botacin PhD, Marcus F." or "Bogomolov bachelor, Egor" in the candidate
        list, "Botacin, Marcus" / "Bogomolov, Egor" on the manuscript — so a
        name match can wrongly report that a reviewer who *was* added is
        missing, and the invitation is then never sent.  The person id is an
        exact match when both pages carry the same xik token; the name key
        (surname + first initial, degrees dropped) is the fallback.
        """
        rows = self.selected_reviewer_rows()
        if person_id:
            for row in rows:
                if row.get("person_id") == person_id:
                    return row
        wanted = self._normalize_person_label(reviewer_name)
        for row in rows:
            if self._normalize_person_label(row["name"]) == wanted:
                return row

        wanted_key = self._person_name_key(reviewer_name)
        if not wanted_key:
            return None
        matches = [r for r in rows if self._person_name_key(r["name"]) == wanted_key]
        return matches[0] if len(matches) == 1 else None

    _NAME_TITLES = {"phd", "dr", "prof", "professor", "mr", "ms", "mrs", "jr", "sr", "md",
                    "bachelor", "master", "msc", "bsc"}

    @classmethod
    def _person_name_key(cls, label: str) -> str:
        """Surname + first initial, ignoring honorifics and middle initials."""
        parts = [p for p in re.split(r"[\s,]+", label.strip()) if p]
        words = [w for w in parts if w.strip(".").lower() not in cls._NAME_TITLES]
        if not words:
            return ""
        if "," in label:
            surname, rest = words[0], words[1:]
        else:
            surname, rest = words[-1], words[:-1]
        initial = next((w[0] for w in rest if len(w.strip(".")) > 1), "")
        return f"{re.sub(r'[^a-z]', '', surname.lower())}|{initial.lower()}"

    def _multipart_submit(self, url: str, items: list[tuple[str, str]], referer: str) -> object:
        from curl_cffi import CurlMime
        mp = CurlMime()
        for name, value in items:
            mp.addpart(name=name, data=value.encode())
        r = self.session.post(
            url,
            multipart=mp,
            headers={"Referer": referer, "Origin": BASE_URL},
        )
        r.raise_for_status()
        return r

    @staticmethod
    def reviews_contributed(stats: dict[str, str]) -> int:
        """Reviews returned to this journal, lifetime: agreed minus not returned."""
        def num(key: str) -> int:
            return int(stats.get(key) or 0) if (stats.get(key) or "0").isdigit() else 0
        agreed = num("times_agreed") + num("times_custom_agreed") + num("times_late_accept")
        return max(agreed - num("assigned_no_review_returned"), 0)

    @staticmethod
    def _insert_paragraph(body: str, paragraph: str) -> str:
        """Put `paragraph` after the first paragraph that follows "Dear …:" in an HTML letter."""
        m = re.search(r"Dear [^<]*<br\s*/?>\s*<br\s*/?>.*?<br\s*/?>\s*<br\s*/?>", body, re.S)
        at = m.end() if m else 0
        return f"{body[:at]}{paragraph}<br /><br />{body[at:]}"

    def _send_reviewer_invitation(self, invite_popup: str, paragraph: str = "") -> None:
        popup_url = invite_popup if invite_popup.startswith("http") else f"{BASE_URL}/{invite_popup.lstrip('/')}"
        frameset = self.session.get(popup_url, headers={"Referer": self.current_url})
        frameset.raise_for_status()
        frame_pairs = re.findall(r'<frame src="([^"]+)" name="([^"]+)"', frameset.text)
        frame_sources = {name: src for src, name in frame_pairs}
        main_src = frame_sources.get("mainemailwindow")
        if not main_src:
            raise RuntimeError("Could not open the reviewer invitation email popup.")

        main_url = urljoin(BASE_URL, main_src)
        main_page = self.session.get(main_url, headers={"Referer": frameset.url})
        main_page.raise_for_status()

        action, items = self._extract_form_items_from(main_page.text)
        if not items:
            raise RuntimeError("Reviewer invitation email form was empty.")

        if paragraph:
            items = [(k, self._insert_paragraph(v, paragraph) if k == "EMAIL_TEMPLATE_BODY" else v)
                     for k, v in items]

        override_values = {
            # Mirror the "Save & Send" button onclick: TASK_COMPLETED_FL=Y triggers
            # the server to send the invitation email.
            "TASK_COMPLETED_FL": "Y",
            "EMAIL_POPUP_CLOSE_WIN_FL": "Y",
            "EMAIL_POPUP_VALIDATE_FILE_SIZE_FL": "Y",
            "TRANSFER_TO": "null",
            "NEXT_PAGE": "EMAIL_POPUP_MAIN",
            "PAGE_LOADED_FLAG": "Y",
            "EMAIL_POPUP_MAIN_FULLY_LOADED": "Y",
        }
        for key, value in override_values.items():
            updated = False
            for idx, (name, _old_value) in enumerate(items):
                if name == key:
                    items[idx] = (name, value)
                    updated = True
            if not updated:
                items.append((key, value))

        post_url = urljoin(main_url, action or self.journal_url)
        self._multipart_submit(post_url, items, referer=main_url)

    def invite_reviewer(self, person_id: str, person_xik: str, paragraph: str = "") -> dict:
        """Add a reviewer candidate and send the invitation email if needed.

        `paragraph` (plain text) is inserted in the letter after its opening paragraph.
        """
        action = self._find_candidate_add_action(person_id)
        if not action:
            raise RuntimeError("Could not locate the Add action for the selected reviewer.")

        extra = {
            "MANUSCRIPT_DETAILS_SAVE_METADATA": "Y",
            "SELECTED_VALUES": action["person_id"],
            f"SET_SELECTED{action['person_id']}": "selected",
            "XIK_ADD_DOCUMENT_PERSON_ID": action["person_xik"] or person_xik,
            "XIK_CURRENT_DOCUMENT_TASK_ID": action["current_document_task_id"],
            "CURRENT_DOCUMENT_TASK_ID_FOR_REVIEWER": action["current_document_task_for_reviewer"],
            "XIK_REVIEWER_SOURCE_RECORD_ID": action["reviewer_source_record_id"],
            "XIK_REVIEWER_SOURCE_TYPE_ID": action["reviewer_source_type_id"],
            "XIK_TAGACT": action["tagact"],
        }
        self._post_manuscript_details(extra)

        selected = self._find_selected_reviewer(action["name"], action["person_id"])
        if not selected:
            raise RuntimeError(f"Reviewer {action['name']!r} was not added to the manuscript.")

        if selected["invite_popup"]:
            self._send_reviewer_invitation(selected["invite_popup"], paragraph)
        else:
            # The row can come back without its invite link (the page is
            # rebuilt as the reviewer is added), leaving the reviewer merely
            # "Selected" — nothing was mailed.  Refresh and send explicitly.
            self.send_pending_invitation(action["name"], paragraph)

        return {"name": action["name"]}

    def send_pending_invitation(self, name: str, paragraph: str = "") -> str:
        """Send the invitation of a reviewer stuck at "Selected".

        Adding a reviewer and mailing the invitation are two steps in MC, so a
        row can sit as "Selected" with nobody contacted.  Idempotent: returns
        the row's status, and does nothing when it is already "Invited".
        """
        self._post_manuscript_details({})
        row = self._find_selected_reviewer(name)
        if not row:
            return ""
        if (row.get("status") or "").strip().lower().startswith("invited"):
            return row.get("status", "")
        if row.get("invite_popup"):
            self._send_reviewer_invitation(row["invite_popup"], paragraph)
            self.log_action("invite_sent", name=name)
            # Re-POST the details page: the invitation popup does not update the
            # page in hand, so reading it again would report the stale
            # "Selected" for a reviewer who has just been invited.
            self._post_manuscript_details({})
            refreshed = self._find_selected_reviewer(name)
            if refreshed:
                return refreshed.get("status", "")
        return row.get("status", "")

    def _navigate_to_adv_search_form(self) -> str:
        """Navigate to the Advanced Search form and return the anchor name used."""
        import html as _html
        unesc = _html.unescape(self.current_html)
        m = re.search(
            r"setField\('RETURN_TO_SEARCH_FL','Y'\)[^;]*;"
            r"(?:[^;]*setField\('ANCHOR_PAGE_TO','([^']+)'\)[^;]*;)?\s*"
            r"[^;]*setDataAndNextPage\('XIK_TAGACT',\s*'([^']+)',\s*"
            r"'ASSOCIATE_EDITOR_MANUSCRIPT_DETAILS'\)",
            unesc,
        )
        if not m:
            raise RuntimeError(
                f"No reviewer search button found. Page title: {self.page_title()}"
            )
        anchor = m.group(1)
        tagact = m.group(2)
        if anchor and anchor != "ANCHOR_ADV_SEARCH_SEARCH":
            adv = re.search(
                r"setField\('ANCHOR_PAGE_TO','(ANCHOR_ADV_SEARCH_SEARCH)'\)[^;]*;"
                r"\s*setDataAndNextPage\('XIK_TAGACT',\s*'([^']+)',\s*"
                r"'ASSOCIATE_EDITOR_MANUSCRIPT_DETAILS'\)",
                unesc,
            )
            if adv:
                anchor = adv.group(1)
                tagact = adv.group(2)
        extra = {"RETURN_TO_SEARCH_FL": "Y", "XIK_TAGACT": tagact}
        if anchor:
            extra["ANCHOR_PAGE_TO"] = anchor
        self._post_manuscript_details(extra)
        return anchor or "ANCHOR_ADV_SEARCH_SEARCH"

    def _submit_reviewer_search(self, anchor: str, form_fields: dict) -> list[dict]:
        """Submit a reviewer search with the given fields and return candidates."""
        import html as _html
        button_name = {
            "ANCHOR_ADV_SEARCH_SEARCH": "SEARCH_REV_ADVANCED",
            "ANCHOR_AUTO_SUGG_SEARCH": "SEARCH_REV_AUTO_SUGG",
        }.get(anchor, "SEARCH_REV_QUICK")
        unesc = _html.unescape(self.current_html)
        btn_m = re.search(
            rf"<a href=\"javascript:[^\"]*setDataAndNextPage\('XIK_TAGACT'\s*,\s*'([^']+)'\s*,\s*"
            rf"'ASSOCIATE_EDITOR_MANUSCRIPT_DETAILS'\)[^\"]*\">\s*"
            rf"<img [^>]*name=\"{button_name}\"",
            unesc,
            re.DOTALL,
        )
        search_extra = dict(form_fields)
        if btn_m:
            search_extra["XIK_TAGACT"] = btn_m.group(1)
        self._debug(
            f"reviewer search uses anchor={anchor} button={button_name} "
            f"tagact={'found' if btn_m else 'missing'}"
        )
        self._post_manuscript_details(search_extra)
        candidates = self.parse_reviewer_candidates()
        return candidates

    def search_reviewer_by_email(self, email: str) -> list[dict]:
        """
        Navigate to the reviewer search form, submit an email search,
        and return matching candidates as dicts with name, institution, person_id, xik, person_details_popup.
        """
        anchor = self._navigate_to_adv_search_form()

        # Discover the email input field name from the rendered form
        soup = self._soup()
        visible_inputs = [
            inp for inp in soup.find_all("input")
            if inp.get("type", "hidden").lower()
               not in ("hidden", "submit", "image", "button", "checkbox", "radio")
            and inp.get("name")
        ]
        email_inp = None
        for inp in visible_inputs:
            if re.search(r"email|e_mail", inp["name"], re.I):
                email_inp = inp["name"]
                break
        if not email_inp and visible_inputs:
            for inp in visible_inputs:
                if inp["name"] != "QUICK_SEARCH_HEADER_SEARCH_TEXT":
                    email_inp = inp["name"]
                    break
        if not email_inp:
            raise RuntimeError(
                f"Could not locate email input. Visible inputs: "
                f"{[i['name'] for i in visible_inputs]}"
            )

        return self._submit_reviewer_search(anchor, {email_inp: email})

    def search_reviewer_by_name(self, name: str) -> list[dict]:
        """
        Navigate to the reviewer Advanced Search form, search by first/last name,
        and return matching candidates.
        """
        anchor = self._navigate_to_adv_search_form()

        soup = self._soup()
        visible_inputs = [
            inp for inp in soup.find_all("input")
            if inp.get("type", "hidden").lower()
               not in ("hidden", "submit", "image", "button", "checkbox", "radio")
            and inp.get("name")
        ]
        first_inp = next(
            (inp["name"] for inp in visible_inputs if re.search(r"first", inp["name"], re.I)),
            "ADMIN_FIRST_NAME",
        )
        last_inp = next(
            (inp["name"] for inp in visible_inputs if re.search(r"last", inp["name"], re.I)),
            "ADMIN_LAST_NAME",
        )

        # MC stores names its own way and matches them literally: "Gema
        # Rodríguez-Pérez" is "Rodriguez Perez, Gema", "Hong Jin Kang" is
        # "Kang, Hong Jin".  Try the splits and spellings in turn and stop at
        # the first that finds someone.
        import unicodedata

        def fold(s: str) -> str:
            s = unicodedata.normalize("NFKD", s).encode("ascii", "ignore").decode()
            return s.replace("-", " ").strip()

        if "," in name:
            last, _, first = (p.strip() for p in name.partition(","))
            splits = [(first, last)]
        else:
            words = name.split()
            splits = [(words[0] if words else "", " ".join(words[1:]))]
            if len(words) > 2:
                splits.append((" ".join(words[:-1]), words[-1]))
        tried: list[tuple[str, str]] = []
        for first, last in splits:
            for variant in ((first, last), (fold(first), fold(last))):
                if variant in tried:
                    continue
                tried.append(variant)
                if len(tried) > 1:
                    anchor = self._navigate_to_adv_search_form()
                found = self._submit_reviewer_search(
                    anchor, {first_inp: variant[0], last_inp: variant[1]})
                if found:
                    return found
        return []

    def invitation_paragraph(self, candidate: dict[str, str], **opts: Any) -> str:
        """A paragraph inserted after the opening of every invitation letter, or "".

        Empty by default. `opts` are the extra keyword arguments given to
        `invite_by_email` / `invite_by_name`.
        """
        return ""

    def _invite_one(self, ms_id: str, candidates: list[dict], label: str,
                    **paragraph_opts: Any) -> InviteResult:
        """Common tail after a reviewer search: invite if exactly 1 match.

        The letter carries `invitation_paragraph(candidate, **paragraph_opts)`.
        """
        if not candidates:
            return InviteResult(ok=False, message=f"No reviewer found for {label!r}.")
        if len(candidates) > 1:
            hists = [
                self.reviewer_history_analysis({
                    "person_details_popup": c.get("person_details_popup", ""),
                    "person_id": c.get("person_id", ""),
                })
                for c in candidates
            ]
            with_orcid = [(c, h) for c, h in zip(candidates, hists) if h.get("orcid")]
            if len(with_orcid) == 1:
                print(f"    [auto-select] {with_orcid[0][0]['name']} — only candidate with an ORCID.")
                candidates = [with_orcid[0][0]]
            else:
                lines = [f"Multiple matches for {label!r} — be more specific:"]
                for c, hist in zip(candidates, hists):
                    email_str = f"  {hist['email']}" if hist.get("email") else ""
                    lines.append(f"  {c['name']}  ({c['institution'][:50]}){email_str}")
                    parts = []
                    for key, label_str in (
                        ("average_turnaround_time", "turnaround"),
                        ("average_r_score",         "R-score"),
                        ("completed_past_12m",      "done12m"),
                        ("open_invitations",        "open"),
                        ("last_invitation_date",    "last"),
                        ("orcid",                   "ORCID"),
                    ):
                        val = hist.get(key, "")
                        if val and val != "N/A":
                            parts.append(f"{label_str}: {val}")
                    if parts:
                        lines.append(f"    {' · '.join(parts)}")
                msg = "\n".join(lines)
                return InviteResult(ok=False, ambiguous=True,
                                    candidates=candidates, candidate_details=hists, message=msg)

        person_id, xik = candidates[0]["person_id"], candidates[0]["xik"]
        chosen_name = candidates[0].get("name", label)
        chosen_email = label if "@" in label else candidates[0].get("email", "")
        paragraph = self.invitation_paragraph(candidates[0], **paragraph_opts)
        try:
            invite_info = self.invite_reviewer(person_id, xik, paragraph)
        except Exception as exc:
            self.log_action("invite_reviewer", ms_id=ms_id, ok=False, reviewer=chosen_name,
                            email=chosen_email, person_id=person_id, error=str(exc))
            raise
        self.log_action("invite_reviewer", ms_id=ms_id, reviewer=invite_info["name"],
                        email=chosen_email, person_id=person_id, query=label,
                        paragraph=paragraph)

        if not self.navigate_to_reviewer_tab(ms_id):
            msg = f"Added {invite_info['name']}, but could not re-open {ms_id} to verify."
            return InviteResult(ok=True, name=invite_info["name"], message=msg)

        selected = self._find_selected_reviewer(invite_info["name"])
        if not selected:
            msg = f"Added {invite_info['name']}, but could not verify the final status."
            return InviteResult(ok=True, name=invite_info["name"], message=msg)

        status = selected["status"] or "Selected"
        if not status.lower().startswith("invited"):
            # "Selected" right after adding is either a stale read (the mail
            # went out) or a row whose invitation was never sent; the
            # idempotent send_pending_invitation() refreshes and tells which.
            status = self.send_pending_invitation(selected["name"], paragraph) or status
        ok = status.lower().startswith("invited")
        msg = (f"Done — {selected['name']} is now {status}." if ok else
               f"{selected['name']} is {status}: no invitation was mailed.")
        return InviteResult(ok=ok, name=selected["name"], status=status, message=msg)

    def invite_by_email(self, ms_id: str, email: str, **paragraph_opts: Any) -> InviteResult:
        """Full flow: navigate to manuscript, search by email, invite if exactly 1 match.

        `paragraph_opts` go to `invitation_paragraph`.
        """
        if not self.navigate_to_reviewer_tab(ms_id):
            return InviteResult(ok=False, message=f"Could not navigate to {ms_id}.")
        candidates = self.search_reviewer_by_email(email)
        return self._invite_one(ms_id, candidates, email, **paragraph_opts)

    def invite_by_name(self, ms_id: str, name: str, **paragraph_opts: Any) -> InviteResult:
        """Full flow: navigate to manuscript, search by name, invite if exactly 1 match."""
        if not self.navigate_to_reviewer_tab(ms_id):
            return InviteResult(ok=False, message=f"Could not navigate to {ms_id}.")
        candidates = self.search_reviewer_by_name(name)
        return self._invite_one(ms_id, candidates, name, **paragraph_opts)

    def title_for_manuscript(self, ms_id: str) -> str:
        """
        Look up the title for ms_id by scanning dashboard queue pages.
        Falls back to parsing the current page if the queues don't list it.
        """
        link_map, source_url = self._get_dashboard_link_map()
        all_queues = (
            "Select Reviewers", "Invite Reviewers", "Assign Reviewers",
            "Reviewer Scoring", "Overdue Reviewer Response", "Overdue Reviewer Scores",
            "Manuscripts Awaiting Revision", "Manuscripts with Decisions",
        )
        for queue_key in all_queues:
            href = link_map.get(queue_key)
            if not href:
                continue
            try:
                for paper in self._fetch_queue_papers(href, source_url):
                    if paper["ms_id"] == ms_id:
                        return paper["title"]
            except Exception as exc:
                self._debug(f"title_for_manuscript: skipping {queue_key!r}: {exc}")
        return ""

    @staticmethod
    def _popup_url_from_js(value: str) -> str:
        match = re.search(r"(?:popWindow|window\.open)\('([^']+)'", value)
        return match.group(1) if match else ""

    @staticmethod
    def _html_to_text(html: str) -> str:
        soup = BeautifulSoup(html, "html.parser")
        for tag in soup(["script", "style", "noscript", "head"]):
            tag.decompose()
        ScholarOneSession._deobfuscate_emails(soup)
        return "\n".join(
            line.strip()
            for line in soup.get_text("\n").splitlines()
            if line.strip()
        )

    @staticmethod
    def _deobfuscate_emails(soup) -> None:
        """Restore addresses that Cloudflare's email protection hid, in place.

        MC is fronted by Cloudflare, which rewrites every mailto into
        ``<a class="__cf_email__" data-cfemail="HEX">[email&nbsp;protected]</a>``
        — so reviewer addresses read as "[email protected]" in the text of any
        page unless the hex is decoded: first byte is the XOR key, the rest is
        the address.
        """
        for tag in soup.select("a.__cf_email__, span.__cf_email__, [data-cfemail]"):
            hexed = tag.get("data-cfemail", "")
            try:
                data = bytes.fromhex(hexed)
                key = data[0]
                tag.replace_with("".join(chr(b ^ key) for b in data[1:]))
            except (ValueError, IndexError):
                continue

    def current_manuscript_metadata(self) -> dict[str, str]:
        """Parse title, authors, abstract, and keywords from the details page.

        Returns a dict with keys: ms_id, title, authors, abstract, keywords.
        Values are empty strings for fields not found on the page.
        Must be called after navigating to a manuscript (navigate_to_reviewer_tab
        or navigate_to_any_manuscript).
        """
        soup = self._soup()
        result: dict[str, str] = {
            "ms_id": "", "title": "", "authors": "", "abstract": "", "keywords": "",
        }

        # MS number: the first manuscript id on the page
        text_blob = soup.get_text(" ")
        ms_m = re.search(rf"\b({self.ms_id_pattern})\b", text_blob)
        if ms_m:
            result["ms_id"] = ms_m.group(1)

        # ManuscriptCentral reviewer-tab page: metadata appears as a sequence of
        # <p class="pagecontents"> elements: title, authors, manuscript type, AE/EIC line.
        # Abstract and keywords are in a later tab (not present on this page), so we
        # fall back to a two-column table scan for those.
        pagecontents = [
            re.sub(r"\s+", " ", p.get_text(" ", strip=True))
            for p in soup.find_all("p", class_="pagecontents")
            if p.get_text(strip=True)
        ]
        for pc in pagecontents:
            # Skip the session-timeout warning banner
            if "session will time out" in pc.lower():
                continue
            # Skip the internal MS-ID / token line (starts with the manuscript id)
            if re.match(self.ms_id_pattern, pc):
                continue
            if not result["title"]:
                result["title"] = pc
                continue
            if not result["authors"]:
                result["authors"] = pc
                break

        # Abstract tab: MC renders it in a popup window linked from the manuscript page.
        if not result["abstract"]:
            for a in soup.find_all("a"):
                if a.get_text(strip=True) == "Abstract":
                    m = re.search(r"popWindow\('([^']+)'", a.get("href", ""))
                    if m:
                        try:
                            resp = self.session.get(
                                "https://mc.manuscriptcentral.com/" + m.group(1)
                            )
                            ps = BeautifulSoup(resp.text, "html.parser")
                            for p in ps.find_all("p"):
                                t = re.sub(r"\s+", " ", p.get_text(" ", strip=True))
                                if t.lower().startswith("abstract:"):
                                    result["abstract"] = t[len("abstract:"):].strip()
                                    break
                        except Exception as exc:
                            self._debug(f"abstract popup fetch error: {exc}")
                    break

        # Fallback: two-column table scan for abstract / keywords (detail tab)
        label_map = {
            "title":    {"title", "manuscript title", "paper title", "article title"},
            "authors":  {"authors", "author", "author(s)"},
            "abstract": {"abstract"},
            "keywords": {"keywords", "key words"},
        }
        for row in soup.find_all("tr"):
            cells = row.find_all("td", recursive=False)
            if len(cells) < 2:
                continue
            label_text = cells[0].get_text(" ", strip=True).lower().rstrip(": ")
            for key, aliases in label_map.items():
                if result[key]:
                    continue
                if label_text in aliases:
                    value = re.sub(r"\s+", " ", cells[1].get_text(" ", strip=True)).strip()
                    if value:
                        result[key] = value
                    break

        return result

    def current_manuscript_pdf_url(self) -> str:
        """Return the direct DOWNLOAD=TRUE URL for the current manuscript proof."""
        soup = self._soup()
        proof_popup = ""
        for link in soup.find_all("a"):
            attrs = " ".join(str(value) for value in link.attrs.values())
            if "pdf_proof" not in attrs and "PDF Proof" not in attrs:
                continue
            proof_popup = self._popup_url_from_js(
                link.get("onclick", "") or link.get("onClick", "")
            )
            if proof_popup:
                break
        if not proof_popup:
            return ""

        popup_url = proof_popup if proof_popup.startswith("http") else f"{BASE_URL}/{proof_popup.lstrip('/')}"
        r = self.session.get(popup_url, headers={"Referer": self.current_url}, timeout=120)
        r.raise_for_status()

        match = re.search(r'location\.href\s*=\s*"([^"]*DOWNLOAD=TRUE[^"]*)"', r.text)
        if not match:
            return popup_url
        download_url = match.group(1)
        return download_url if download_url.startswith("http") else f"{BASE_URL}/{download_url.lstrip('/')}"

    def download_current_manuscript_pdf(self) -> bytes:
        """Download the current manuscript proof PDF bytes."""
        pdf_url = self.current_manuscript_pdf_url()
        if not pdf_url:
            return b""
        r = self.session.get(pdf_url, headers={"Referer": self.current_url}, timeout=180)
        r.raise_for_status()
        return r.content

    @staticmethod
    def _is_view_review_link(link) -> bool:
        """True for a "view review" control, whether it is text or an icon.

        Some manuscript pages render the control as the words "view review",
        others as a bare ``view_review.gif`` button with no text at all — and a
        text-only match silently reports "no completed reviews" on the latter.
        """
        if link.get_text(strip=True).lower() == "view review":
            return True
        for img in link.find_all("img"):
            haystack = f"{img.get('src', '')} {img.get('alt', '')} {img.get('title', '')}"
            if "view_review" in haystack.lower():
                return True
        return False

    def current_review_links(self) -> list[dict[str, str]]:
        """Return per-reviewer 'view review' popup links from the current page.

        Each dict has keys: reviewer, popup_url.  Reviewer names are matched to
        their link by walking back through the sibling table rows of the
        manuscript Reviews section.
        """
        soup = self._soup()
        results: list[dict[str, str]] = []
        for link in soup.find_all("a", href=True):
            if not self._is_view_review_link(link):
                continue
            popup = self._popup_url_from_js(link.get("href", ""))
            if not popup:
                continue
            reviewer = ""
            row = link.find_parent("tr")
            # The reviewer's own row first: walking straight back to the
            # previous rows picks up whichever reviewer happens to sit above,
            # which mis-attributes every review on a multi-reviewer page.
            if row is not None:
                own = row.find("a", href=re.compile(r"mailpopup"))
                if own:
                    reviewer = own.get_text(strip=True)
            while not reviewer and row is not None:
                row = row.find_previous_sibling("tr")
                if row is None:
                    break
                name_link = row.find("a", href=re.compile(r"mailpopup"))
                if name_link:
                    reviewer = name_link.get_text(strip=True)
                    break
            popup_url = popup if popup.startswith("http") else f"{BASE_URL}/{popup.lstrip('/')}"
            results.append({"reviewer": reviewer, "popup_url": popup_url})
        return results

    @staticmethod
    def _parse_review_popup(html: str) -> dict[str, object]:
        """Parse a review-popup page into a structured dict.

        Extracts reviewer name/affiliation, manuscript metadata, the completed
        score-sheet answers, the recommendation, and the confidential/public
        comment texts.
        """
        soup = BeautifulSoup(html, "html.parser")
        for tag in soup(["script", "style", "noscript", "head"]):
            tag.decompose()

        paras = soup.find_all("p")
        texts = [re.sub(r"\s+", " ", p.get_text(" ", strip=True)) for p in paras]

        def after(label: str) -> str:
            for i, t in enumerate(texts):
                if t == label:
                    for nxt in texts[i + 1:]:
                        if nxt:
                            return nxt
            return ""

        out: dict[str, object] = {}
        m = re.search(r"Reviewer\s+(\d+):\s*(.+)", soup.get_text(" "))
        if m:
            out["reviewer_number"] = m.group(1)
            out["reviewer"] = re.sub(r"\s+", " ", m.group(2)).strip()
        out["affiliation"] = after("Reviewer Affiliation")
        out["ms_id"] = after("Manuscript ID:")
        out["title"] = after("Manuscript Title:")
        out["date_submitted"] = after("Date Submitted:")
        out["date_assigned"] = after("Date Assigned:")
        out["date_review_returned"] = after("Date Review Returned:")

        authors: list[str] = []
        for i, para in enumerate(paras):
            if texts[i] == "Authors:":
                for j, nxt in enumerate(texts[i + 1:], start=i + 1):
                    if not nxt or "Review Form" in nxt:
                        break
                    if paras[j].get("id", "").startswith("ANCHOR_CUSTOM_FIELD"):
                        break
                    authors.append(nxt)
                break
        out["authors"] = authors

        # Score-sheet Q&A: question rows carry a REQUIRED_CUSTOM_FIELD input;
        # answers are the non-empty ANCHOR_CUSTOM_FIELD paragraphs that follow.
        order = {el: i for i, el in enumerate(soup.descendants)}
        questions: list[tuple[int, str]] = []
        for inp in soup.find_all("input", {"name": "REQUIRED_CUSTOM_FIELD"}):
            node = inp.find_parent("tr") or inp.find_parent("p")
            if node is None:
                continue
            questions.append((order.get(inp, 0),
                              re.sub(r"\s+", " ", node.get_text(" ", strip=True))))
        questions.sort()
        answers: list[tuple[int, str]] = []
        for p in soup.find_all("p", id=re.compile(r"^ANCHOR_CUSTOM_FIELD")):
            t = re.sub(r"\s+", " ", p.get_text(" ", strip=True))
            if t:
                answers.append((order.get(p, 0), t))
        answers.sort()

        scores: list[dict[str, str]] = []
        for qi, (qpos, qtext) in enumerate(questions):
            qend = questions[qi + 1][0] if qi + 1 < len(questions) else float("inf")
            vals = list(dict.fromkeys(t for apos, t in answers if qpos < apos < qend))
            scores.append({"question": qtext, "answer": vals[0] if len(vals) == 1 else ""})
        out["scores"] = scores

        # Recommendation: marked in the popup with a check-mark icon row
        recommendation = ""
        for img in soup.find_all("img", src=re.compile(r"check_mark")):
            row = img.find_parent("tr")
            if row:
                t = re.sub(r"\s+", " ", row.get_text(" ", strip=True))
                if t and t != "Yes":
                    recommendation = t
                    break
        out["recommendation"] = recommendation

        def comment_after(header: str) -> str:
            for i, t in enumerate(texts):
                if t.startswith(header):
                    for nxt in texts[i + 1:]:
                        if not nxt or nxt.startswith("Please give detailed justifications"):
                            continue
                        if nxt.startswith(("Public Comments", "Reviewer opted", "Timeliness")):
                            break
                        return nxt
            return ""

        out["confidential_comments"] = comment_after("Confidential Comments (")
        out["public_comments"] = comment_after("Public Comments (")
        return out

    def current_reviews(self) -> list[dict[str, object]]:
        """Return all completed reviews of the current manuscript.

        Fetches each reviewer's score-sheet popup concurrently (up to 4
        threads) and returns parsed dicts (see _parse_review_popup).
        """
        from concurrent.futures import ThreadPoolExecutor, as_completed

        links = self.current_review_links()
        if not links:
            return []

        referer = self.current_url

        def fetch(item: dict[str, str]) -> dict[str, object]:
            r = self.session.get(item["popup_url"], headers={"Referer": referer}, timeout=120)
            r.raise_for_status()
            parsed = self._parse_review_popup(r.text)
            parsed.setdefault("reviewer", item["reviewer"])
            return parsed

        results: dict[int, dict[str, object]] = {}
        with ThreadPoolExecutor(max_workers=min(4, len(links))) as pool:
            futures = {pool.submit(fetch, item): idx for idx, item in enumerate(links)}
            for fut in as_completed(futures):
                results[futures[fut]] = fut.result()

        return [results[i] for i in range(len(links))]

    @staticmethod
    def _format_review_text(review: dict[str, object]) -> str:
        """Render one parsed review as plain text for the combined txt file.

        Anonymous by design: reviewer identity and metadata are omitted.  Of
        the score sheet only the verdict is kept — recommendation, overall
        rating, technical soundness — then the free-text comments.
        """
        def g(key: str) -> str:
            return str(review.get(key, "") or "")

        lines: list[str] = []

        verdict = [f"Recommendation: {g('recommendation')}"] if g("recommendation") else []
        for prefix, label in (("Please rate the manuscript", "Rating"),
                              ("Is the manuscript technically sound", "Technically sound")):
            for score in review.get("scores") or []:   # type: ignore[union-attr,attr-defined]
                if str(score.get("question", "")).startswith(prefix) and score.get("answer"):
                    verdict.append(f"{label}: {score['answer']}")
        if verdict:
            lines.append("── " + " · ".join(verdict) + " ──")
            lines.append("")

        for label, key in (
            ("Confidential comments (authors will not see these)",
             "confidential_comments"),
            ("Public comments (made available to the author)",
             "public_comments"),
        ):
            text = g(key)
            if text:
                lines.append(f"── {label} ──")
                lines.append(textwrap.fill(text, width=100))
                lines.append("")
        return "\n".join(lines).rstrip()

    def download_reviews_txt(
        self,
        ms_id: str = "",
        out_path: str = "",
    ) -> str:
        """Download all reviews of a manuscript into a single local txt file.

        Navigates to the manuscript (any accessible queue), fetches every
        completed reviewer score-sheet popup, and writes one combined txt
        file.  Returns the written path, or "" when no reviews are available.
        """
        if ms_id and not self.navigate_to_any_manuscript(ms_id):
            print(f"[reviews] could not navigate to {ms_id}")
            return ""

        reviews = self.current_reviews()
        if not reviews:
            print(f"[reviews] no completed reviews found"
                  f"{' for ' + ms_id if ms_id else ''}")
            return ""

        meta = self.current_manuscript_metadata()
        ms_label = meta.get("ms_id") or ms_id
        if not out_path:
            out_path = f"{re.sub(r'[^A-Za-z0-9._-]+', '_', ms_label or 'manuscript')}_reviews.txt"

        parts: list[str] = [
            f"# Reviews for {ms_label}",
            f"# Title: {meta.get('title', '')}",
            f"# Authors: {meta.get('authors', '')}",
            f"# Reviews: {len(reviews)}",
            "",
        ]
        for i, review in enumerate(reviews, start=1):
            if i > 1:
                parts.append("")
                parts.append("█" * 100)
                parts.append("")
            parts.append(self._format_review_text(review))

        with open(out_path, "w", encoding="utf-8") as fp:
            fp.write("\n".join(parts).rstrip() + "\n")
        print(f"[reviews] {len(reviews)} review(s) saved → {out_path}")
        self.log_action("download_reviews", ms_id=ms_label, path=out_path, reviews=len(reviews))
        return out_path

    def current_decision_letters(self) -> list[dict[str, str]]:
        """Return decision-letter popup text from the current manuscript page.

        Popups are fetched concurrently (up to 4 threads) to reduce latency
        on papers with multiple review rounds.
        """
        from concurrent.futures import ThreadPoolExecutor, as_completed

        soup = self._soup()
        pending: list[tuple[str, str]] = []   # (label, popup_url), deduped
        seen: set[str] = set()
        for link in soup.find_all("a", href=True):
            label = link.get_text(" ", strip=True)
            if "view decision letter" not in label.lower():
                continue
            popup = self._popup_url_from_js(link.get("href", ""))
            if not popup or popup in seen:
                continue
            seen.add(popup)
            popup_url = popup if popup.startswith("http") else f"{BASE_URL}/{popup.lstrip('/')}"
            pending.append((label, popup_url))

        if not pending:
            return []

        referer = self.current_url

        def fetch(item: tuple[str, str]) -> dict[str, str]:
            label, popup_url = item
            r = self.session.get(popup_url, headers={"Referer": referer}, timeout=120)
            r.raise_for_status()
            return {"label": label, "url": popup_url, "text": self._html_to_text(r.text)}

        # Preserve page order while fetching in parallel.
        results: dict[int, dict[str, str]] = {}
        with ThreadPoolExecutor(max_workers=min(4, len(pending))) as pool:
            futures = {pool.submit(fetch, item): idx for idx, item in enumerate(pending)}
            for fut in as_completed(futures):
                results[futures[fut]] = fut.result()

        return [results[i] for i in range(len(pending))]

    def show_tables(self) -> str:
        """Return a plain-text rendering of data tables."""
        soup = self._soup()
        out = []
        for i, table in enumerate(soup.find_all("table")):
            rows = table.find_all("tr")
            if not rows:
                continue
            grid: list[list[str]] = []
            for row in rows:
                cells = [
                    c.get_text(" ", strip=True)
                    for c in row.find_all(["td", "th"])
                ]
                if any(cells):
                    grid.append(cells)
            if not grid:
                continue
            col_w = [
                max(len(r[c]) if c < len(r) else 0 for r in grid)
                for c in range(max(len(r) for r in grid))
            ]
            out.append(f"── Table {i} ──")
            for row in grid:
                parts = [
                    (row[c] if c < len(row) else "").ljust(col_w[c])
                    for c in range(len(col_w))
                ]
                out.append("  " + "  │  ".join(parts))
            out.append("")
        return "\n".join(out) if out else "(no tables on this page)"


# ── REPL ─────────────────────────────────────────────────────────────────────

HELP = """\
Commands
────────
editor                       show all papers currently assigned to you as AE
select                       pick a paper by number and open its reviewer details
invitees                     show reviewers you've invited, sorted by turnaround
reviewers [ms_id]            show invited reviewers + candidates for a manuscript
invite <ms_id> <email|name>  search by email or "First Last" and send invitation
abstract <ms_id>             show abstract for any accessible manuscript
download <ms_id>             download proof PDF for any accessible manuscript
reviews <ms_id>              download all reviews of a manuscript to one txt file
log [n|ms_id]                show the last n logged state-changing actions
login                        (re)authenticate
quit / exit / q              exit
help / ?                     show this help
"""


def prompt(mc: ScholarOneSession) -> str:
    title = mc.page_title()[:60]
    return input(f"\n[{title}]\n> ").strip()


def show_reviewer_snapshot(mc: ScholarOneSession) -> list[dict]:
    selected_rows = mc.selected_reviewer_rows()
    selected = [
        (row["name"], row["status"], row["history"])
        for row in selected_rows
    ]
    candidates = mc.parse_reviewer_candidates()
    if selected:
        print(f"┌─ Invited Reviewers ({len(selected)}) {'─'*54}")
        for name, status, history in selected:
            status_clean = re.sub(r"\s+", " ", status)[:30]
            print(f"│  {name:<30}  {status_clean:<30}  {history[:30]}")
        print("└" + "─" * 79)
        history_rows = []
        for row in selected_rows:
            hist = mc.reviewer_history_analysis(row)
            if not hist:
                continue
            history_rows.append((
                row["name"],
                hist.get("average_turnaround_time", "-"),
                hist.get("open_invitations", "-"),
                hist.get("completed_past_12m", "-"),
                hist.get("last_invitation_date", "-"),
                hist.get("average_r_score", "-"),
            ))
        if history_rows:
            print("Reviewer history (ScholarOne):")
            print(f"┌─ Historical Reviewer Metrics ({len(history_rows)}) {'─'*44}")
            for name, turnaround, open_inv, completed_12m, last_invite, r_score in history_rows:
                print(
                    "│  "
                    f"{name:<24}  "
                    f"turnaround {turnaround:<14}  "
                    f"open {open_inv:<3}  "
                    f"done12m {completed_12m:<3}  "
                    f"last {last_invite:<11}  "
                    f"R {r_score:<6}"
                )
            print("└" + "─" * 79)
    if candidates:
        print(f"┌─ Candidates ({len(candidates)}) {'─'*62}")
        for i, c in enumerate(candidates):
            print(f"│  [{i:2d}]  {c['name']:<30}  {c['institution'][:40]}")
        print("└" + "─" * 79)
        print("  Use: invite <n>  to send an invitation")
    elif not selected:
        print("No reviewer data found. Navigate to a manuscript first.")
    return candidates


def run_repl(mc: ScholarOneSession,
             commands: dict[str, Callable[[ScholarOneSession, str], None]] | None = None,
             help_text: str = HELP) -> None:
    """Interactive loop. `commands` adds or overrides commands: name → fn(mc, arg)."""
    commands = commands or {}
    links: list[tuple[int, str, str]] = []

    while True:
        try:
            raw = prompt(mc)
        except (EOFError, KeyboardInterrupt):
            print("\nBye.")
            break

        if not raw:
            continue
        parts = raw.split(None, 1)
        cmd = parts[0].lower()
        arg = parts[1] if len(parts) > 1 else ""

        if cmd in commands:
            try:
                commands[cmd](mc, arg)
            except Exception as exc:
                print(f"Error: {exc}")
            continue

        if cmd in ("quit", "exit", "q"):
            print("Bye.")
            break

        elif cmd in ("help", "?"):
            print(help_text)

        elif cmd == "editor":
            print("Fetching AE dashboard …")
            print(mc.ae_dashboard())

        elif cmd == "select":
            print("Fetching selectable papers …")
            papers = mc.reviewer_dashboard_papers()
            if not papers:
                print("No reviewer-manageable papers found.")
                continue
            print(f"┌─ Reviewer Papers ({len(papers)}) {'─'*58}")
            for i, paper in enumerate(papers, start=1):
                counts = f"  [{paper['counts']}]" if paper["counts"] else ""
                title = paper["title"][:34]
                print(
                    f"│  [{i:2d}]  {paper['ms_id']:<18}  {paper['date']:<12}  "
                    f"{title:<34}  {paper['queue']}{counts}"
                )
            print("└" + "─" * 79)
            choice = input("Paper number (blank to cancel): ").strip()
            if not choice:
                print("Cancelled.")
                continue
            if not choice.isdigit():
                print("Please enter a paper number.")
                continue
            index = int(choice)
            if index < 1 or index > len(papers):
                print(f"Paper number out of range (1-{len(papers)}).")
                continue
            paper = papers[index - 1]
            print(f"Opening {paper['ms_id']} …")
            if not mc.navigate_to_reviewer_tab(paper["ms_id"], nav=paper["nav"]):
                print(f"Could not open {paper['ms_id']}.")
                continue
            print(f"{paper['ms_id']}  {paper['title']}")
            print(f"Queue: {paper['queue']}  Date: {paper['date']}")
            show_reviewer_snapshot(mc)

        elif cmd == "invitees":
            print("Collecting invited reviewers …")
            rows = mc.invited_reviewers_overview()
            if not rows:
                print("No invited reviewers found on the accessible papers.")
                continue
            print(f"┌─ Invited Reviewers Across Papers ({len(rows)}) {'─'*39}")
            for row in rows:
                papers = ",".join(sorted(row["papers"]))
                if len(papers) > 24:
                    papers = papers[:23] + "…"
                print(
                    "│  "
                    f"{row['name']:<24}  "
                    f"{str(row['average_turnaround_time']):<17}  "
                    f"papers {len(row['papers']):<2}  "
                    f"open {row['open_invitations']:<3}  "
                    f"done12m {row['completed_past_12m']:<3}  "
                    f"{papers}"
                )
            print("└" + "─" * 79)

        elif cmd == "reviewers":
            if arg:
                print(f"Navigating to {arg} …")
                if not mc.navigate_to_reviewer_tab(arg):
                    print(f"Could not find {arg}. Try `editor` first to reach the dashboard.")
                    continue
            show_reviewer_snapshot(mc)

        elif cmd in ("ls", "links"):
            links = mc.list_links()
            if not links:
                print("(no navigable links found)")
            else:
                for idx, label, href in links:
                    short_href = href[:70] + ("…" if len(href) > 70 else "")
                    print(f"  [{idx:3d}]  {label[:40]:<40}  {short_href}")

        elif cmd == "go":
            if not arg:
                print("Usage: go <n>  or  go <url>")
                continue
            if arg.isdigit():
                n = int(arg)
                if not links:
                    links = mc.list_links()
                if n >= len(links):
                    print(f"Index {n} out of range (0–{len(links)-1})")
                    continue
                _, label, href = links[n]
                print(f"→ {label}  ({href[:80]})")
                # strip leading javascript: wrappers like popWindow('url')
                m = re.search(r"'([^']*PARAMS=[^']*)'", href)
                if m:
                    href = m.group(1)
                mc.goto_url(href)
                links = mc.list_links()
            else:
                mc.goto_url(arg)
                links = mc.list_links()

        elif cmd == "back":
            mc.back()
            links = mc.list_links()

        elif cmd == "text":
            limit = 0 if arg == "all" else 60
            print(mc.page_text(max_lines=limit or 99999))

        elif cmd == "tables":
            print(mc.show_tables())

        elif cmd == "form":
            fields = mc.show_form_fields()
            if not fields:
                print("(no form found)")
            else:
                for ftype, name, value in fields:
                    val_disp = (value[:60] + "…") if len(value) > 60 else value
                    print(f"  {ftype:10}  {name:<40}  {val_disp}")

        elif cmd == "url":
            print(mc.current_url)

        elif cmd == "title":
            print(mc.page_title())

        elif cmd == "abstract":
            if not arg:
                print("Usage: abstract <ms_id>")
                continue
            if not mc.navigate_to_any_manuscript(arg):
                print(f"Could not navigate to {arg}.")
                continue
            meta = mc.current_manuscript_metadata()
            abstract = meta.get("abstract", "")
            if not abstract:
                print("No abstract found.")
            else:
                print(abstract)

        elif cmd == "invite":
            parts2 = arg.split(None, 1)
            if len(parts2) != 2:
                print("Usage: invite <ms_id> <email|name>")
                continue
            ms_id_arg, identifier = parts2
            identifier = identifier.strip("\"'")
            print(f"Searching for {identifier!r} …")
            try:
                if "@" in identifier:
                    result = mc.invite_by_email(ms_id_arg, identifier)
                else:
                    result = mc.invite_by_name(ms_id_arg, identifier)
                if result.ambiguous:
                    print(f"Multiple matches for {identifier!r} — choose one:")
                    for i, (c, h) in enumerate(zip(result.candidates, result.candidate_details), 1):
                        email_str = f"  <{h['email']}>" if h.get("email") else ""
                        print(f"  {i}) {c['name']}  ({c.get('institution', '')[:50]}){email_str}")
                    choice = input("Choice (blank to cancel): ").strip()
                    if choice.isdigit() and 1 <= int(choice) <= len(result.candidates):
                        chosen = result.candidates[int(choice) - 1]
                        result = mc._invite_one(ms_id_arg, [chosen], chosen["name"])
                        print(result)
                    else:
                        print("Cancelled.")
                else:
                    print(result)
            except Exception as exc:
                print(f"Error: {exc}")

        elif cmd == "download":
            if not arg:
                print("Usage: download <ms_id>  (e.g. download ABC-2026-04-0342)")
                continue
            ms_id_arg = arg.strip()
            print(f"Searching for {ms_id_arg} in all accessible queues …")
            if not mc.navigate_to_any_manuscript(ms_id_arg):
                print(f"Not found: {ms_id_arg} is not accessible from any queue.")
                continue
            print(f"Navigated to {ms_id_arg}.  Downloading PDF …")
            pdf_bytes = mc.download_current_manuscript_pdf()
            if pdf_bytes.startswith(b"%PDF"):
                out_path = f"{ms_id_arg}_proof.pdf"
                with open(out_path, "wb") as fp:
                    fp.write(pdf_bytes)
                print(f"Saved {len(pdf_bytes)//1024} KB → {out_path}")
                mc.log_action("download_pdf", ms_id=ms_id_arg, path=out_path,
                              bytes=len(pdf_bytes))
            else:
                print("No PDF proof found on this page.")

        elif cmd == "reviews":
            if not arg:
                print("Usage: reviews <ms_id>  (e.g. reviews ABC-2026-06-0614)")
                continue
            ms_id_arg = arg.strip()
            print(f"Searching for {ms_id_arg} in all accessible queues …")
            mc.download_reviews_txt(ms_id_arg)

        elif cmd == "log":
            limit = int(arg) if arg.strip().isdigit() else 20
            ms_filter = "" if arg.strip().isdigit() else arg.strip()
            rows = mc.worklog.entries(ms_id=ms_filter, limit=limit)
            if not rows:
                print("(no actions logged yet)")
                continue
            for row in rows:
                extra = " ".join(
                    f"{k}={v}" for k, v in row.items()
                    if k not in ("ts", "action", "ok", "ms_id", "journal")
                )
                flag = "" if row.get("ok", True) else " ✗"
                print(f"  {row['ts']}  {row['action']:<18}{flag}  "
                      f"{row.get('ms_id', ''):<20}  {extra[:60]}")

        elif cmd == "login":
            email = input("Email: ").strip()
            password = input("Password: ").strip()
            mc.login(email, password)
            links = mc.list_links()

        else:
            print(f"Unknown command '{cmd}'. Type 'help' for usage.")


# ── entry point ───────────────────────────────────────────────────────────────


def load_credentials(path: str = "credentials.json") -> dict:
    import json as _json
    try:
        with open(path) as f:
            return _json.load(f)
    except FileNotFoundError:
        return {}


def main(session_cls: type[ScholarOneSession] = ScholarOneSession,
         commands: dict[str, Callable[[ScholarOneSession, str], None]] | None = None,
         help_text: str = HELP) -> None:
    """Console entry point: log in from credentials.json (or prompts), then the REPL."""
    import argparse
    argparse.ArgumentParser(
        description="Interactive ScholarOne / ManuscriptCentral session for editors. "
                    "Reads credentials.json in the current directory; MC_JOURNAL, MC_EMAIL, "
                    "MC_PASSWORD override it.",
        epilog=help_text, formatter_class=argparse.RawDescriptionHelpFormatter,
    ).parse_args()
    creds_path = "credentials.json"
    creds      = load_credentials(creds_path)
    journal    = os.environ.get("MC_JOURNAL",  creds.get("journal") or session_cls.default_journal)
    email      = os.environ.get("MC_EMAIL",    creds.get("email",    ""))
    password   = os.environ.get("MC_PASSWORD", creds.get("password", ""))
    cookies    = creds.get("cookies", {})

    mc = session_cls(journal=journal or None)
    print(help_text)

    if not email:
        email = input("ManuscriptCentral email: ").strip()
    if not password:
        import getpass
        password = getpass.getpass("Password: ")

    # Pass only the non-session cookies as device-recognition hints.
    device_cookies = {k: v for k, v in cookies.items()
                      if k not in ScholarOneSession._SESSION_COOKIES}

    try:
        mc.login(email, password, device_cookies=device_cookies, credentials_path=creds_path)
    except Exception as exc:
        print(f"Login failed: {exc}", file=sys.stderr)
        sys.exit(1)

    run_repl(mc, commands, help_text)


if __name__ == "__main__":
    main()
