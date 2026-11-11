"""The hooks a subclass overrides to plug in local infrastructure."""
from __future__ import annotations

import json
import os

import pytest

from agentic_scholarone import ScholarOneSession


@pytest.fixture(autouse=True)
def _isolated_state(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(ScholarOneSession, "state_dir", str(tmp_path / "state"))
    for var in ("MC_JOURNAL", "MC_PASSWORD", "MC_2FA_CODE", "MC_2FA_CODE_FILE"):
        monkeypatch.delenv(var, raising=False)


def test_journal_is_required(monkeypatch) -> None:
    with pytest.raises(ValueError, match="No journal"):
        ScholarOneSession()
    monkeypatch.setenv("MC_JOURNAL", "env-cs")
    assert ScholarOneSession().journal == "env-cs"
    assert ScholarOneSession("arg-cs").journal_url.endswith("/arg-cs")


def test_subclass_defaults() -> None:
    class Mine(ScholarOneSession):
        default_journal = "mine-cs"
        ms_id_pattern = r"MINE-\d{4}[-.\w]*"

    mc = Mine()
    assert mc.journal == "mine-cs"
    page = "<table><tr><td>MINE-2026-01-0001</td><td>T</td><td>d</td><td>s</td></tr>" \
           "<tr><td>ABC-2026-01-0002</td><td>T</td><td>d</td><td>s</td></tr></table>"
    assert [p["ms_id"] for p in mc._parse_queue_papers(page)] == ["MINE-2026-01-0001"]


def test_action_log_goes_to_state_dir(tmp_path) -> None:
    mc = ScholarOneSession("abc-cs")
    mc.log_action("invite_sent", ms_id="ABC-2026-01-0001", name="Doe, Jane")
    log = tmp_path / "state" / "mc_actions.jsonl"
    row = json.loads(log.read_text())
    assert row["action"] == "invite_sent" and row["journal"] == "abc-cs"


def test_2fa_order(monkeypatch, tmp_path) -> None:
    calls: list[str] = []

    class Mine(ScholarOneSession):
        def two_factor_code_providers(self):
            return [lambda t: calls.append("empty") or "",
                    lambda t: calls.append("mail") or "123456"]

    mc = Mine("abc-cs")
    assert mc._read_2fa_code(timeout_s=1) == "123456"
    assert calls == ["empty", "mail"]

    monkeypatch.setenv("MC_2FA_CODE", "999999")
    calls.clear()
    assert mc._read_2fa_code(timeout_s=1) == "999999"
    assert calls == []          # the env code wins, providers are not touched

    monkeypatch.delenv("MC_2FA_CODE")
    code_file = tmp_path / "code.txt"
    code_file.write_text("424242\n")
    monkeypatch.setenv("MC_2FA_CODE_FILE", str(code_file))
    assert ScholarOneSession("abc-cs")._read_2fa_code(timeout_s=1) == "424242"


def test_password_resolution(monkeypatch) -> None:
    assert ScholarOneSession._resolve_password({"direct_password": "d", "password": "p"}) == "d"
    assert ScholarOneSession._resolve_password({"password": "p"}) == "p"
    monkeypatch.setenv("MC_PASSWORD", "env")
    assert ScholarOneSession._resolve_password({"password": "p"}) == "env"


def test_keyring_service_is_overridable(monkeypatch) -> None:
    import types
    import sys
    seen: list[tuple[str, str]] = []
    fake = types.SimpleNamespace(get_password=lambda s, n: seen.append((s, n)) or "kp")
    monkeypatch.setitem(sys.modules, "keyring", fake)

    class Mine(ScholarOneSession):
        keyring_service = "my-vault"

    assert Mine._resolve_password({"password_keyring": "mc"}) == "kp"
    assert Mine._resolve_password({"password_keyring": "other/mc"}) == "kp"
    assert seen == [("my-vault", "mc"), ("other", "mc")]


def test_invitation_paragraph_receives_invite_options(monkeypatch) -> None:
    got: dict = {}

    class Mine(ScholarOneSession):
        def invitation_paragraph(self, candidate, **opts):
            got.update(candidate=candidate["name"], **opts)
            return "PARA"

    mc = Mine("abc-cs")
    monkeypatch.setattr(mc, "invite_reviewer", lambda pid, xik, paragraph: (_ for _ in ()).throw(
        RuntimeError(f"stop:{paragraph}")))
    with pytest.raises(RuntimeError, match="stop:PARA"):
        mc._invite_one("ABC-2026-01-0001", [{"name": "Doe, Jane", "person_id": "1", "xik": "x"}],
                       "jane@example.org", profile="42")
    assert got == {"candidate": "Doe, Jane", "profile": "42"}
    assert ScholarOneSession("abc-cs").invitation_paragraph({"name": "x"}) == ""


def test_state_dir_default_is_not_the_package() -> None:
    import agentic_scholarone._session as s
    assert not s.STATE_DIR.startswith(os.path.dirname(s.__file__))
