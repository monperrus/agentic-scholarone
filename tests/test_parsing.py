"""Page parsers, on hand-written minimal HTML (never captured pages: they hold real names)."""
from __future__ import annotations

import re

import pytest

from agentic_scholarone import ScholarOneSession

QUEUE_PAGE = """
<html><body><form name="f">
<input type="hidden" name="NEXT_PAGE" value="ASSOCIATE_EDITOR_VIEW_MANUSCRIPTS">
<input type="hidden" name="XIK_TOKEN" value="xik_abc">
</form>
<table>
<tr><td>ABC-2026-04-0342</td><td>A Study of Things [ View Submission ]</td><td>04-Apr-2026</td>
    <td>3 active selections; 3 invited; 2 agreed; 5 declined; 1 returned
        <span class="pagecontents">Select Reviewers (Due 03-Oct-2026) 18 days overdue</span></td></tr>
<tr><td>ABC-2026-05-0447.R1</td><td>Another Paper</td><td>05-May-2026</td>
    <td><span class="pagecontents">Make Recommendation (Due 28-Oct-2026)</span></td></tr>
<tr><td>not an id</td><td>x</td><td>y</td><td>z</td></tr>
<tr><td>ABC-2026-04-0342</td><td>duplicate row</td><td>x</td><td>y</td></tr>
</table></body></html>
"""


@pytest.fixture
def mc(tmp_path, monkeypatch) -> ScholarOneSession:
    monkeypatch.setattr(ScholarOneSession, "state_dir", str(tmp_path))
    return ScholarOneSession(journal="abc-cs")


def test_queue_rows(mc: ScholarOneSession) -> None:
    papers = mc._parse_queue_papers(QUEUE_PAGE)
    assert [p["ms_id"] for p in papers] == ["ABC-2026-04-0342", "ABC-2026-05-0447.R1"]
    first, second = papers
    assert first["title"] == "A Study of Things"
    assert first["counts"] == "1 received / 1 waiting / 1 pending / 5 declined"
    assert first["stage"] == "Select Reviewers (due 03-Oct-2026, 18 days overdue)"
    assert second["counts"] == ""
    assert second["stage"] == "Make Recommendation (due 28-Oct-2026)"


@pytest.mark.parametrize("cell, expected", [
    ("3 invited; 3 agreed; 2 returned", "2 received / 1 waiting"),
    ("4 invited; 1 agreed; 0 returned; 2 declined", "0 received / 1 waiting / 3 pending / 2 declined"),
    ("no counts here", ""),
])
def test_reviewer_counts(cell: str, expected: str) -> None:
    assert ScholarOneSession._reviewer_counts(cell) == expected


def test_form_fields(mc: ScholarOneSession) -> None:
    form = mc._extract_form_data_from(QUEUE_PAGE)
    assert form["NEXT_PAGE"] == "ASSOCIATE_EDITOR_VIEW_MANUSCRIPTS"
    assert form["XIK_TOKEN"] == "xik_abc"
    assert mc._extract_form_data_from("<p>no form</p>") == {}


@pytest.mark.parametrize("text, match", [
    ("ABC-2026-04-0342", True),
    ("TOSEM-2025-0012.R2", True),
    ("abc-2026-04-0342", False),
    ("Select Reviewers", False),
])
def test_default_ms_id_pattern(text: str, match: bool) -> None:
    assert bool(re.fullmatch(ScholarOneSession.ms_id_pattern, text)) is match


def test_cloudflare_email_deobfuscation() -> None:
    # "a@b.c" XOR-encoded with key 0x42, as Cloudflare writes it
    hexed = "42" + "".join(f"{ord(ch) ^ 0x42:02x}" for ch in "a@b.c")
    html = f'<p>Contact <a class="__cf_email__" data-cfemail="{hexed}">[email protected]</a></p>'
    assert ScholarOneSession._html_to_text(html) == "Contact\na@b.c"


def test_popup_url_from_js() -> None:
    js = "javascript: popWindow('abc-cs?PARAMS=xik_123', 'w', 600, 400)"
    assert ScholarOneSession._popup_url_from_js(js) == "abc-cs?PARAMS=xik_123"
    assert ScholarOneSession._popup_url_from_js("javascript:void(0)") == ""


def test_insert_paragraph_after_opening() -> None:
    body = "Dear Dr. Doe:<br /><br />We invite you.<br /><br />Regards"
    out = ScholarOneSession._insert_paragraph(body, "EXTRA")
    assert out == "Dear Dr. Doe:<br /><br />We invite you.<br /><br />EXTRA<br /><br />Regards"
