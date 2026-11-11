# agentic-scholarone

Drive [ScholarOne Manuscripts](https://mc.manuscriptcentral.com) (ManuscriptCentral) as a journal
editor, without a browser. You can use it two ways:

* **as a library**, for coding agents and scripts: list your queues, read manuscripts, reviews and
  decision letters, search and screen reviewers, and send invitations;
* **as an interactive REPL**, for humans at the keyboard: `agentic-scholarone`.

ScholarOne has no public API for editors. This client speaks the web app's own protocol: form POSTs
that carry the page's hidden `XIK_*` tokens, plus `popWindow(...)` popups fetched with GETs. The
HTTP layer is [`curl_cffi`](https://github.com/lexiforest/curl_cffi) with a consistent Chrome
fingerprint, so the login's device check treats the client as an ordinary browser.

> ⚠️ ScholarOne is a live production system with real authors and reviewers on the other end.
> Reading needs no care. **Invitations are real emails**: have a human confirm every one.
> Reuse one session instead of logging in per call, because each fresh login can send a
> verification code to the editor's inbox.

## Install

```bash
pip install agentic-scholarone            # library + REPL
pip install "agentic-scholarone[keyring]" # + passwords from the OS secret store
```

Python ≥ 3.10.

## Credentials

A `credentials.json` in the working directory (keep it out of version control). The client also
saves session cookies into it, so later runs resume without logging in again:

```json
{
  "journal": "abc-cs",
  "email": "jane.doe@example.org",
  "auth_method": "clarivate",
  "password": "…"
}
```

* `journal`: the slug after `mc.manuscriptcentral.com/` in your journal's URL.
* `auth_method`: `"clarivate"` (default, Web of Science single sign-on) or `"direct"` (ScholarOne's
  own login form, with your ScholarOne user id in `email` and the native password in
  `direct_password`).
* Password lookup order: `MC_PASSWORD` env, then `password_keyring` (`"name"` or `"service/name"`,
  read live from the OS secret store, so the file holds no password), then `direct_password`, then
  `password`.

`MC_JOURNAL`, `MC_EMAIL`, `MC_PASSWORD`, `MC_AUTH` override the file.

**Two-factor codes.** When a login triggers the emailed device check, the code is taken from, in
order: `MC_2FA_CODE`, any provider you plug in (see below), the file named by `MC_2FA_CODE_FILE`
(polled for up to 15 min, so an agent can start the login and the code can be dropped in when the
mail arrives), then an interactive prompt.

## Use 1: library, for agents and scripts

```python
from agentic_scholarone import ScholarOneSession

mc = ScholarOneSession.from_credentials()      # resumes saved cookies, else logs in
print(mc.ae_dashboard())                       # papers needing reviewers, awaiting revision

# every queue you can see
link_map, src = mc._get_dashboard_link_map()
for queue in mc._ALL_QUEUE_KEYS:
    if href := link_map.get(queue):
        for p in mc.fetch_queue_papers_all_pages(href, src):
            print(queue, p["ms_id"], p["counts"], p["stage"], p["title"][:60])
```

`counts` reads `2 received / 1 waiting / 1 pending / 5 declined`. ScholarOne's own cell
(`3 invited; 2 agreed; 5 declined; 2 returned`) is cumulative, so the client turns it into
disjoint numbers. `stage` is the pending task, e.g. `Make Recommendation (due 28-Oct-2026)`.

The session is stateful. Navigate first, then read the page you are on.

```python
mc.navigate_to_any_manuscript("ABC-2026-04-0342")
meta = mc.current_manuscript_metadata()        # ms_id, title, authors, abstract, keywords
pdf = mc.download_current_manuscript_pdf()     # bytes
reviews = mc.current_reviews()                 # parsed score sheets
letters = mc.current_decision_letters()        # [{label, text}]
mc.download_reviews_txt("ABC-2026-04-0342")    # all reviews in one text file, headed by verdicts
```

Reviewers:

```python
mc.navigate_to_reviewer_tab("ABC-2026-04-0342")
for row in mc.selected_reviewer_rows():        # already selected or invited
    stats = mc.reviewer_history_analysis(row)
    print(row["name"], row["status"], stats.get("average_turnaround_time"))

for c in mc.search_reviewer_by_name("Jane Doe"):   # people usually have several accounts
    info = mc.person_account_info(c)                # email, affiliation, roles, keywords
    stats = mc.reviewer_history_analysis(c)         # agreed / declined / turnaround / ORCID
    print(info.get("email"), stats.get("times_agreed"), stats.get("last_invitation_date"))

# outward-facing: sends the invitation email
result = mc.invite_by_email("ABC-2026-04-0342", "jane.doe@example.org")
print(result.ok, result.status, result.message)  # result.ambiguous lists several matches
```

A row reading `Selected` was added but never mailed; `mc.send_pending_invitation(name)` sends it.

Every state-changing action is appended to `mc_actions.jsonl` in the state directory
(`MC_STATE_DIR`, default `~/.local/state/agentic-scholarone`); `mc.worklog.entries()` reads it back.

When a page parses to nothing, `MC_DEBUG=1` traces every navigation, and `mc.page_title()`,
`mc.page_text()`, `mc.list_links()`, `mc.show_form_fields()`, `mc.show_tables()` show what the
session is looking at.

## Use 2: interactive REPL, for humans

```bash
agentic-scholarone          # reads credentials.json in the current directory
```

```
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
```

## Extending: plug in your own infrastructure

Subclass `ScholarOneSession` and override what you need. The defaults are generic or do nothing.

| Extension point | Default | Typical override |
| --- | --- | --- |
| `default_journal` | `""` (then `MC_JOURNAL`) | your journal slug |
| `ms_id_pattern` | `[A-Z][A-Z0-9]+-\d{4}[-.\w]*` | your journal's id format |
| `keyring_service` | `agentic-scholarone` | your secret-store service name |
| `state_dir` | `~/.local/state/agentic-scholarone` | a project directory |
| `two_factor_code_providers()` | `[]` | read the code from a local mailbox |
| `invitation_paragraph(candidate, **opts)` | `""` | a paragraph added to every invitation |

```python
from agentic_scholarone import ScholarOneSession, main

class MyJournal(ScholarOneSession):
    default_journal = "abc-cs"
    ms_id_pattern = r"ABC-\d{4}-\d{2}-\d+[\w.]*"

    def two_factor_code_providers(self):
        return [read_code_from_my_mailbox]           # fn(timeout_s) -> "123456" or ""

    def invitation_paragraph(self, candidate, note="", **_):
        return note                                  # mc.invite_by_email(ms, email, note="…")

def cmd_hello(mc, arg):                              # an extra REPL command
    print("hello", mc.journal, arg)

if __name__ == "__main__":
    main(MyJournal, {"hello": cmd_hello})
```

Keyword arguments given to `invite_by_email` / `invite_by_name` reach `invitation_paragraph`.

## Development

```bash
uv venv && uv pip install -e ".[keyring,dev]"
pytest && ruff check . && mypy agentic_scholarone
```

Tests run on hand-written HTML fixtures. Never commit pages captured from a live session: they hold
the names of authors and reviewers.

## License

MIT
