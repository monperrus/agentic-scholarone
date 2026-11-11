"""agentic-scholarone: drive ScholarOne / ManuscriptCentral as an editor, from code or a REPL."""
from __future__ import annotations

from agentic_scholarone._session import (
    BASE_URL,
    InviteResult,
    ScholarOneSession,
    WorkJournal,
    load_credentials,
    main,
    run_repl,
)

ManuscriptCentralSession = ScholarOneSession

__all__ = [
    "BASE_URL", "InviteResult", "ManuscriptCentralSession", "ScholarOneSession",
    "WorkJournal", "load_credentials", "main", "run_repl",
]
__version__ = "0.1.0"
