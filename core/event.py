from dataclasses import dataclass
from datetime import datetime


@dataclass
class LogEvent:

    source: str

    raw_line: str

    timestamp: datetime | None = None

    ip: str | None = None

    method: str | None = None

    path: str | None = None

    status_code: int | None = None

    referer: str | None = None

    user_agent: str | None = None
