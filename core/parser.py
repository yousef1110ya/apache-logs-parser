import re

from datetime import datetime

from core.event import LogEvent


ACCESS_PATTERN = re.compile(
    r"""
    ^(?P<ip>\S+)\s+
    (?P<ident>\S+)\s+
    (?P<user>\S+)\s+
    \[(?P<timestamp>[^\]]+)\]\s+
    "(?P<request>[^"]*)"\s+
    (?P<status>\d{3}|-)\s+
    (?P<size>\S+)
    (?:\s+"(?P<referer>[^"]*)"\s+"(?P<user_agent>[^"]*)")?
    (?:\s+.*)?$
    """,
    re.VERBOSE
)

APACHE_TIMESTAMP_FORMAT = "%d/%b/%Y:%H:%M:%S %z"


def _parse_timestamp(value):

    try:
        return datetime.strptime(
            value,
            APACHE_TIMESTAMP_FORMAT
        )
    except ValueError:
        return None


def _parse_request(value):

    parts = value.split()

    if len(parts) < 2:
        return None, None

    return parts[0], parts[1]


def _normalize_optional_header(value):

    if value in (None, "-"):
        return None

    return value


def parse_access(line):

    match = ACCESS_PATTERN.search(
        line
    )

    if not match:
        return None

    method, path = _parse_request(
        match.group("request")
    )

    status = match.group("status")

    return LogEvent(
        source="access",
        raw_line=line,
        timestamp=_parse_timestamp(
            match.group("timestamp")
        ),
        ip=match.group("ip"),
        method=method,
        path=path,
        status_code=int(status) if status.isdigit() else None,
        referer=_normalize_optional_header(
            match.group("referer")
        ),
        user_agent=_normalize_optional_header(
            match.group("user_agent")
        )
    )


def parse_error(line):

    return LogEvent(
        source="error",
        raw_line=line
    )
