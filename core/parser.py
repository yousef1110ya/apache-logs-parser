import json
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
JSON_TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%S"


def _parse_timestamp(value, timestamp_format=APACHE_TIMESTAMP_FORMAT):

    if not value:
        return None

    try:
        return datetime.strptime(
            value,
            timestamp_format
        )
    except ValueError:
        return None


def _parse_request(value):

    parts = value.split()

    if len(parts) < 2:
        return None, None

    return parts[0], parts[1]


def _normalize_optional_header(value):

    if value in (None, "", "-"):
        return None

    return value


def _parse_status(value):

    try:
        return int(
            value
        )
    except (TypeError, ValueError):
        return None


def _parse_json_access(line):

    try:
        payload = json.loads(
            line
        )
    except json.JSONDecodeError:
        return None

    path = payload.get(
        "path"
    )

    query = payload.get(
        "query"
    )

    if query and query != "-":
        path = f"{path or ''}{query}"

    return LogEvent(
        source="access",
        raw_line=line,
        timestamp=_parse_timestamp(
            payload.get("timestamp"),
            JSON_TIMESTAMP_FORMAT
        ),
        ip=payload.get("client_ip"),
        method=payload.get("method"),
        path=path,
        status_code=_parse_status(
            payload.get("status")
        ),
        referer=_normalize_optional_header(
            payload.get("referer")
        ),
        user_agent=_normalize_optional_header(
            payload.get("user_agent")
        )
    )


def parse_access(line):

    event = _parse_json_access(
        line
    )

    if event:
        return event

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
        status_code=_parse_status(
            status
        ),
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
