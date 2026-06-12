from enum import Enum


class DetectionType(Enum):

    ERROR = "error"

    SECURITY = "security"

    AUTH_FAILURE = "auth_failure"

    SUSPICIOUS = "suspicious"

    SQLI = "sqli"

    XSS = "xss"

    RATE_LIMITED_429 = "rate_limited_429"

    DDOS = "ddos"

    TRAFFIC = "traffic"
