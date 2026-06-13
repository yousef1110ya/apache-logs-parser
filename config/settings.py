import os


ACCESS_LOG_PATH = os.getenv(
    "ACCESS_LOG_PATH",
    "/shared-logs/access.log"
)

ERROR_LOG_PATH = os.getenv(
    "ERROR_LOG_PATH",
    "/shared-logs/error.log"
)

REQUEST_AUDIT_LOG_PATH = os.getenv(
    "REQUEST_AUDIT_LOG_PATH",
    "/shared-logs/request-audit.log"
)

PROMETHEUS_PORT = int(
    os.getenv(
        "PROMETHEUS_PORT",
        "8000"
    )
)
