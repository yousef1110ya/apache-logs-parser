import threading
import time

from prometheus_client import start_http_server

from config.settings import (
    ACCESS_LOG_PATH,
    ERROR_LOG_PATH,
    REQUEST_AUDIT_LOG_PATH,
    PROMETHEUS_PORT
)

from core.engine import DetectionEngine

from core.parser import (
    parse_access,
    parse_error,
    parse_request_audit
)

from reader.tail_reader import follow

from metrics.exporter import (
    increment,
    increment_line_processed,
    increment_parse_failure
)


engine = DetectionEngine()


def process_access_logs():

    for line in follow(
        ACCESS_LOG_PATH
    ):

        increment_line_processed(
            "access"
        )

        event = parse_access(line)

        if not event:
            increment_parse_failure(
                "access"
            )
            continue

        detections = engine.process(
            event
        )

        for detection in detections:

            increment(
                detection
            )


def process_error_logs():

    for line in follow(
        ERROR_LOG_PATH
    ):

        increment_line_processed(
            "error"
        )

        event = parse_error(line)

        detections = engine.process(
            event
        )

        for detection in detections:

            increment(
                detection
            )


def process_request_audit_logs():

    for line in follow(
        REQUEST_AUDIT_LOG_PATH
    ):

        increment_line_processed(
            "request_audit"
        )

        event = parse_request_audit(line)

        if not event:
            increment_parse_failure(
                "request_audit"
            )
            continue

        detections = engine.process(
            event
        )

        for detection in detections:

            increment(
                detection
            )


if __name__ == "__main__":

    print(
        "Starting AI classifier metrics server on port",
        PROMETHEUS_PORT
    )
    print(
        "Watching access log:",
        ACCESS_LOG_PATH
    )
    print(
        "Watching error log:",
        ERROR_LOG_PATH
    )
    print(
        "Watching request audit log:",
        REQUEST_AUDIT_LOG_PATH
    )

    start_http_server(
        PROMETHEUS_PORT
    )

    threading.Thread(
        target=process_access_logs,
        daemon=True
    ).start()

    threading.Thread(
        target=process_error_logs,
        daemon=True
    ).start()

    threading.Thread(
        target=process_request_audit_logs,
        daemon=True
    ).start()

    while True:
        time.sleep(
            1
        )
