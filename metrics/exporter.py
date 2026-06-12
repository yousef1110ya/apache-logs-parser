from prometheus_client import Counter


DETECTION_COUNTER = Counter(
    "log_detections_total",
    "Detected log events",
    ["type"]
)

LINES_PROCESSED_COUNTER = Counter(
    "log_lines_processed_total",
    "Log lines processed by source",
    ["source"]
)

PARSE_FAILURE_COUNTER = Counter(
    "log_parse_failures_total",
    "Log lines that could not be parsed by source",
    ["source"]
)


def increment_detection(detection_type):

    DETECTION_COUNTER.labels(
        type=detection_type.value
    ).inc()


def increment_line_processed(source):

    LINES_PROCESSED_COUNTER.labels(
        source=source
    ).inc()


def increment_parse_failure(source):

    PARSE_FAILURE_COUNTER.labels(
        source=source
    ).inc()


def increment(detection_type):

    increment_detection(
        detection_type
    )
