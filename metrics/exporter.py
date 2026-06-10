from prometheus_client import Counter


DETECTION_COUNTER = Counter(
    "log_detections_total",
    "Detected log events",
    ["type"]
)


def increment(detection_type):

    DETECTION_COUNTER.labels(
        type=detection_type.value
    ).inc()
