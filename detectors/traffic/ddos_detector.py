from collections import defaultdict
from collections import deque
from datetime import datetime
from datetime import timedelta

from detectors.base import BaseDetector

from core.types import DetectionType


class DDOSDetector(BaseDetector):

    NAME = "ddos"

    WINDOW_SECONDS = 60

    REQUEST_THRESHOLD = 100

    RESPONSE_429_THRESHOLD = 20

    def __init__(self):

        self.request_history = defaultdict(
            deque
        )

        self.response_429_history = defaultdict(
            deque
        )

    def detect(self, event):

        if not event.ip:
            return []

        now = datetime.utcnow()

        ip = event.ip

        self.request_history[ip].append(now)

        cutoff = now - timedelta(
            seconds=self.WINDOW_SECONDS
        )

        while (
            self.request_history[ip]
            and self.request_history[ip][0] < cutoff
        ):
            self.request_history[ip].popleft()

        if event.status_code == 429:

            self.response_429_history[ip].append(
                now
            )

            while (
                self.response_429_history[ip]
                and self.response_429_history[ip][0]
                < cutoff
            ):
                self.response_429_history[ip].popleft()

        request_count = len(
            self.request_history[ip]
        )

        response_429_count = len(
            self.response_429_history[ip]
        )

        if (
            request_count >= self.REQUEST_THRESHOLD
            or response_429_count >= self.RESPONSE_429_THRESHOLD
        ):

            return [
                DetectionType.DDOS,
                DetectionType.TRAFFIC
            ]

        return []
