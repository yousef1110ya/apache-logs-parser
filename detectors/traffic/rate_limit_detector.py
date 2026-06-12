from detectors.base import BaseDetector

from core.types import DetectionType


class RateLimitDetector(BaseDetector):

    NAME = "rate_limit"

    def detect(self, event):

        if event.status_code == 429:
            return [
                DetectionType.RATE_LIMITED_429,
                DetectionType.TRAFFIC
            ]

        return []
