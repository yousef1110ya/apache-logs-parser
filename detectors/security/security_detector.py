from detectors.base import BaseDetector

from core.types import DetectionType


class SecurityDetector(BaseDetector):

    NAME = "security"

    AUTH_FAILURE_KEYWORDS = [
        "unauthorized",
        "bad credentials",
        "authentication failed",
        "failed authentication",
        "invalid token",
        "expired token",
        "login failed"
    ]

    SECURITY_KEYWORDS = [
        "forbidden",
        "access denied",
        "permission denied"
    ]

    def detect(self, event):

        detections = []

        if event.status_code == 401:
            detections.extend(
                [
                    DetectionType.SECURITY,
                    DetectionType.AUTH_FAILURE
                ]
            )

        if event.status_code == 403:
            detections.append(
                DetectionType.SECURITY
            )

        line = event.raw_line.lower()

        if any(
            keyword in line
            for keyword in self.AUTH_FAILURE_KEYWORDS
        ):
            detections.extend(
                [
                    DetectionType.SECURITY,
                    DetectionType.AUTH_FAILURE
                ]
            )

        if any(
            keyword in line
            for keyword in self.SECURITY_KEYWORDS
        ):
            detections.append(
                DetectionType.SECURITY
            )

        return list(
            set(detections)
        )

