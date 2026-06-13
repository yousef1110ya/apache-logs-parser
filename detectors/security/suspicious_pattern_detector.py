import re

from urllib.parse import unquote_plus

from detectors.base import BaseDetector

from core.types import DetectionType


class SuspiciousPatternDetector(BaseDetector):

    NAME = "suspicious_patterns"

    SQLI_PATTERNS = [
        re.compile(r"\bunion\s+select\b"),
        re.compile(r"(\bor\b|\band\b)\s+1\s*=\s*1"),
        re.compile(r"'\s*or\s+'?1'?\s*=\s*'?1"),
        re.compile(r"\"\s*or\s+\"?1\"?\s*=\s*\"?1"),
        re.compile(r"'\s*--"),
        re.compile(r"\bdrop\s+table\b"),
        re.compile(r"\binformation_schema\b"),
        re.compile(r"\bsleep\s*\("),
        re.compile(r"\bbenchmark\s*\(")
    ]

    XSS_PATTERNS = [
        re.compile(r"<\s*script\b"),
        re.compile(r"javascript\s*:"),
        re.compile(r"\bonerror\s*="),
        re.compile(r"\bonload\s*="),
        re.compile(r"\balert\s*\("),
        re.compile(r"\bdocument\.cookie\b")
    ]

    def detect(self, event):

        target = self._target_text(
            event
        )

        detections = []

        if any(
            pattern.search(target)
            for pattern in self.SQLI_PATTERNS
        ):
            detections.extend(
                [
                    DetectionType.SECURITY,
                    DetectionType.SUSPICIOUS,
                    DetectionType.SQLI
                ]
            )

        if any(
            pattern.search(target)
            for pattern in self.XSS_PATTERNS
        ):
            detections.extend(
                [
                    DetectionType.SECURITY,
                    DetectionType.SUSPICIOUS,
                    DetectionType.XSS
                ]
            )

        return list(
            set(detections)
        )

    def _target_text(self, event):

        text = " ".join(
            value
            for value in [
                event.path,
                event.query,
                self._flatten(
                    event.headers
                ),
                self._flatten(
                    event.body
                ),
                event.raw_line
            ]
            if value
        )

        return unquote_plus(
            text
        ).lower()

    def _flatten(self, value):

        if value is None:
            return ""

        if isinstance(
            value,
            dict
        ):
            return " ".join(
                f"{key} {self._flatten(item)}"
                for key, item in value.items()
            )

        if isinstance(
            value,
            list
        ):
            return " ".join(
                self._flatten(item)
                for item in value
            )

        return str(
            value
        )

