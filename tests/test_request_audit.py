import json
import sys
import unittest

from pathlib import Path


sys.path.insert(
    0,
    str(Path(__file__).resolve().parents[1])
)

from core.parser import parse_request_audit
from core.types import DetectionType
from detectors.security.suspicious_pattern_detector import SuspiciousPatternDetector


class RequestAuditParserTest(unittest.TestCase):

    def test_parse_request_audit_body(self):
        line = json.dumps(
            {
                "timestamp": "2026-06-13T10:00:00Z",
                "source": "request-audit",
                "method": "POST",
                "path": "/api/products",
                "query": None,
                "status": 400,
                "client_ip": "10.0.0.1",
                "user_agent": "postman",
                "headers": {
                    "Content-Type": "application/json"
                },
                "body": {
                    "name": "' OR 1=1--",
                    "description": "<script>alert(1)</script>"
                }
            }
        )

        event = parse_request_audit(
            line
        )

        self.assertEqual(
            "request_audit",
            event.source
        )
        self.assertEqual(
            "/api/products",
            event.path
        )
        self.assertEqual(
            "' OR 1=1--",
            event.body["name"]
        )

    def test_suspicious_detector_scans_body(self):
        line = json.dumps(
            {
                "method": "POST",
                "path": "/api/products",
                "status": 400,
                "body": {
                    "name": "' OR 1=1--",
                    "description": "<script>alert(1)</script>"
                }
            }
        )

        event = parse_request_audit(
            line
        )

        detections = SuspiciousPatternDetector().detect(
            event
        )

        self.assertIn(
            DetectionType.SQLI,
            detections
        )
        self.assertIn(
            DetectionType.XSS,
            detections
        )
        self.assertIn(
            DetectionType.SUSPICIOUS,
            detections
        )


if __name__ == "__main__":
    unittest.main()
