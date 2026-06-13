# AI Log Classifier

## Overview

The AI Log Classifier is a lightweight rule-based log analysis service designed to run as a dedicated Docker container.

The service continuously monitors Apache access and error logs, classifies log entries into operational and security-related categories, and exposes detection metrics through a Prometheus-compatible endpoint.

No machine learning model or training process is required.

The system is built around a plugin architecture that allows new detectors to be added without modifying the existing codebase.

---

# Architecture

The system consists of four major components:

```text
Apache Logs
    │
    ▼
Log Readers
    │
    ▼
Detection Engine
    │
    ▼
Detector Plugins
    │
    ▼
Prometheus Metrics
    │
    ▼
Grafana Dashboards
```

## Processing Flow

1. Apache and the e-commerce app write log entries to:

```text
access.log
error.log
request-audit.log
```

2. The classifier watches all configured log files in real time.

3. New log entries are parsed into LogEvent objects.

4. The Detection Engine sends each event to every loaded detector.

5. Detectors return one or more DetectionTypes.

6. Metrics are updated.

7. Prometheus scrapes the metrics endpoint.

8. Grafana visualizes the results.

---

# Project Structure

```text
ai_classifier/
│
├── main.py
│
├── core/
│   ├── event.py
│   ├── parser.py
│   ├── engine.py
│   ├── registry.py
│   └── types.py
│
├── detectors/
│   ├── base.py
│   │
│   ├── operational/
│   │   └── error_detector.py
│   │
│   └── traffic/
│       └── ddos_detector.py
│
├── metrics/
│   └── exporter.py
│
├── reader/
│   └── tail_reader.py
│
└── config/
    └── settings.py
```

---

# Core Concepts

## LogEvent

Every log line is converted into a LogEvent object.

Example:

```python
event.ip
event.method
event.path
event.query
event.status_code
event.headers
event.body
event.raw_line
```

All detectors receive the same event object.

---

## Detection Types

Detectors report findings using DetectionType values.

Example:

```python
DetectionType.ERROR

DetectionType.DDOS

DetectionType.TRAFFIC
```

These values become Prometheus labels.

---

## Detector Plugins

Each detector is a completely independent plugin.

Detectors do not communicate with each other.

Detectors do not know anything about:

* Prometheus
* Grafana
* Apache
* Other detectors

Their only responsibility is:

```python
Analyze Event
        ↓
Return Detections
```

---

# Automatic Plugin Discovery

The system automatically discovers detectors at startup.

The registry scans all modules inside the detectors package.

Any class that:

1. Inherits from BaseDetector
2. Implements detect()

will automatically be loaded.

No registration is required.

No configuration changes are required.

No engine changes are required.

---

# Creating New Detectors

## Step 1

Create a new file.

Example:

```text
detectors/security/xss_detector.py
```

---

## Step 2

Inherit from BaseDetector.

Example:

```python
from detectors.base import BaseDetector


class XSSDetector(BaseDetector):

    NAME = "xss"

    def detect(self, event):

        return []
```

---

## Step 3

Implement detection logic.

Example:

```python
if "<script" in event.path.lower():

    return [
        DetectionType.SECURITY,
        DetectionType.XSS
    ]

return []
```

---

## Step 4

Restart the container.

The detector will be loaded automatically.

No additional changes are required.

---

# Detector Rules

Every detector must follow the following rules.

## Rule 1

Must inherit from BaseDetector.

Correct:

```python
class MyDetector(BaseDetector):
```

Incorrect:

```python
class MyDetector:
```

---

## Rule 2

Must define a NAME field.

Correct:

```python
NAME = "xss"
```

Incorrect:

```python
# Missing NAME
```

---

## Rule 3

Must implement detect().

Correct:

```python
def detect(self, event):
```

---

## Rule 4

Must return a list.

Correct:

```python
return []
```

Correct:

```python
return [
    DetectionType.SECURITY
]
```

Incorrect:

```python
return DetectionType.SECURITY
```

---

## Rule 5

Must never modify the event.

Correct:

```python
read event fields
```

Incorrect:

```python
event.path = "changed"
```

Events should be treated as read-only.

---

## Rule 6

Must not update metrics directly.

Correct:

```python
return detections
```

Incorrect:

```python
DETECTION_COUNTER.inc()
```

Only the metrics layer should interact with Prometheus.

---

# Example Detector

```python
from detectors.base import BaseDetector

from core.types import DetectionType


class ExampleDetector(BaseDetector):

    NAME = "example"

    def detect(self, event):

        if "example" in event.raw_line.lower():

            return [
                DetectionType.TRAFFIC
            ]

        return []
```

---

# Prometheus Metrics

The system exposes metrics at:

```text
http://localhost:8000/metrics
```

Example:

```text
log_detections_total{type="error"}
log_detections_total{type="ddos"}
log_detections_total{type="traffic"}
```

---

# Current Detectors

## ErrorDetector

Detects:

* HTTP 5xx responses
* Exceptions
* Fatal errors
* Stack traces
* Application crashes

---

## DDOSDetector

Detects:

* Excessive request rates
* High request volume from a single IP
* Large numbers of HTTP 429 responses
* DDoS-like traffic patterns

The detector uses a rolling time window and tracks activity per IP address.

## Request Body Audit Logs

The e-commerce app writes sanitized request-body audit events as JSON lines.

Example:

```json
{
  "source": "request-audit",
  "method": "PUT",
  "path": "/api/users/me",
  "status": 200,
  "body": {
    "name": "<script>alert(1)</script>",
    "password": "[REDACTED]"
  }
}
```

The classifier parses these events and the suspicious-pattern detector scans URL paths, query strings, headers, request body values, and the raw log line.

---

# Design Goals

The system was designed around the following principles:

* Simple deployment
* No machine learning training
* Modular architecture
* Easy extension
* Automatic plugin discovery
* Prometheus compatibility
* Grafana integration
* Docker-friendly operation

New detectors should be addable without modifying existing application code.

