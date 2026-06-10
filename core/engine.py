from core.registry import load_detectors


class DetectionEngine:

    def __init__(self):

        self.detectors = load_detectors()

        print(
            "Loaded detectors:",
            [d.NAME for d in self.detectors]
        )

    def process(self, event):

        results = []

        for detector in self.detectors:

            results.extend(
                detector.detect(event)
            )

        return list(
            set(results)
        )
