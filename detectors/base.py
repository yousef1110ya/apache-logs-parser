from abc import ABC, abstractmethod


class BaseDetector(ABC):

    NAME = "base"

    @abstractmethod
    def detect(self, event):
        pass
