from abc import ABC, abstractmethod

class BaseModule(ABC):
    @property
    @abstractmethod
    def name(self) -> str:
        pass

    @abstractmethod
    def run(self, target_url: str) -> list[dict]:
        """
        Executes the security check.
        Returns a list of finding dicts:
        [{
            'name': str,
            'severity': 'LOW'|'MEDIUM'|'HIGH'|'CRITICAL',
            'description': str,
            'evidence': str,
            'remediation': str
        }]
        """
        pass
