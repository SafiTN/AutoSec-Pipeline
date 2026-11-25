from dataclasses import dataclass, field
from typing import Any, Dict, List


@dataclass
class HarnessSpec:
    """تعريف مهمة الاختبار الأمني ومواصفات تشغيل الوكيل."""

    task_id: str
    description: str
    target_code: str
    test_code: str = ""
    timeout_sec: int = 10
    allowed_imports: List[str] = field(default_factory=lambda: ["math", "re", "json", "urllib.parse"])
    metadata: Dict[str, Any] = field(default_factory=dict)


class BaseHarness:
    """الواجهة الأساسية لبيئة تشغيل وتقييم الوكيل الأمني."""

    def __init__(self, settings: Dict[str, Any]):
        self.settings = settings

    def prepare(self, spec: HarnessSpec) -> None:
        raise NotImplementedError("Subclasses must implement prepare().")

    def execute(self, spec: HarnessSpec) -> Dict[str, Any]:
        raise NotImplementedError("Subclasses must implement execute().")

    def cleanup(self) -> None:
        raise NotImplementedError("Subclasses must implement cleanup().")
