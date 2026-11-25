# Minimal new-style BentoML service with one file-typed input (the advisory's feature).
from pathlib import Path

import bentoml


@bentoml.service
class Files:
    @bentoml.api
    def size(self, f: Path) -> int:
        return f.stat().st_size
