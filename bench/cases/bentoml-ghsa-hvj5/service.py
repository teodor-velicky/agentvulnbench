# Minimal new-style BentoML service: one JSON API, nothing pickle-related declared.
import bentoml


@bentoml.service
class Echo:
    @bentoml.api
    def echo(self, text: str) -> str:
        return text
