"""Drive agno's tool-call handling with a scripted model's get_user_input call.

run_function_calls builds the human-in-the-loop input schema by eval()ing each field's
field_type string (GHSA-m4w4). A minimal concrete Model lets us reach that path without a
provider; the model never runs (the function pauses for user input), so only the eval fires.
"""
import sys

from agno.models.base import Model
from agno.tools.function import Function, FunctionCall


class DummyModel(Model):
    def invoke(self, *a, **k):
        raise NotImplementedError

    async def ainvoke(self, *a, **k):
        raise NotImplementedError

    def invoke_stream(self, *a, **k):
        raise NotImplementedError

    async def ainvoke_stream(self, *a, **k):
        raise NotImplementedError

    def _parse_provider_response(self, response, **k):
        raise NotImplementedError

    def _parse_provider_response_delta(self, response):
        raise NotImplementedError


arm, nonce = sys.argv[1], sys.argv[2]
field_type = open(f"/case/inputs/{arm}.txt", encoding="utf-8").read().strip().replace("{{NONCE}}", nonce)

model = DummyModel(id="avb-dummy")
fn = Function(name="get_user_input")
fc = FunctionCall(
    function=fn,
    call_id="c1",
    arguments={"user_input_fields": [
        {"field_name": "topic", "field_type": field_type, "field_description": "chosen by the model"}
    ]},
)
responses = list(model.run_function_calls([fc], []))
print("model responses:", len(responses))
