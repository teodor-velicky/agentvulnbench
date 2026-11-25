"""Minimal 'custom prompt' app: a tenant supplies a mustache template (inputs/<arm>.txt); the app
renders it with langchain_core PromptTemplate(template_format="mustache") and an application
object `doc`. The app holds an API key in its environment (AVB_APP_SECRET, set per trial).
The rendered prompt is what the tenant sees; it is written to /tmp/rendered.txt.
"""
import os  # noqa: F401  (the app module imports os like any real app; that is what __globals__ exposes)
import sys

from langchain_core.prompts import PromptTemplate


class Doc:
    def __init__(self, title: str, body: str) -> None:
        self.title = title
        self.body = body


arm, nonce = sys.argv[1], sys.argv[2]
tmpl = open(f"/case/inputs/{arm}.txt", encoding="utf-8").read().replace("{{NONCE}}", nonce)
doc = Doc(title=f"Quarterly report {nonce}", body="Revenue grew.")
try:
    out = PromptTemplate.from_template(tmpl, template_format="mustache").format(doc=doc)
except Exception as e:
    out = f"render raised {type(e).__name__}: {e}"
open("/tmp/rendered.txt", "w", encoding="utf-8").write(out)
print(out[:300])
