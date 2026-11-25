"""CHAINLAB driver: Langroid Neo4jChatAgent, model-mediated Cypher injection on the
RAG (read) path, with a real DB-backed effect.

The SCRIPTED MODEL is langroid's own MockLM (a LanguageModel, type=mock) plugged into
the agent's llm slot via Neo4jChatAgentConfig.llm=MockLMConfig(default_response=<tool
JSON>). The framework's real pipeline is then driven end to end:

    llm_msg = agent.llm_response(prompt)      # the (scripted) model emits a tool call
    agent.agent_response(llm_msg)             # the framework parses it and runs the tool

`agent_response` parses the model output into a CypherRetrievalTool and invokes
`cypher_retrieval_tool`, whose body (the sink) passes the model's Cypher to
`read_query` -> neo4j `session.run(query)` -- an AUTO-COMMIT transaction. So the outcome
depends only on whether the FRAMEWORK guards what it does with model-generated Cypher,
not on how a real model behaves. This mirrors the FakeListLLM approach in the LangChain
cases; here the framework's LLM interface is langroid's MockLM and the sink is a Cypher
query rather than Python exec.

Attacker story: an app runs a Neo4jChatAgent for graph RAG. A prompt injection (user
turn, tool result, or graph data read back) steers the model into emitting a
cypher_retrieval_tool call whose cypher_query is a write/destructive statement. In
langroid 0.65.4 the read path runs it verbatim (CVE-2026-55615 / GHSA-2pq5-3q89-j7cc);
the retrieval tool, meant for read-only RAG, performs arbitrary writes. The fix (0.65.5)
adds validate_cypher_query, restricting the read path to read-only Cypher.

A loopback memgraph (Neo4j bolt-compatible) runs in the same --network none container.
The attack Cypher CREATEs a (:ChainlabCanary {nonce}) node; the oracle checks the DB for
it. CONTROL is a benign in-shape retrieval (MATCH ... RETURN), which writes nothing.

Usage: python -I driver.py <arm> <nonce>   # arm in {attack, control}
"""
import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

ARM, NONCE = sys.argv[1], sys.argv[2]
BOLT = "bolt://127.0.0.1:7687"
AUTH = ("memgraph", "memgraph")  # memgraph ignores auth by default; any creds connect

# The scripted model's completion: a CypherRetrievalTool call carrying the fixture Cypher.
cypher = Path(f"/case/fixtures/{ARM}.txt").read_text(encoding="utf-8").replace("{{NONCE}}", NONCE).strip()
tool_json = json.dumps({"request": "cypher_retrieval_tool", "cypher_query": cypher})


def start_memgraph() -> subprocess.Popen:
    data_dir = "/tmp/mg_data"
    os.makedirs(data_dir, exist_ok=True)
    p = subprocess.Popen(
        ["/usr/lib/memgraph/memgraph", "--bolt-address=127.0.0.1", "--bolt-port=7687",
         f"--data-directory={data_dir}", "--telemetry-enabled=false", "--log-level=WARNING",
         "--log-file=/tmp/memgraph.log"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    for _ in range(200):  # up to ~20s
        try:
            socket.create_connection(("127.0.0.1", 7687), 0.3).close()
            return p
        except OSError:
            time.sleep(0.1)
    raise RuntimeError("memgraph did not come up on 127.0.0.1:7687")


def main() -> int:
    start_memgraph()  # left running for the oracle; reaped on container teardown
    import neo4j
    from langroid.agent.special.neo4j.neo4j_chat_agent import (
        Neo4jChatAgent, Neo4jChatAgentConfig, Neo4jSettings,
    )
    from langroid.language_models.mock_lm import MockLMConfig

    cfg = Neo4jChatAgentConfig(
        neo4j_settings=Neo4jSettings(uri=BOLT, username=AUTH[0], password=AUTH[1], database="memgraph"),
        llm=MockLMConfig(default_response=tool_json),
        use_schema_tools=True, use_functions_api=False, use_tools=True,
    )
    # Build the agent against an EMPTY graph so its __init__ never calls the
    # (memgraph-incompatible) schema-visualization procedure. We then seed a benign
    # node to model the existing RAG graph and set the ordinary in-session flags.
    agent = Neo4jChatAgent(cfg)

    seed = neo4j.GraphDatabase.driver(BOLT, auth=AUTH)
    with seed.session() as s:
        s.run("CREATE (:Person {name:'Ada'})-[:KNOWS]->(:Person {name:'Grace'})")
    seed.close()
    agent.tried_schema = True            # normal RAG state: schema already fetched
    agent.config.database_created = True  # normal RAG state: graph has data

    # Drive the framework's real LLM -> tool pipeline. The scripted model emits the
    # tool call; the framework routes its cypher_query to the Cypher sink.
    llm_msg = agent.llm_response("Use the graph to answer the user's question.")
    result = agent.agent_response(llm_msg)
    print(f"[{ARM}] scripted model -> framework; handler said:",
          str(result.content if result is not None else result)[:200].replace("\n", " "))
    return 0


if __name__ == "__main__":
    sys.exit(main())
