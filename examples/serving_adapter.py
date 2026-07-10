"""
Integration adapter: SCE around an OpenAI-style stateless inference endpoint.

Run:  python examples/serving_adapter.py

This shows the concrete pattern for injecting SCE into an existing serving
stack, and that it is a thin wrapper -- not a rewrite. The provider stays
STATELESS: it holds no conversation between turns. Instead:

    * on egress, the server seals the new continuation state and returns it in
      the API response (base64), and
    * on ingress, the client returns that sealed state and the server unseals it
      to resume -- or, if the model changed underneath, the unseal fails closed
      and the client transparently rebuilds from its retained transcript.

`MockInferenceServer` stands in for a real engine (vLLM/TGI) so this runs with
no GPU. The SCE calls are exactly what they would be in production; only the
"run the model" line is mocked.
"""

import os
import json
import base64
import logging

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sce import (  # noqa: E402
    ModelManifest, seal_state, unseal_state, StateSealMismatch, explain_mismatch,
)

# The refusal reason (explain_mismatch) is an ORACLE. It is written here, to the
# SERVER's log, and must never be placed on the wire. See the chat() handler.
logger = logging.getLogger("sce.serving_adapter")


# --------------------------------------------------------------------------- #
# The provider side: a stateless endpoint + a thin SCE wrapper.
# --------------------------------------------------------------------------- #
class MockInferenceServer:
    """Stands in for an OpenAI-compatible, stateless inference server.

    The only state it keeps is its own model identity (manifest) and its server
    master secret. It never stores conversations.
    """

    def __init__(self):
        self.master_secret = os.urandom(32)
        self.manifest = ModelManifest(
            weights_hash="sha3:llama-3-8b-instruct-v1",
            quantization="bf16",
            kernel_build_id="vllm-0.6.3+build.a1b2c3",
            tensor_parallel="tp=1,pp=1",
            numerics_mode="bf16",
        )

    def service_discovery(self):
        """What a client fetches from /.well-known to learn the environment."""
        return {"memh": self.manifest.memh().hex()}

    # --- the SCE-wrapped endpoint -------------------------------------- #
    def chat(self, request: dict) -> dict:
        """OpenAI-style call with an added `continuation` (a sealed SCE blob).

        request = {"message": str, "continuation": <b64 str> | None}
        response = {"reply": str, "continuation": <b64 str>}   on success
                 = {"error": "state_epoch_mismatch", ...}       on fail-closed
        """
        prior_state = b""
        if request.get("continuation"):
            sealed = base64.b64decode(request["continuation"])
            try:
                prior_state = unseal_state(sealed, self.manifest,
                                           master_secret=self.master_secret)
            except StateSealMismatch:
                # Fail closed. The REASON is an oracle, so it is logged server-side
                # only and NEVER placed on the wire; the client receives a uniform
                # code and rebuilds from its own transcript.
                logger.warning("SCE unseal refused (server log only): %s",
                               explain_mismatch(sealed, self.manifest))
                return {"error": "state_epoch_mismatch"}

        # ---- the ONLY mocked line: run the model ----
        reply, new_state = self._run_model(request["message"], prior_state)

        sealed_new = seal_state(new_state, self.manifest, master_secret=self.master_secret)
        return {"reply": reply, "continuation": base64.b64encode(sealed_new).decode()}

    def _run_model(self, message: str, prior_state: bytes):
        """Mock: 'state' is a running transcript; reply echoes the turn count."""
        history = prior_state.decode() if prior_state else ""
        history = (history + "\n" if history else "") + "user:" + message
        turns = history.count("user:")
        reply = f"(model reply on turn {turns}; I have {len(history)} bytes of state)"
        history += "\nassistant:" + reply
        return reply, history.encode()

    def update_model(self):
        """Simulate an overnight re-quantisation: the manifest (hence MEMH) changes."""
        self.manifest = ModelManifest(
            weights_hash="sha3:llama-3-8b-instruct-v2",  # new checkpoint
            quantization="fp8-e4m3",                     # re-quantised
            kernel_build_id="vllm-0.6.4+build.d4e5f6",
            tensor_parallel="tp=1,pp=1",
            numerics_mode="bf16",
        )


# --------------------------------------------------------------------------- #
# The client side: holds the sealed state + the plaintext transcript.
# --------------------------------------------------------------------------- #
class Client:
    def __init__(self, server: MockInferenceServer):
        self.server = server
        self.continuation = None          # opaque sealed SCE blob (can't read it)
        self.transcript = []              # the client's own authoritative record

    def say(self, message: str) -> str:
        self.transcript.append(("user", message))
        resp = self.server.chat({"message": message, "continuation": self.continuation})

        if resp.get("error") == "state_epoch_mismatch":
            # The client learns only the uniform code -- never *why* it failed.
            print("    [client] server refused stale state (uniform error, no reason given);")
            print("    [client] rebuilding from transcript and retrying...")
            # Rebuild: replay the whole transcript in one turn (re-prefill), no stale blob.
            self.continuation = None
            replay = " | ".join(f"{r}:{m}" for r, m in self.transcript)
            resp = self.server.chat({"message": replay, "continuation": None})

        self.continuation = resp["continuation"]
        self.transcript.append(("assistant", resp["reply"]))
        return resp["reply"]


def rule(t):
    print("\n" + "=" * 68 + f"\n{t}\n" + "=" * 68)


def main():
    # Surface the server-side warning log so the demo shows that the reason still
    # exists ON THE SERVER -- it is simply never sent to the client.
    logging.basicConfig(level=logging.WARNING, format="  [server-log] %(message)s")
    server = MockInferenceServer()
    client = Client(server)

    rule("A normal multi-turn conversation (provider stays stateless)")
    print("server MEMH:", server.service_discovery()["memh"][:16], "...")
    for msg in ["Hello", "What did I just say?", "And before that?"]:
        print(f"  user: {msg}")
        print(f"   bot: {client.say(msg)}")
    print("\n  The provider stored NO conversation; the sealed continuation rode")
    print("  with the client each turn. Its size stays bounded by the state, not")
    print("  the transcript, and the client cannot read it (it is server-sealed).")

    rule("Mid-conversation, the model is updated overnight")
    server.update_model()
    print("new server MEMH:", server.service_discovery()["memh"][:16], "...  (changed)")
    print("  user: Continue please")
    print(f"   bot: {client.say('Continue please')}")
    print("\n  The client's stored continuation was sealed under the OLD model, so")
    print("  the server refused it (fail-closed) instead of resuming into silent")
    print("  corruption. The client rebuilt from its transcript and the")
    print("  conversation continued correctly under the new model.")
    print()


if __name__ == "__main__":
    main()
