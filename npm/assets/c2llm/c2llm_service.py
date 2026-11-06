#!/usr/bin/env python3
"""Opt-in, loopback-only C2LLM embedding adapter; never changes Docdex memory models.

Run `prepare --directory PATH` once, then `serve --directory PATH` in its own
memory-limited service. Heavy dependencies are imported only for these commands.
"""
import argparse
import hashlib
import json
import math
import shutil
import threading
from collections import OrderedDict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

MODEL = "codefuse-ai/C2LLM-0.5B"
REVISION = "bd6d0ddb29f0c9a3d0f14281aedc9f940bb8d67a"
DIMENSIONS = 896
MAX_TOKENS = 512
MAX_BATCH = 4
MAX_BODY = 65536


def prepare(directory):
    from huggingface_hub import snapshot_download

    directory.mkdir(parents=True, exist_ok=False)
    snapshot = Path(snapshot_download(MODEL, revision=REVISION,
        allow_patterns=["*.json", "*.py", "*.safetensors", "*.txt", "*.model"]))
    for source in snapshot.iterdir():
        if source.is_file():
            shutil.copy2(source, directory / source.name)
    path = directory / "modeling_c2llm.py"
    original = path.read_text()
    source = original
    # These names occur only in imports, not in the model's inference code.
    for line, names in [
        ("from peft import LoraConfig, get_peft_model, TaskType",
         ["LoraConfig", "get_peft_model", "TaskType"]),
        ("from deepspeed.utils.zero_to_fp32 import get_fp32_state_dict_from_zero_checkpoint",
         ["get_fp32_state_dict_from_zero_checkpoint"]),
    ]:
        if not all(source.count(name) == 1 for name in names):
            raise RuntimeError("Pinned model source changed; review training imports")
        source = source.replace(line, "# Unused training-only import omitted.")
    before = "self.target_devices = self.get_target_devices(None)"
    if source.count(before) != 1:
        raise RuntimeError("Pinned model source changed; review device selection")
    # Upstream CPU detection refers to undefined optional-backend functions.
    source = source.replace(before, 'self.target_devices = ["cpu"]')
    path.write_text(source)
    (directory / "docdex-adapter.json").write_text(json.dumps({
        "model": MODEL, "revision": REVISION, "dimensions": DIMENSIONS,
        "upstream_source_sha256": hashlib.sha256(original.encode()).hexdigest(),
        "adapted_source_sha256": hashlib.sha256(source.encode()).hexdigest(),
        "changes": ["omit unused training imports", "explicit CPU device selection"],
    }, indent=2) + "\n")


def validate_request(payload):
    if not isinstance(payload, dict) or payload.get("model", MODEL) != MODEL:
        raise ValueError("unsupported model")
    values = payload.get("input")
    if isinstance(values, str):
        values = [values]
    if not isinstance(values, list) or not 1 <= len(values) <= MAX_BATCH:
        raise ValueError("input must contain one to four strings")
    if any(not isinstance(s, str) or not s.strip() or len(s) > 16000 for s in values):
        raise ValueError("each input must contain 1–16000 characters")
    return values


class Encoder:
    def __init__(self, directory, threads):
        import torch
        from transformers import AutoConfig, AutoModel, AutoTokenizer

        manifest = json.loads((directory / "docdex-adapter.json").read_text())
        digest = hashlib.sha256((directory / "modeling_c2llm.py").read_bytes()).hexdigest()
        if manifest.get("revision") != REVISION or digest != manifest.get("adapted_source_sha256"):
            raise ValueError("unrecognized model preparation; rerun prepare into a new directory")
        torch.set_num_threads(threads)
        torch.set_num_interop_threads(1)
        config = AutoConfig.from_pretrained(directory, trust_remote_code=True, local_files_only=True)
        config.tokenizer_name_or_path = None
        config.use_cache = False
        config.attn_implementation = "sdpa"
        self.model = AutoModel.from_pretrained(directory, config=config,
            trust_remote_code=True, local_files_only=True, dtype=torch.bfloat16,
            attn_implementation="sdpa").eval()
        self.tokenizer = AutoTokenizer.from_pretrained(directory, padding_side="left",
            local_files_only=True)
        self.torch = torch
        self.cache = OrderedDict()
        self.cache_hits = 0
        self.cache_misses = 0

    def encode(self, texts):
        vectors = []
        for text in texts:
            key = hashlib.sha256(text.encode()).digest()
            if key in self.cache:
                self.cache_hits += 1
                self.cache.move_to_end(key)
                vectors.append(self.cache[key])
                continue
            self.cache_misses += 1
            inputs = self.tokenizer([text], return_tensors="pt", padding=True,
                truncation=True, max_length=MAX_TOKENS)
            with self.torch.inference_mode():
                # The stock wrapper computes vocabulary logits and retains every
                # hidden layer. PMA needs only the final Qwen hidden state.
                hidden = self.model.plm_model.model(**inputs, use_cache=False).last_hidden_state
                embedding = self.model.get_sentence_embedding("pma", hidden, "disc",
                    inputs["attention_mask"])
                vector = self.torch.nn.functional.normalize(embedding.float(), p=2, dim=-1)[0].tolist()
            if len(vector) != DIMENSIONS or not all(math.isfinite(v) for v in vector):
                raise RuntimeError("invalid embedding output")
            self.cache[key] = vector
            if len(self.cache) > 256:
                self.cache.popitem(last=False)
            vectors.append(vector)
        return vectors


def serve(directory, port, threads):
    encoder = Encoder(directory, threads)
    admission = threading.BoundedSemaphore(1)

    class Handler(BaseHTTPRequestHandler):
        def reply(self, status, payload):
            body = json.dumps(payload, allow_nan=False).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            if self.path != "/healthz":
                return self.reply(404, {"error": "not_found"})
            self.reply(200, {"model": MODEL, "revision": REVISION, "dimensions": DIMENSIONS,
                "max_tokens": MAX_TOKENS, "cache_entries": len(encoder.cache),
                "cache_hits": encoder.cache_hits, "cache_misses": encoder.cache_misses})

        def do_POST(self):
            if self.path != "/v1/embeddings":
                return self.reply(404, {"error": "not_found"})
            if not admission.acquire(blocking=False):
                return self.reply(503, {"error": "embedding_busy"})
            try:
                self.connection.settimeout(10)
                length = int(self.headers.get("Content-Length", "0"))
                if not 0 < length <= MAX_BODY:
                    return self.reply(413, {"error": "request_too_large"})
                texts = validate_request(json.loads(self.rfile.read(length)))
                vectors = encoder.encode(texts)
                self.reply(200, {"object": "list", "model": MODEL,
                    "data": [{"object": "embedding", "index": i, "embedding": v}
                             for i, v in enumerate(vectors)]})
            except (ValueError, TimeoutError) as error:
                self.reply(400, {"error": str(error)})
            except Exception:
                self.reply(500, {"error": "embedding_failed"})
            finally:
                admission.release()

        def log_message(self, *_args):
            pass  # Do not log source text or query content.

    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    server.daemon_threads = True
    server.serve_forever()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["prepare", "serve"])
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--port", type=int, default=28521)
    parser.add_argument("--threads", type=int, default=2, choices=range(1, 9))
    args = parser.parse_args()
    if args.command == "prepare":
        prepare(args.directory)
    else:
        serve(args.directory, args.port, args.threads)
