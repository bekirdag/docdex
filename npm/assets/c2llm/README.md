# Experimental C2LLM code retrieval

C2LLM-0.5B is worth a controlled retrieval trial, not an automatic replacement for Nomic. This experiment uses an independent code-vector database and the existing Docdex AST, file-open and Tantivy APIs. It does not alter repository memory, profile memory, documentation embeddings, delegation, or normal HTTP/MCP search behavior.

The [official model](https://huggingface.co/codefuse-ai/C2LLM-0.5B) uses custom PMA pooling and 896-dimensional embeddings. [CoREB v202602](https://hq-bench.github.io/coreb-page/) reports overall query-weighted nDCG@10 of 0.625 versus 0.508 for Qwen3-Embedding-0.6B. That comparison is neither a coding-performance result nor an evaluation against Docdex's Nomic model. Do not mix the February and March benchmark versions.

## Runtime and isolation

The adapter pins model revision `bd6d0ddb29f0c9a3d0f14281aedc9f940bb8d67a` and records source hashes. Its copied inference module omits two unused training imports and fixes upstream CPU backend detection. The model's PMA pooling is preserved. Inference reads the last Qwen hidden state directly, avoiding unnecessary vocabulary logits and retained intermediate layers.

The service is CPU-only for this trial. It binds only to loopback, admits one inference request, rejects concurrent requests with 503, accepts at most four inputs, limits inputs to 512 tokens and caches at most 256 vectors. Run it in a separate memory-limited unit: model weights must not be charged to Docdex's 6/8 GiB service. Do not displace Raijin's occupied GPU workloads to enable it.

A tested isolated Python environment uses `torch==2.9.1+cpu`, `transformers==4.57.6`, and NumPy. Install the Torch wheel from the official CPU index; these are optional experiment dependencies, not new daemon dependencies.

```sh
python3 -m venv /path/to/c2llm-venv
/path/to/c2llm-venv/bin/pip install torch==2.9.1+cpu --index-url https://download.pytorch.org/whl/cpu
/path/to/c2llm-venv/bin/pip install transformers==4.57.6 numpy
/path/to/c2llm-venv/bin/python c2llm_service.py prepare --directory /path/to/new-model-directory
systemd-run --user --unit=docdex-code-embeddings \
  -p MemoryHigh=4G -p MemoryMax=6G -p CPUQuota=200% \
  /path/to/c2llm-venv/bin/python /absolute/docdex/c2llm_service.py \
  serve --directory /path/to/new-model-directory
```

`GET http://127.0.0.1:28521/healthz` reports the model revision, dimension, token bound and cache counters. `/v1/embeddings` accepts the OpenAI-compatible model/input shape. Local source text is not sent to a hosted embedding provider.

## Explicit code index and hybrid search

```sh
python3 c2llm_retrieval.py index \
  --repo /absolute/repository --index /separate/state/code-c2llm.sqlite \
  --paths src/auth.rs src/session.rs
python3 c2llm_retrieval.py search \
  --repo /absolute/repository --index /separate/state/code-c2llm.sqlite \
  --query 'reject expired authentication tokens'
```

The explicit path list is the complete corpus for this experimental index. Builds use Docdex symbol ranges, split large definitions, reuse embeddings by content hash, exclude removed chunks, and commit atomically. A per-index lock rejects concurrent duplicate builds. The database records the repository identity and model/chunker fingerprint; incompatible databases are rejected instead of silently mixed or deleted. It caps coverage at 1,024 chunks (3.5 MiB of float32 vectors) and reports truncation. This intentionally small exact-search experiment is not a production ANN implementation.

Search combines semantic and Tantivy file ranks with reciprocal-rank fusion, deduplicates paths, and returns the supporting semantic chunk ranges. Changed/deleted files are excluded from semantic results until the explicit code index is refreshed; current Tantivy results remain available. No automatic full-repository embedding jobs run inside Docdex.

Before enabling a native/default retrieval lane, require a representative, independently labeled multi-repository A/B evaluation against Nomic and Tantivy, measured recall/ranking gains, acceptable cold/warm latency, model-service memory headroom, and bounded index/cache behavior at production corpus sizes. Keep delegation on the mswarm load balancer using `qwen-latest-flash-next`, with local enforcement and no paid/primary fallback.

## Raijin trial (2026-11-06)

An exploratory test used 18 AST-selected Docdex functions and six author-labeled natural-language queries. Both models achieved recall@5 = 1.0. Nomic scored MRR@10 0.764 / nDCG@10 0.822; C2LLM scored 0.708 / 0.782. Median query embedding latency was 4.5 ms for the current Nomic service and 91.5 ms for C2LLM on two CPU threads. The C2LLM service used approximately 1.23 GB cgroup memory. This is a small single-repository sample, not a statistically meaningful general model ranking; the backends also use different hardware.

Decision: retain Nomic and normal Docdex retrieval defaults. Include this opt-in adapter and evaluation path for further experiments, but do not promote C2LLM to a native/default retrieval lane on the strength of the published aggregate benchmark. Representative multi-repository improvements have not been demonstrated.

For an npm global installation, these experimental scripts are under `$(npm root -g)/docdex/assets/c2llm`. Run them from that directory or use absolute script paths. Python model dependencies are optional and are not installed by npm.
