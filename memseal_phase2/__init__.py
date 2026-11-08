"""MemSeal Phase 2 — real-LLM measurement harness (local Ollama, offline, $0).

Phase 2 measures the Phase 1 deterministic policies (Envelope, W1-W5, recall
path, consolidation guard) under a real local LLM agent. It adds only harness /
adapter / runner / scorer code; the Phase 1 semantics are reused unchanged.
"""
