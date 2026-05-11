# SaaS / Identity Trust Chain Model

The SaaS identity trust-chain model is a read-only graph derived from imported configuration and evidence already present in a run.

It models:

- SaaS apps
- OAuth clients
- OAuth scopes
- service accounts
- connectors
- datasets

The model flags broad OAuth scopes and cross-system trust where imported evidence links a connector, service account, and reachable dataset.

## Safety Contract

The model does not use tokens, materialize credentials, call SaaS APIs, mutate SaaS configuration, simulate exfiltration, create tasks, dispatch runners, approve proposals, mutate scope, or modify runtime behavior.

Risk paths are evidence-backed only. If the imported evidence is incomplete, the model returns nodes and flags where possible but does not invent a complete path.
