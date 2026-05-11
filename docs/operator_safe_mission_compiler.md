# Operator-Safe AI Mission Compiler

The operator-safe mission compiler turns natural-language intent into a bounded mission plan JSON object.

It records:

- exact scope and scope gaps
- ROE and authorization requirements
- allowed planning capabilities
- explicit forbidden capabilities
- required approvals before runtime
- safe validation language

Unsafe runtime wording such as exploit, payload, shell, bypass, or brute force is converted into safe evidence-review and approval-gated validation language. Destructive or exfiltration intent is rejected.

## Safety Contract

The compiler does not execute work, create tasks, dispatch runners, approve proposals, generate exploits or payloads, mutate scope, materialize secrets, use credentials, or modify runtime behavior.
