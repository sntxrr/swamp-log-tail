# swamp-log-tail

A [swamp](https://github.com/swamp-club/swamp) extension that lets an
alert-triage agent with no shell read the end of a log — chosen **by name**
from an allowlist fixed in the model definition, never by path — with secret
values redacted.

**The full documentation is
[`extensions/models/README.md`](extensions/models/README.md)**, which is also
what ships with the extension.

## Install

```bash
swamp extension pull @sntxrr/log-tail
```

## Development

```bash
cd extensions/models
deno check log_tail.ts log_tail_test.ts
deno lint log_tail.ts log_tail_test.ts
deno test --allow-read --allow-write --allow-run=mkfifo log_tail_test.ts
```

CI runs the same on every pull request.
