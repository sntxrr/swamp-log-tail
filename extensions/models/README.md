# @sntxrr/log-tail

Read the last lines of a log chosen **by name** from an allowlist fixed in the
model definition, with secret values redacted.

Built for an alert-triage agent that has no shell. An alert says "see
`example-job.log`"; the cause is usually one line near its end. Without this,
the agent's answer is "please tail it for me". With a general file-read tool,
it can read anything the process can. This sits between the two: the caller
passes a **name**, never a path, and the name → path map lives in the
definition, where only its owner can change it.

## Methods

| Method | Writes? | What it does                                                                 |
| ------ | ------- | ---------------------------------------------------------------------------- |
| `tail` | no      | Last `lines` (1–200, default 50) lines of log `name`, redacted               |
| `list` | no      | Every allowlisted name, whether it is readable now, size and mtime; no content |

## Definition

```yaml
type: "@sntxrr/log-tail/allowlist"
name: logs
globalArguments:
  logs:
    example-job:
      path: /var/log/example/example-job.log
      description: nightly example job wrapper log
    gateway:
      path: /var/log/example/gateway.log
      include: "(started|stopped|connected|disconnected|ERROR)"
      description: gateway status lines only
  maxScanBytes: 8388608 # read at most 8 MiB from the end of a file
  maxLineChars: 2000 # cut each returned line, after redaction
```

```bash
swamp model method run logs list
swamp model method run logs tail --input name=example-job --input lines=20
```

## What it refuses

- **A path as input.** `name` must be a key of `logs`, matched with
  `Object.hasOwn` — `../../etc/passwd`, `/etc/passwd`, `__proto__` and
  `constructor` are all "unknown log name". A value that is not shaped like a
  name is never echoed back: swamp's `--input name=@file` fills it from a file,
  and quoting it in the error would turn a refusal into a read.
- **Symlinks and paths that resolve elsewhere.** The configured path must be
  absolute and normalised, must not be a symlink, and must equal its own
  `realpath`, so a symlinked parent directory is refused too. After opening,
  the file's device and inode must match the `lstat` taken before the open, so
  a symlink swapped in between is refused rather than followed.
- **Anything that is not a regular file.** A FIFO would block the read forever.
- **Unbounded output.** At most 200 lines, each cut to `maxLineChars`, and at
  most `maxScanBytes` read from the end of the file.

## Redaction

Values are dropped and names kept, so a line still says what was there:

| In the log                              | Returned                                    |
| --------------------------------------- | ------------------------------------------- |
| `password=hunter2 user=alice`           | `password=[REDACTED] user=alice`            |
| `{"api_key": "abc123"}`                 | `{"api_key": "[REDACTED]"}`                 |
| `--api-token=abc`                       | `--api-token=[REDACTED]`                    |
| a URL whose userinfo is `app:hunter2`   | the same URL, userinfo `app:[REDACTED]`     |
| `Authorization: Bearer abc.def`         | `Authorization: Bearer [REDACTED]`          |
| a bare GitHub/GitLab/AWS/JWT-shaped token | `[REDACTED]`                              |

Lower-case hex — commit SHAs, image digests, UUIDs — is kept: a triage
usually needs it, and it has no upper case to look like a random secret.

It **fails closed**:

1. A line that mentions a password-manager CLI or reference (`op read`,
   `op://`, `1Password`, `OP_SERVICE_ACCOUNT_…`) or private key material is
   withheld whole, never redacted — a regex fails open the first time a
   value's shape surprises it.
2. A line still credential-shaped after redaction is withheld whole.
3. A line over 64 KiB is withheld unread.
4. Any error inside redaction fails the method, so nothing is returned rather
   than something unredacted.

Withheld lines appear as `[line withheld: <reason>]`, and the result counts
`redactedValues` and `withheldLines`.

## Running it for an agent

Run it on the host that holds the logs. A remote swamp serve reads its own
filesystem, not the caller's, so routing `tail` through serve would read the
wrong machine. Grant the agent `run` on this one model and its two methods,
nothing wider.

## License

MIT — see [LICENSE.md](LICENSE.md).
