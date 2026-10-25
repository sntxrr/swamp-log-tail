/**
 * Log tail — read the last lines of a log file, chosen by NAME from an
 * allowlist fixed in the model definition, with secret values redacted.
 *
 * It exists for an agent that triages alerts but has no shell. An alert says
 * "see example-job.log"; the cause is usually one line near the end of it.
 * Without this, the agent's answer is "please tail example-job.log for me".
 * With a general file-read tool, the agent can read anything the process can.
 * This sits between the two: the caller passes a name, never a path, and the
 * name → path map lives in the definition, where only its owner can change it.
 *
 * What it refuses, and why each refusal is a rule rather than a default:
 *
 * 1. **Paths as input.** `name` must be a key of the allowlist. It is matched
 *    with `Object.hasOwn`, so `__proto__` or `constructor` match nothing, and
 *    a name that is not even shaped like one is never echoed back: swamp's
 *    `--input name=@file` reads a file into the value, and an error message
 *    that quoted it would turn a refusal into a read.
 *
 * 2. **Symlinks, and paths that resolve elsewhere.** The configured path must
 *    be absolute and normalised, must not itself be a symlink, and must equal
 *    its own `realpath` — so a symlinked parent directory is refused too. The
 *    file is then opened and its device and inode compared with the `lstat`
 *    taken before the open, so swapping in a symlink between check and open
 *    is refused rather than followed. Only regular files are opened: a FIFO
 *    would block the read forever.
 *
 * 3. **Unbounded output.** At most 200 lines, each cut to `maxLineChars`, and
 *    at most `maxScanBytes` read from the end of the file.
 *
 * 4. **Secret values.** Redaction drops the value and keeps the name
 *    (`password=[REDACTED]`), so the line still says what was there. It fails
 *    closed three ways: a line that mentions a password manager CLI or a
 *    private key is withheld whole; a line that still looks like it carries a
 *    credential after redaction is withheld whole; and any error inside
 *    redaction fails the method, so nothing is returned rather than something
 *    unredacted.
 *
 * Both methods are read-only. Nothing here writes to, truncates or rotates a
 * log.
 */
import { z } from "npm:zod@4";

// ---------------------------------------------------------------------------
// Limits.
// ---------------------------------------------------------------------------

/** The most lines `tail` will ever return, whatever `lines` asks for. */
export const MAX_LINES = 200;

/** A line longer than this is withheld unread: too long to redact safely. */
export const MAX_RAW_LINE_BYTES = 64 * 1024;

/** The marker that replaces a redacted value. */
export const REDACTED = "[REDACTED]";

/** The shape every allowlisted name must have. */
export const NAME_RE = /^[a-z0-9][a-z0-9._-]{0,63}$/;

// ---------------------------------------------------------------------------
// Errors. A refusal is a thrown error, so the method fails and writes nothing.
// ---------------------------------------------------------------------------

/** Raised for every refusal, so callers and tests can tell one from a bug. */
export class RefusedError extends Error {
  /** @param message Why the read was refused. Never contains file content. */
  constructor(message: string) {
    super(message);
    this.name = "RefusedError";
  }
}

// ---------------------------------------------------------------------------
// Allowlist resolution and path checks.
// ---------------------------------------------------------------------------

/** One allowlisted log, as configured in the definition. */
export interface LogEntry {
  path: string;
  include?: string;
  description?: string;
}

/**
 * Resolve a caller-supplied name to its configured entry.
 *
 * The name is looked up, never interpreted: no path joining, no globbing, no
 * normalisation. A name that is not shaped like an allowlist key is refused
 * without being quoted, because swamp may have filled it from a file.
 */
export function resolveName(
  logs: Record<string, LogEntry>,
  name: unknown,
): LogEntry {
  const allowed = Object.keys(logs).sort().join(", ");
  if (typeof name !== "string" || !NAME_RE.test(name)) {
    throw new RefusedError(
      `unknown log name (not shown: it is not shaped like a log name); allowed: ${allowed}`,
    );
  }
  if (!Object.hasOwn(logs, name)) {
    throw new RefusedError(`unknown log name "${name}"; allowed: ${allowed}`);
  }
  return logs[name];
}

/**
 * Check a configured path is absolute and already in normal form.
 *
 * A path with `.`/`..` segments, doubled or trailing slashes, or a NUL is
 * refused rather than normalised: the allowlist should say exactly what it
 * reads, and the realpath check below compares strings.
 */
export function checkPathShape(path: string): void {
  if (!path.startsWith("/")) {
    throw new RefusedError("configured path is not absolute");
  }
  if (path.includes("\0")) {
    throw new RefusedError("configured path contains a NUL byte");
  }
  if (path.length > 1 && path.endsWith("/")) {
    throw new RefusedError("configured path ends in a slash");
  }
  const segments = path.split("/").slice(1);
  if (segments.some((s) => s === "" || s === "." || s === "..")) {
    throw new RefusedError(
      "configured path is not normalised (empty, '.' or '..' segment)",
    );
  }
}

/** File metadata kept from the open, for the result. */
export interface OpenedLog {
  file: Deno.FsFile;
  size: number;
  mtime: Date | null;
}

/**
 * Open an allowlisted path for reading, refusing anything that is not a
 * regular file at exactly that path.
 *
 * Order matters: `lstat` (not a symlink, a regular file), then `realPath`
 * (no symlinked parent), then open, then compare the open file's device and
 * inode with the `lstat`. A symlink swapped in after the checks changes the
 * inode the open lands on, and is refused.
 */
export async function openAllowlisted(path: string): Promise<OpenedLog> {
  checkPathShape(path);

  let before: Deno.FileInfo;
  try {
    before = await Deno.lstat(path);
  } catch (e) {
    if (e instanceof Deno.errors.NotFound) {
      throw new RefusedError("configured log file does not exist");
    }
    throw new RefusedError(
      `cannot stat configured log file: ${(e as Error).name}`,
    );
  }
  if (before.isSymlink) {
    throw new RefusedError("configured log file is a symlink; refusing");
  }
  if (!before.isFile) {
    throw new RefusedError("configured log file is not a regular file");
  }

  const real = await Deno.realPath(path);
  if (real !== path) {
    throw new RefusedError(
      "configured path resolves somewhere else (a symlinked directory?); configure the real path",
    );
  }

  const file = await Deno.open(path, { read: true });
  try {
    const after = await file.stat();
    if (
      before.ino === null || after.ino === null ||
      before.dev !== after.dev || before.ino !== after.ino
    ) {
      throw new RefusedError(
        "log file changed between check and open; refusing",
      );
    }
    if (!after.isFile) {
      throw new RefusedError("configured log file is not a regular file");
    }
    return { file, size: after.size, mtime: after.mtime };
  } catch (e) {
    file.close();
    throw e;
  }
}

// ---------------------------------------------------------------------------
// Reading the end of a file.
// ---------------------------------------------------------------------------

/** What `readTail` found. */
export interface TailRead {
  lines: string[];
  scannedBytes: number;
  reachedStart: boolean;
  /** True when the file holds earlier (matching) lines than those returned. */
  truncated: boolean;
}

/** Strip ANSI escape sequences and other C0 controls except tab. */
export function stripControls(line: string): string {
  return line
    // deno-lint-ignore no-control-regex
    .replace(/\x1b\[[0-9;?]*[ -/]*[@-~]/g, "")
    // deno-lint-ignore no-control-regex
    .replace(/\x1b\][^\x07\x1b]*(\x07|\x1b\\)/g, "")
    // deno-lint-ignore no-control-regex
    .replace(/[\x00-\x08\x0b-\x1f\x7f]/g, "");
}

/**
 * Return the last `count` lines of an open file (matching `include`, when
 * given), reading at most `maxScanBytes` from the end.
 *
 * Reads a growing window from the end rather than the whole file, so a
 * multi-megabyte log costs one small read in the common case. The first line
 * of a window that does not start at byte 0 is partial and is dropped.
 */
export async function readTail(
  file: Deno.FsFile,
  size: number,
  count: number,
  maxScanBytes: number,
  include?: RegExp,
): Promise<TailRead> {
  const limit = Math.min(size, maxScanBytes);
  let window = Math.min(limit, 64 * 1024);
  const decoder = new TextDecoder("utf-8", { fatal: false });

  while (true) {
    const start = size - window;
    const buf = new Uint8Array(window);
    await file.seek(start, Deno.SeekMode.Start);
    let filled = 0;
    while (filled < window) {
      const n = await file.read(buf.subarray(filled));
      if (n === null) break;
      filled += n;
    }
    const text = decoder.decode(buf.subarray(0, filled));
    let lines = text.split("\n");
    if (lines.length > 0 && lines[lines.length - 1] === "") lines.pop();
    const reachedStart = start === 0;
    if (!reachedStart) lines = lines.slice(1);
    lines = lines.map((l) => l.endsWith("\r") ? l.slice(0, -1) : l);
    if (include) lines = lines.filter((l) => include.test(stripControls(l)));

    if (lines.length >= count || window >= limit) {
      return {
        lines: lines.slice(-count),
        scannedBytes: filled,
        reachedStart,
        truncated: !reachedStart || lines.length > count,
      };
    }
    window = Math.min(limit, window * 4);
  }
}

// ---------------------------------------------------------------------------
// Redaction.
// ---------------------------------------------------------------------------

/**
 * Lines that are withheld whole, whatever else they say.
 *
 * Password-manager CLI output must never be returned, redacted or not: a
 * redaction regex fails open the first time a value's shape surprises it.
 * Private key material is the same — no part of it is useful in a triage.
 */
const WITHHOLD: Array<[RegExp, string]> = [
  [/\bop:\/\//i, "password manager reference"],
  [
    /\bop\s+(read|run|inject|signin|item|document|connect|whoami|vault)\b/i,
    "password manager CLI",
  ],
  [/1password|onepassword/i, "password manager"],
  [/\bOP_(SERVICE_ACCOUNT|CONNECT|SESSION)/i, "password manager variable"],
  [/\bops_[A-Za-z0-9]{8,}/, "password manager token"],
  [/-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----/, "private key"],
  [/PRIVATE KEY-----|-----END [A-Z0-9 ]*KEY-----/, "private key"],
];

/**
 * Credential shapes recognised anywhere in a line, with no name beside them.
 * Each is replaced by `[REDACTED]`; any left after redaction withholds the line.
 */
const TOKEN_SHAPES: RegExp[] = [
  /\bgh[pousr]_[A-Za-z0-9]{20,}/g,
  /\bgithub_pat_[A-Za-z0-9_]{20,}/g,
  /\bglpat-[A-Za-z0-9_-]{20,}/g,
  /\bsk-[A-Za-z0-9_-]{20,}/g,
  /\bxox[abposr]-[A-Za-z0-9-]{10,}/g,
  /\b(AKIA|ASIA)[0-9A-Z]{16}\b/g,
  /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}/g,
  /\bK00[0-9A-Za-z+/]{20,}/g,
];

/**
 * A long run of base64/url-safe characters that mixes upper case, lower case
 * and digits: the shape of most random secrets. Pure lower-case hex — commit
 * SHAs, image digests, UUIDs — has no upper case and is left alone, because
 * it is what a triage most often needs to see.
 */
const OPAQUE_RUN = /[A-Za-z0-9+/_-]{32,}={0,2}/g;

function looksOpaque(s: string): boolean {
  return /[A-Z]/.test(s) && /[a-z]/.test(s) && /[0-9]/.test(s);
}

/** Key names whose VALUE is a secret. The key itself is kept. */
const SECRET_KEY =
  /(pass(word|wd|phrase)|^pass$|^pwd$|secret|token(?!s\b)|api[_-]?key|apikey|access[_-]?key|private[_-]?key|credential|^auth$|authori[sz]ation|auth[_-]?(token|key|header)|session[_-]?(id|key|token)|^session$|cookie|signature|^sig$|bearer|^dsn$|webhook[_-]?url)/i;

/** True when a key name's value should be redacted. */
export function isSecretKey(key: string): boolean {
  return SECRET_KEY.test(key);
}

/** The result of redacting one line. */
export interface RedactedLine {
  text: string;
  redactions: number;
  withheld: string | null;
}

/**
 * Redact one line. Drops values, keeps names.
 *
 * Order: withhold checks; URL userinfo; Authorization / Bearer; CLI flags;
 * `key=value`, `key: value` and `"key": "value"` pairs with a secret-shaped
 * key; bare credential shapes; then a residual scan that withholds the line
 * if anything credential-shaped survived.
 */
export function redactLine(raw: string): RedactedLine {
  const line = stripControls(raw);
  for (const [re, why] of WITHHOLD) {
    if (re.test(line)) return { text: "", redactions: 0, withheld: why };
  }

  let n = 0;
  let out = line;

  // scheme://user:password@host -> scheme://user:[REDACTED]@host
  out = out.replace(
    /(\b[a-z][a-z0-9+.-]*:\/\/)([^\s:@/]*):([^\s@/]+)@/gi,
    (_m, scheme: string, user: string) => {
      n++;
      return `${scheme}${user}:${REDACTED}@`;
    },
  );

  // Authorization: Bearer xxx / Basic xxx, and a bare "Bearer xxx".
  out = out.replace(
    /\b(proxy-authorization|authorization)(["']?\s*[:=]\s*["']?)((?:bearer|basic|token|digest)\s+)?[^\s"',;]+/gi,
    (_m, key: string, sep: string, scheme: string | undefined) => {
      n++;
      return `${key}${sep}${scheme ?? ""}${REDACTED}`;
    },
  );
  out = out.replace(
    /\b(bearer|basic)\s+(?!\[REDACTED\])[A-Za-z0-9._~+/=-]{8,}/gi,
    (_m, scheme: string) => {
      n++;
      return `${scheme} ${REDACTED}`;
    },
  );

  // --password xyz, --api-token=xyz
  out = out.replace(
    /(\s|^)(--?[A-Za-z0-9][A-Za-z0-9_-]*)(=|\s+)(?!\[REDACTED\])("[^"]*"|'[^']*'|[^\s]+)/g,
    (m, lead: string, flag: string, sep: string) => {
      if (!isSecretKey(flag.replace(/^-+/, ""))) return m;
      n++;
      return `${lead}${flag}${sep}${REDACTED}`;
    },
  );

  // key=value, key: value, "key": "value", key="value"
  out = out.replace(
    /(["']?)([A-Za-z_][A-Za-z0-9_.-]{0,63})\1(\s*[:=]\s*)(?!\[REDACTED\])("(?:[^"\\]|\\.)*"|'[^']*'|[^\s,;&)}\]]+)/g,
    (
      m,
      q: string,
      key: string,
      sep: string,
      value: string,
      offset: number,
      whole: string,
    ) => {
      if (!isSecretKey(key)) return m;
      // "Authorization: Bearer [REDACTED]" was already handled above.
      if (
        /^(bearer|basic|token|digest)$/i.test(value) &&
        whole.startsWith(` ${REDACTED}`, offset + m.length)
      ) return m;
      if (value.startsWith("//")) return m; // a URL scheme, not a pair
      n++;
      const quoted = value.startsWith('"')
        ? `"${REDACTED}"`
        : value.startsWith("'")
        ? `'${REDACTED}'`
        : REDACTED;
      return `${q}${key}${q}${sep}${quoted}`;
    },
  );

  for (const re of TOKEN_SHAPES) {
    out = out.replace(re, () => {
      n++;
      return REDACTED;
    });
  }
  out = out.replace(OPAQUE_RUN, (m) => {
    if (!looksOpaque(m)) return m;
    n++;
    return REDACTED;
  });

  // Fail closed: anything still credential-shaped withholds the line.
  for (const re of TOKEN_SHAPES) {
    re.lastIndex = 0;
    if (re.test(out)) {
      re.lastIndex = 0;
      return { text: "", redactions: n, withheld: "credential survived" };
    }
  }
  for (const m of out.matchAll(OPAQUE_RUN)) {
    if (looksOpaque(m[0])) {
      return { text: "", redactions: n, withheld: "credential survived" };
    }
  }
  return { text: out, redactions: n, withheld: null };
}

/** The result of redacting a batch of lines. */
export interface RedactedBatch {
  lines: string[];
  redactions: number;
  withheld: number;
}

/**
 * Redact every line. A line over `MAX_RAW_LINE_BYTES` is withheld unread; a
 * redacted line is then cut to `maxLineChars`. Any exception propagates, so
 * the method fails and returns nothing.
 */
export function redactLines(
  lines: string[],
  maxLineChars: number,
): RedactedBatch {
  const out: string[] = [];
  let redactions = 0;
  let withheld = 0;
  for (const raw of lines) {
    if (raw.length > MAX_RAW_LINE_BYTES) {
      withheld++;
      out.push("[line withheld: too long to redact safely]");
      continue;
    }
    const r = redactLine(raw);
    redactions += r.redactions;
    if (r.withheld !== null) {
      withheld++;
      out.push(`[line withheld: ${r.withheld}]`);
      continue;
    }
    out.push(
      r.text.length > maxLineChars
        ? `${r.text.slice(0, maxLineChars)}…[cut]`
        : r.text,
    );
  }
  return { lines: out, redactions, withheld };
}

// ---------------------------------------------------------------------------
// Schemas.
// ---------------------------------------------------------------------------

const LogEntrySchema = z.object({
  path: z.string().min(2).describe(
    "Absolute, normalised path of the log file. Must be a regular file, not a symlink, and equal to its own realpath.",
  ),
  include: z.string().optional().describe(
    "Optional regex. When set, only lines matching it are returned — e.g. status lines of a chatty log. Matched against the line with ANSI escapes stripped.",
  ),
  description: z.string().optional().describe(
    "What the log is, for `list`. Shown to the caller.",
  ),
});

const GlobalArgsSchema = z.object({
  logs: z.record(z.string().regex(NAME_RE), LogEntrySchema).describe(
    "The allowlist: log name → entry. Names are what callers pass; paths never are.",
  ),
  maxScanBytes: z.number().int().min(4096).max(64 * 1024 * 1024).default(
    8 * 1024 * 1024,
  ).describe(
    "Read at most this many bytes from the end of a file. Bounds a filtered tail of a large log.",
  ),
  maxLineChars: z.number().int().min(80).max(8192).default(2000).describe(
    "Cut each returned line to this many characters, after redaction.",
  ),
});

/** Global arguments, as parsed. */
export type GlobalArgs = z.infer<typeof GlobalArgsSchema>;

const TailArgsSchema = z.object({
  name: z.string().describe("Allowlisted log name. Not a path."),
  lines: z.coerce.number().int().min(1).max(MAX_LINES).default(50).describe(
    `Lines to return, 1–${MAX_LINES}.`,
  ),
});

const TailSchema = z.object({
  name: z.string(),
  requestedLines: z.number(),
  lineCount: z.number(),
  lines: z.array(z.string()),
  filtered: z.boolean(),
  redactedValues: z.number(),
  withheldLines: z.number(),
  reachedStart: z.boolean(),
  truncated: z.boolean().describe(
    "True when the file holds earlier lines (matching `include`, if set) than those returned.",
  ),
  scannedBytes: z.number(),
  fileBytes: z.number(),
  modifiedAt: z.string().nullable(),
  timestamp: z.string(),
});

const ListSchema = z.object({
  logs: z.array(z.object({
    name: z.string(),
    description: z.string().nullable(),
    filtered: z.boolean(),
    readable: z.boolean(),
    problem: z.string().nullable(),
    fileBytes: z.number().nullable(),
    modifiedAt: z.string().nullable(),
  })),
  timestamp: z.string(),
});

/** The `tail` result. */
export type Tail = z.infer<typeof TailSchema>;

// ---------------------------------------------------------------------------
// The method bodies, separate from swamp's context so they can be tested.
// ---------------------------------------------------------------------------

/** Compile an entry's include filter, refusing one that does not compile. */
export function compileInclude(entry: LogEntry): RegExp | undefined {
  if (entry.include === undefined) return undefined;
  try {
    return new RegExp(entry.include);
  } catch {
    throw new RefusedError("configured include filter is not a valid regex");
  }
}

/** Tail one allowlisted log by name. */
export async function tailLog(
  g: GlobalArgs,
  name: unknown,
  lines: number,
): Promise<Tail> {
  const count = Math.max(1, Math.min(MAX_LINES, Math.trunc(lines)));
  const entry = resolveName(g.logs, name);
  const include = compileInclude(entry);
  const opened = await openAllowlisted(entry.path);
  let read: TailRead;
  try {
    read = await readTail(
      opened.file,
      opened.size,
      count,
      g.maxScanBytes,
      include,
    );
  } finally {
    opened.file.close();
  }
  const red = redactLines(read.lines, g.maxLineChars);
  return {
    name: name as string,
    requestedLines: count,
    lineCount: red.lines.length,
    lines: red.lines,
    filtered: include !== undefined,
    redactedValues: red.redactions,
    withheldLines: red.withheld,
    reachedStart: read.reachedStart,
    truncated: read.truncated,
    scannedBytes: read.scannedBytes,
    fileBytes: opened.size,
    modifiedAt: opened.mtime?.toISOString() ?? null,
    timestamp: new Date().toISOString(),
  };
}

/** Describe every allowlisted log without reading any content. */
export async function listLogs(
  g: GlobalArgs,
): Promise<z.infer<typeof ListSchema>> {
  const out = [];
  for (const name of Object.keys(g.logs).sort()) {
    const entry = g.logs[name];
    let readable = false;
    let problem: string | null = null;
    let fileBytes: number | null = null;
    let modifiedAt: string | null = null;
    try {
      compileInclude(entry);
      const opened = await openAllowlisted(entry.path);
      opened.file.close();
      readable = true;
      fileBytes = opened.size;
      modifiedAt = opened.mtime?.toISOString() ?? null;
    } catch (e) {
      problem = e instanceof RefusedError ? e.message : (e as Error).name;
    }
    out.push({
      name,
      description: entry.description ?? null,
      filtered: entry.include !== undefined,
      readable,
      problem,
      fileBytes,
      modifiedAt,
    });
  }
  return { logs: out, timestamp: new Date().toISOString() };
}

// ---------------------------------------------------------------------------
// The model.
// ---------------------------------------------------------------------------

interface Context {
  globalArgs: GlobalArgs;
  logger: { info: (msg: string, meta?: Record<string, unknown>) => void };
  writeResource: (
    resource: string,
    instance: string,
    attributes: unknown,
  ) => Promise<unknown>;
}

/**
 * The `@sntxrr/log-tail/allowlist` model: the last lines of a named log,
 * redacted, from a fixed allowlist.
 */
export const model = {
  type: "@sntxrr/log-tail/allowlist",
  description:
    "Read the last lines of a log chosen by NAME from an allowlist fixed in the definition — never by path — with secret values redacted and password-manager lines withheld. Built for an alert-triage agent with no shell.",
  version: "2026.10.25.1",
  upgrades: [
    {
      toVersion: "2026.10.25.1",
      description: "Version bump, no schema changes",
      upgradeAttributes: (old: Record<string, unknown>) => old,
    },
  ],
  globalArguments: GlobalArgsSchema,
  resources: {
    tail: {
      description:
        "The last lines of one allowlisted log, redacted, with counts of what was redacted or withheld.",
      schema: TailSchema,
      lifetime: "infinite" as const,
      garbageCollection: 10,
    },
    list: {
      description:
        "Every allowlisted name, whether it is readable now, its size and age. No content.",
      schema: ListSchema,
      lifetime: "infinite" as const,
      garbageCollection: 5,
    },
  },
  methods: {
    tail: {
      description:
        `Read-only. Return the last \`lines\` (1–${MAX_LINES}) lines of the allowlisted log \`name\`, with secret values redacted. Refuses unknown names, symlinks and paths that resolve elsewhere.`,
      arguments: TailArgsSchema,
      execute: async (
        args: z.infer<typeof TailArgsSchema>,
        context: Context,
      ): Promise<Tail> => {
        // The raw name is not logged: it is unvalidated until tailLog
        // resolves it, and `--input name=@file` can fill it from a file.
        context.logger.info("tail: reading up to {lines} lines", {
          lines: args.lines,
        });
        const result = await tailLog(context.globalArgs, args.name, args.lines);
        context.logger.info(
          "{name}: {count} lines, {redacted} values redacted, {withheld} lines withheld",
          {
            name: result.name,
            count: result.lineCount,
            redacted: result.redactedValues,
            withheld: result.withheldLines,
          },
        );
        await context.writeResource("tail", result.name, result);
        return result;
      },
    },
    list: {
      description:
        "Read-only. List the allowlisted log names, with whether each is readable now, its size and its last-modified time. Reads no content.",
      arguments: z.object({}),
      execute: async (
        _args: unknown,
        context: Context,
      ): Promise<z.infer<typeof ListSchema>> => {
        context.logger.info("list: checking {count} allowlisted logs", {
          count: Object.keys(context.globalArgs.logs).length,
        });
        const result = await listLogs(context.globalArgs);
        context.logger.info("{count} allowlisted logs", {
          count: result.logs.length,
        });
        await context.writeResource("list", "list", result);
        return result;
      },
    },
  },
};
