import {
  assert,
  assertEquals,
  assertMatch,
  assertRejects,
  assertStringIncludes,
  assertThrows,
} from "jsr:@std/assert@1";
import {
  checkPathShape,
  type GlobalArgs,
  isSecretKey,
  listLogs,
  MAX_LINES,
  model,
  REDACTED,
  redactLine,
  redactLines,
  RefusedError,
  resolveName,
  tailLog,
} from "./log_tail.ts";

// --- fixtures ----------------------------------------------------------------
// Every fixture lives in a fresh temp dir, realpath'd first: on macOS the temp
// dir sits under /var, which is a symlink to /private/var, and the model
// (correctly) refuses any path that is not its own realpath.

async function tmpDir(): Promise<string> {
  return await Deno.realPath(await Deno.makeTempDir({ prefix: "log-tail-" }));
}

function numbered(n: number): string {
  return Array.from({ length: n }, (_, i) => `line ${i + 1}`).join("\n") + "\n";
}

function args(logs: GlobalArgs["logs"]): GlobalArgs {
  return { logs, maxScanBytes: 8 * 1024 * 1024, maxLineChars: 2000 };
}

// --- unknown names and path traversal ---------------------------------------

Deno.test("an unknown name is refused and the allowlist is named", () => {
  const logs = { "example-job": { path: "/var/log/example-job.log" } };
  const e = assertThrows(
    () => resolveName(logs, "other-job"),
    RefusedError,
  );
  assertStringIncludes(e.message, 'unknown log name "other-job"');
  assertStringIncludes(e.message, "allowed: example-job");
});

Deno.test("a traversal name is refused as an unknown name, never joined to a path", () => {
  const logs = { "example-job": { path: "/var/log/example-job.log" } };
  for (
    const name of [
      "../../etc/passwd",
      "/etc/passwd",
      "example-job/../../etc/passwd",
      "..",
      "example-job/",
      "./example-job",
    ]
  ) {
    const e = assertThrows(() => resolveName(logs, name), RefusedError);
    assertStringIncludes(e.message, "unknown log name");
    assert(!e.message.includes("passwd"), `echoed ${name}`);
  }
});

Deno.test("a name that is not name-shaped is never echoed (it may be file content)", () => {
  // swamp's `--input name=@/some/file` fills the value from the file.
  const logs = { "example-job": { path: "/var/log/example-job.log" } };
  const content = "root:x:0:0:root:/root:/bin/bash\nsecret stuff";
  const e = assertThrows(() => resolveName(logs, content), RefusedError);
  assert(!e.message.includes("root:x"));
  assert(!e.message.includes("secret stuff"));
});

Deno.test("prototype keys are not allowlist entries", () => {
  const logs = { "example-job": { path: "/var/log/example-job.log" } };
  for (
    const name of ["constructor", "__proto__", "tostring", "hasownproperty"]
  ) {
    assertThrows(() => resolveName(logs, name), RefusedError);
  }
});

Deno.test("a non-string name is refused", () => {
  const logs = { "example-job": { path: "/var/log/example-job.log" } };
  assertThrows(() => resolveName(logs, 42), RefusedError);
  assertThrows(() => resolveName(logs, undefined), RefusedError);
});

Deno.test("configured paths must be absolute and normalised", () => {
  checkPathShape("/var/log/example-job.log");
  for (
    const p of [
      "var/log/x.log",
      "/var/log/../../etc/passwd",
      "/var/./log/x.log",
      "/var//log/x.log",
      "/var/log/",
      "/var/log/x\0.log",
    ]
  ) {
    assertThrows(() => checkPathShape(p), RefusedError, undefined, p);
  }
});

Deno.test("tailLog refuses a traversal name end to end", async () => {
  const dir = await tmpDir();
  await Deno.writeTextFile(`${dir}/example-job.log`, numbered(5));
  await assertRejects(
    () =>
      tailLog(
        args({ "example-job": { path: `${dir}/example-job.log` } }),
        "../../etc/passwd",
        20,
      ),
    RefusedError,
    "unknown log name",
  );
});

// --- symlink escape ----------------------------------------------------------

Deno.test("a configured path that is a symlink is refused, not followed", async () => {
  const dir = await tmpDir();
  await Deno.writeTextFile(`${dir}/outside.txt`, "do-not-read-me\n");
  await Deno.symlink(`${dir}/outside.txt`, `${dir}/example-job.log`);
  await assertRejects(
    () =>
      tailLog(
        args({ "example-job": { path: `${dir}/example-job.log` } }),
        "example-job",
        10,
      ),
    RefusedError,
    "symlink",
  );
});

Deno.test("a path under a symlinked directory is refused", async () => {
  const dir = await tmpDir();
  await Deno.mkdir(`${dir}/real`);
  await Deno.writeTextFile(`${dir}/real/example-job.log`, numbered(3));
  await Deno.symlink(`${dir}/real`, `${dir}/linked`);
  await assertRejects(
    () =>
      tailLog(
        args({ "example-job": { path: `${dir}/linked/example-job.log` } }),
        "example-job",
        10,
      ),
    RefusedError,
    "resolves somewhere else",
  );
});

Deno.test("a symlink pointing outside the allowlist does not leak its target in list", async () => {
  const dir = await tmpDir();
  await Deno.writeTextFile(`${dir}/outside.txt`, "do-not-read-me\n");
  await Deno.symlink(`${dir}/outside.txt`, `${dir}/example-job.log`);
  const r = await listLogs(
    args({ "example-job": { path: `${dir}/example-job.log` } }),
  );
  assertEquals(r.logs[0].readable, false);
  assertStringIncludes(r.logs[0].problem ?? "", "symlink");
  assertEquals(r.logs[0].fileBytes, null);
});

Deno.test("a directory or FIFO is refused, never opened", async () => {
  const dir = await tmpDir();
  await Deno.mkdir(`${dir}/example-job.log`);
  await assertRejects(
    () =>
      tailLog(
        args({ "example-job": { path: `${dir}/example-job.log` } }),
        "example-job",
        10,
      ),
    RefusedError,
    "not a regular file",
  );
  const fifo = new Deno.Command("mkfifo", { args: [`${dir}/pipe.log`] });
  if ((await fifo.output()).success) {
    await assertRejects(
      () =>
        tailLog(
          args({ "pipe": { path: `${dir}/pipe.log` } }),
          "pipe",
          10,
        ),
      RefusedError,
      "not a regular file",
    );
  }
});

Deno.test("a missing file is refused with a clear reason", async () => {
  const dir = await tmpDir();
  await assertRejects(
    () =>
      tailLog(
        args({ "example-job": { path: `${dir}/nope.log` } }),
        "example-job",
        10,
      ),
    RefusedError,
    "does not exist",
  );
});

// --- reading -----------------------------------------------------------------

Deno.test("tail returns exactly the last N lines", async () => {
  const dir = await tmpDir();
  await Deno.writeTextFile(`${dir}/example-job.log`, numbered(500));
  const r = await tailLog(
    args({ "example-job": { path: `${dir}/example-job.log` } }),
    "example-job",
    20,
  );
  assertEquals(r.lineCount, 20);
  assertEquals(r.lines[0], "line 481");
  assertEquals(r.lines[19], "line 500");
});

Deno.test(`lines are capped at ${MAX_LINES}`, async () => {
  const dir = await tmpDir();
  await Deno.writeTextFile(`${dir}/example-job.log`, numbered(1000));
  const r = await tailLog(
    args({ "example-job": { path: `${dir}/example-job.log` } }),
    "example-job",
    5000,
  );
  assertEquals(r.lineCount, MAX_LINES);
  assertEquals(r.requestedLines, MAX_LINES);
  assertEquals(r.lines.at(-1), "line 1000");
  assertEquals(r.truncated, true);
});

Deno.test("the method's argument schema rejects lines over the cap", () => {
  const schema = model.methods.tail.arguments;
  assertEquals(schema.safeParse({ name: "x", lines: 201 }).success, false);
  assertEquals(schema.safeParse({ name: "x", lines: 0 }).success, false);
  assertEquals(schema.parse({ name: "x", lines: "20" }).lines, 20);
  assertEquals(schema.parse({ name: "x" }).lines, 50);
});

Deno.test("a short file returns what it has and says it reached the start", async () => {
  const dir = await tmpDir();
  await Deno.writeTextFile(`${dir}/example-job.log`, "only\ntwo");
  const r = await tailLog(
    args({ "example-job": { path: `${dir}/example-job.log` } }),
    "example-job",
    50,
  );
  assertEquals(r.lines, ["only", "two"]);
  assertEquals(r.reachedStart, true);
  assertEquals(r.truncated, false);
});

Deno.test("a large file is read from the end, not whole", async () => {
  const dir = await tmpDir();
  await Deno.writeTextFile(`${dir}/example-job.log`, numbered(200_000));
  const r = await tailLog(
    args({ "example-job": { path: `${dir}/example-job.log` } }),
    "example-job",
    10,
  );
  assertEquals(r.lines.at(-1), "line 200000");
  assertEquals(r.reachedStart, false);
  assert(r.scannedBytes <= 64 * 1024, `scanned ${r.scannedBytes}`);
});

Deno.test("include keeps only matching lines, the last N of them", async () => {
  const dir = await tmpDir();
  const body = Array.from(
    { length: 300 },
    (_, i) => i % 10 === 0 ? `STATUS ok ${i}` : `chatter ${i}`,
  ).join("\n");
  await Deno.writeTextFile(`${dir}/gateway.log`, body + "\n");
  const r = await tailLog(
    args({ gateway: { path: `${dir}/gateway.log`, include: "^STATUS " } }),
    "gateway",
    3,
  );
  assertEquals(r.lines, ["STATUS ok 270", "STATUS ok 280", "STATUS ok 290"]);
  assertEquals(r.filtered, true);
});

Deno.test("an invalid include regex is refused, not ignored", async () => {
  const dir = await tmpDir();
  await Deno.writeTextFile(`${dir}/gateway.log`, "x\n");
  await assertRejects(
    () =>
      tailLog(
        args({ gateway: { path: `${dir}/gateway.log`, include: "(" } }),
        "gateway",
        3,
      ),
    RefusedError,
    "not a valid regex",
  );
});

Deno.test("list reports names, readability and size, never content", async () => {
  const dir = await tmpDir();
  await Deno.writeTextFile(`${dir}/a.log`, "password=hunter2\n");
  const r = await listLogs(
    args({
      "a": { path: `${dir}/a.log`, description: "job a" },
      "b": { path: `${dir}/missing.log` },
    }),
  );
  assertEquals(r.logs.map((l) => l.name), ["a", "b"]);
  assertEquals(r.logs[0].readable, true);
  assertEquals(r.logs[0].fileBytes, 17);
  assertEquals(r.logs[1].readable, false);
  assert(!JSON.stringify(r).includes("hunter2"));
});

// --- redaction: values dropped, names kept -----------------------------------

Deno.test("key=value keeps the key and drops the value", () => {
  const r = redactLine("connecting with password=hunter2 user=alice");
  assertEquals(r.text, `connecting with password=${REDACTED} user=alice`);
  assertEquals(r.redactions, 1);
});

Deno.test("JSON pairs keep the key and the quotes", () => {
  const r = redactLine('{"api_key": "abc123", "region": "example-1"}');
  assertEquals(r.text, `{"api_key": "${REDACTED}", "region": "example-1"}`);
});

Deno.test("YAML-ish and env-style pairs are redacted", () => {
  assertEquals(
    redactLine("  client_secret: s3cr3t-value").text,
    `  client_secret: ${REDACTED}`,
  );
  assertEquals(
    redactLine("EXAMPLE_API_TOKEN=abcdef").text,
    `EXAMPLE_API_TOKEN=${REDACTED}`,
  );
  assertEquals(
    redactLine("session_id=xyz; path=/").text,
    `session_id=${REDACTED}; path=/`,
  );
});

Deno.test("CLI flags keep the flag and drop the value", () => {
  assertEquals(
    redactLine("run tool --password hunter2 --verbose").text,
    `run tool --password ${REDACTED} --verbose`,
  );
  assertEquals(
    redactLine("run tool --api-token=abc").text,
    `run tool --api-token=${REDACTED}`,
  );
});

Deno.test("URL userinfo keeps the user and drops the password", () => {
  assertEquals(
    redactLine("dial postgres://app:hunter2@db.example.com:5432/app").text,
    `dial postgres://app:${REDACTED}@db.example.com:5432/app`,
  );
});

Deno.test("Authorization and Bearer keep the scheme and drop the credential", () => {
  assertEquals(
    redactLine("Authorization: Bearer abc.def.ghi-jklmnop").text.includes(
      "abc.def",
    ),
    false,
  );
  assertMatch(
    redactLine("Authorization: Bearer abc.def.ghi-jklmnop").text,
    /^Authorization: Bearer \[REDACTED\]/,
  );
  assertEquals(
    redactLine("sent header bearer abcdefgh12345678").text,
    `sent header bearer ${REDACTED}`,
  );
});

Deno.test("bare credential shapes are redacted with no key beside them", () => {
  const samples = [
    "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4",
    "github_pat_" + "11ABCDEFG0123456789_abcdefghij",
    "glpat-" + "abcdefghij0123456789",
    "sk-" + "ant-abcdefghij0123456789ABC",
    "xoxb-" + "1234567890-abcdefghij",
    "AKIA" + "ABCDEFGHIJKLMNOP",
    // Assembled from parts so secret scanners do not flag the fixture itself.
    ["eyJhbGciOiJIUzI1NiJ9", "eyJzdWIiOiJleGFtcGxlIn0", "c2lnbmF0dXJlLXZhbHVl"]
      .join("."),
    "Zm9vYmFyQmF6UXV4MTIzNDU2Nzg5MEFCQ0RFRkdISUo",
  ];
  for (const s of samples) {
    const r = redactLine(`saw ${s} in output`);
    assertEquals(r.withheld, null, s);
    assertEquals(r.text, `saw ${REDACTED} in output`, s);
  }
});

Deno.test("hex digests, commit SHAs and UUIDs survive: a triage needs them", () => {
  const line =
    "pulled sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08 at 3f2a9c1e7b4d5a6f8e9d0c1b2a3f4e5d6c7b8a9f id 123e4567-e89b-12d3-a456-426614174000";
  const r = redactLine(line);
  assertEquals(r.text, line);
  assertEquals(r.redactions, 0);
});

Deno.test("ordinary log words that merely contain secret-ish stems survive", () => {
  for (
    const line of [
      "tests passed: 12",
      "input_tokens: 1234 output_tokens: 56",
      "status=ok host=example-host duration=1.2s",
      "Bind for :::9091 failed: port is already allocated",
      "https://example.com/path?q=1",
    ]
  ) {
    assertEquals(redactLine(line).text, line, line);
  }
});

// --- redaction: fails closed --------------------------------------------------

Deno.test("password-manager lines are withheld whole, never redacted", () => {
  for (
    const line of [
      "reading op://Example-Vault/example-item/credential",
      "+ op read --no-newline something",
      "[ERROR] 1Password CLI: session expired",
      "OP_SERVICE_ACCOUNT_TOKEN is set",
      "token ops_eyJhbGciOiJFUzI1NiIsImtpZCI6",
    ]
  ) {
    const r = redactLine(line);
    assert(r.withheld !== null, line);
    assertEquals(r.text, "");
  }
});

Deno.test("private key material is withheld whole", () => {
  for (
    const line of [
      // Assembled from parts so secret scanners do not flag the fixture.
      ["-----BEGIN OPENSSH", "PRIVATE KEY-----"].join(" "),
      ["-----BEGIN RSA", "PRIVATE KEY-----"].join(" "),
      ["-----END OPENSSH", "PRIVATE KEY-----"].join(" "),
    ]
  ) {
    assert(redactLine(line).withheld !== null, line);
  }
  // A body line of a key whose BEGIN fell outside the window is still caught.
  const body =
    "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW";
  const r = redactLine(body);
  assert(r.withheld !== null || !r.text.includes("b3BlbnNzaC1"));
});

Deno.test("redactLines marks withheld lines and cuts long ones after redaction", () => {
  const r = redactLines(
    [
      "fine",
      "op read op://x/y/z",
      "token=abc " + "x".repeat(3000),
      "y".repeat(70 * 1024),
    ],
    100,
  );
  assertEquals(r.lines[0], "fine");
  assertStringIncludes(r.lines[1], "[line withheld:");
  assert(r.lines[2].startsWith(`token=${REDACTED} `));
  assert(r.lines[2].endsWith("…[cut]"));
  assertStringIncludes(r.lines[3], "too long");
  assertEquals(r.withheld, 2);
});

Deno.test("ANSI escapes cannot split a secret past the redactor", () => {
  const r = redactLine("password=\x1b[31mhunter2\x1b[0m");
  assertEquals(r.text, `password=${REDACTED}`);
});

Deno.test("isSecretKey matches secret-ish names and not their look-alikes", () => {
  for (
    const k of [
      "password",
      "DB_PASSWORD",
      "passwd",
      "api_key",
      "apiKey",
      "client_secret",
      "access_token",
      "Authorization",
      "cookie",
    ]
  ) {
    assert(isSecretKey(k), k);
  }
  for (const k of ["passed", "input_tokens", "status", "host", "author"]) {
    assert(!isSecretKey(k), k);
  }
});

Deno.test("redaction runs on file content end to end", async () => {
  const dir = await tmpDir();
  await Deno.writeTextFile(
    `${dir}/example-job.log`,
    [
      "starting",
      "auth ok with api_key=abc123def",
      "op read op://Example-Vault/item/field",
      "done",
    ].join("\n") + "\n",
  );
  const r = await tailLog(
    args({ "example-job": { path: `${dir}/example-job.log` } }),
    "example-job",
    10,
  );
  assertEquals(r.lines[1], `auth ok with api_key=${REDACTED}`);
  assertStringIncludes(r.lines[2], "[line withheld:");
  assertEquals(r.redactedValues, 1);
  assertEquals(r.withheldLines, 1);
  assert(!JSON.stringify(r).includes("abc123def"));
  assert(!JSON.stringify(r).includes("Example-Vault"));
});
