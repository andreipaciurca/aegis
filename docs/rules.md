# Writing aegis detection rules

## Table of Contents

- [Where the file goes](#where-the-file-goes)
- [Schema](#schema)
- [How conditions combine](#how-conditions-combine)
- [Worked examples](#worked-examples)
- [Testing a rule](#testing-a-rule)

aegis's scanner runs a small YARA-inspired rule engine
(`internal/rules/rules.go`) as one layer of its scan pipeline (see the
"How a scan works" diagram in the [README](../README.md#architecture)). Rules
ship built in, and you can add your own — or override a built-in one by
reusing its name — without recompiling aegis.

## Where the file goes

Create `rules.json` in aegis's config directory:

| OS | Path |
|----|------|
| macOS | `~/Library/Application Support/aegis/rules.json` |
| Linux | `~/.config/aegis/rules.json` |
| Windows | `%AppData%\aegis\rules.json` |

It's a JSON array of rule objects. aegis loads it on every run, merges it
with the built-in rules, and if a name collides your rule wins.

## Schema

```jsonc
[
  {
    "name": "my_company_backdoor_string",  // required, unique — reused name overrides a built-in
    "severity": "critical",                // "critical" | "warning" | "info"
    "desc": "shown in scan results as the reason a file was flagged",
    "match": "any",                        // "any" = one condition is enough; "all" (default) = every specified condition must hold
    "strings": ["evil.example.com/beacon"],// case-insensitive substrings looked up in a 64KB head of the file
    "hex": ["4d5a9000"],                   // hex byte sequences, spaces allowed ("4d 5a 90 00")
    "filename": "\\.(exe|scr)$",           // Go regexp, matched case-insensitively against the base filename
    "min_entropy": 7.4                     // 0-8 Shannon entropy; only meaningful with match:"all" alongside other conditions
  }
]
```

Every field except `name` is optional, but a rule needs at least one of
`strings`, `hex`, `filename`, or `min_entropy` to ever match anything.

## How conditions combine

- **`"match": "all"`** (the default) — every condition you specified must
  hold. Use this to pair a weak signal (entropy) with a stronger one
  (filename) so you don't flag every high-entropy file on disk.
- **`"match": "any"`** — a single condition firing is enough. Use this for a
  list of strings where any one of them is damning on its own (e.g.
  alternate spellings of the same IOC).

## Worked examples

**A known bad domain or IOC, exact match is enough:**

```json
{
  "name": "known_c2_domain",
  "severity": "critical",
  "desc": "known command-and-control domain from an internal threat feed",
  "match": "any",
  "strings": ["evil-c2.example", "backup-evil-c2.example"]
}
```

**A packed/obfuscated executable — require both a Windows binary extension
*and* high entropy, so ordinary compressed files elsewhere aren't flagged:**

```json
{
  "name": "custom_packer_signature",
  "severity": "warning",
  "desc": "high-entropy body with a known packer stub",
  "match": "all",
  "filename": "\\.(exe|dll)$",
  "hex": ["60e800000000"],
  "min_entropy": 7.0
}
```

**Silencing a built-in rule that's noisy in your environment** — give it the
same `name` and an impossible-to-match condition, or just a `min_entropy` of
`8.1` (entropy tops out at 8.0, so it never fires):

```json
{
  "name": "reverse_shell_python",
  "severity": "info",
  "desc": "disabled locally: false-positives on our test suite fixtures",
  "match": "all",
  "min_entropy": 8.1
}
```

## Testing a rule

```sh
aegis scan /path/to/a/file/that/should/match
```

`aegis scan --json` includes the matched rule's `desc` in each threat's
`reason` field, so you can confirm it fired without reading logs. Run
`aegis scan` against a folder of files that should **not** match, too — a
rule that's too broad is worse than a missing one, since false positives are
what erode trust in a security tool over time.

If you're contributing a rule back to the built-in set rather than keeping it
local, see [CONTRIBUTING.md](../CONTRIBUTING.md#adding-a-detection-rule).
