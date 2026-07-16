# Contributing to mcpscan

Thanks for helping make the MCP ecosystem safer! Contributions of all sizes are welcome —
new rules, fewer false positives, docs, fixtures. By participating, you're expected to
follow the [Code of Conduct](CODE_OF_CONDUCT.md).

## Getting started

```bash
git clone https://github.com/glatinone/mcpscan && cd mcpscan
pip install -e .
python -m unittest discover -s tests -v
```

No runtime dependencies, Python 3.9+. The test suite must stay green and the **clean
fixture must report zero findings** — false positives are treated as bugs.

## Adding a rule

Rules are small, self-contained classes. A new one is usually ~30 lines.

1. Create `mcpscan/rules/my_rule.py`:

   ```python
   from ..findings import Finding, Severity
   from ..loaders import FileInfo, by_kind
   from .base import Rule, register

   @register
   class MyRule(Rule):
       id = "MCP018"               # next free id, check `mcpscan --list-rules`
       name = "Short description"
       severity = Severity.MEDIUM
       owasp = "MCP05:2025"        # OWASP MCP Top 10 category id, or "" if none fits

       def check(self, files: list[FileInfo]) -> list[Finding]:
           out = []
           for f in by_kind(files, "source"):
               for i, line in enumerate(f.lines, start=1):
                   if "...": 
                       out.append(self.finding(f, i, line, detail="why + how to fix"))
           return out
   ```

   Pick `owasp` from the [mapping table in the README](README.md#-owasp-mcp-top-10-mapping);
   leave it `""` (the `Rule` default) if the finding genuinely doesn't fit any of the
   10 categories — don't force a mapping just to fill the field.

   If the finding has an unambiguous, mechanical fix (a value swap that can't change
   what the call does besides re-enabling the check), also override `fix_line()` — see
   `MCP009`/`MCP010` in `mcpscan/rules/` for examples. Most rules don't need this;
   leave the default `None` if the correct fix requires restructuring the call or
   choosing a replacement value.

2. Import it in `mcpscan/rules/__init__.py`.
3. Add a triggering line to `tests/fixtures/vulnerable/` and assert it fires in
   `tests/test_scanner.py`. Make sure the **clean** fixture still passes.
4. Document it in the README rules table (including its OWASP mapping) and `CHANGELOG.md`.

### Rule design principles

- **High signal.** Prefer precision over recall; a noisy rule gets disabled.
- **Explain & remediate.** Every finding's `detail` should say *why* and *how to fix*.
- **Severity by exploitability.** Reserve `CRITICAL` for direct RCE / secret exposure.
- **Be honest about confidence.** Use interpolation/context checks to avoid flagging
  obviously-safe literal usage.

## Commit & PR

- Keep commits focused; write a clear imperative summary.
- Run the suite before pushing.
- Open a PR describing the issue class and including a fixture demonstrating it.

By contributing you agree your work is licensed under the project's [MIT License](LICENSE).
