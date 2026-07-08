## What this does

A short summary of the change and the issue class it addresses (if adding a rule,
name the rule ID and what it catches).

## Checklist

- [ ] `python -m unittest discover -s tests -v` passes
- [ ] The clean fixture (`tests/fixtures/clean/`) still reports zero findings
- [ ] New rules: added a triggering line to `tests/fixtures/vulnerable/` and an
      assertion in `tests/test_scanner.py`
- [ ] New rules: documented in the README rules table and `CHANGELOG.md`
- [ ] Dogfood self-scan is still clean (`python -m mcpscan .`)

## Related issue

Closes #
