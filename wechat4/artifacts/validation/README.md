# Validation Artifacts

Only sanitized validation summaries belong here.

Do not place any real database, key material, chat export, contact export, screenshot, or debugger log in this directory.

`example-summary.json` is a redacted aggregate result from an authorized local run. It contains counts and selected cipher metadata only. It contains no paths, identifiers, keys, messages, contacts, or schema rows.

## WeChat 4.2 validation

[wechat-4.2-summary.json](wechat-4.2-summary.json) records anonymous aggregate
results for the validated 4.2.0.12 artifact, the multi-key offline export,
selected-group checks and synthetic tests. No account identifiers or keys are
included. The final adapter passed a synthetic Windows capture test; its
traversal was validated against the client during the preceding local export.

The older example summary is historical. Its compatibility label came from
compatibility-before-key probing and should not be treated as definitive
evidence of effective cipher settings. See
[the migration notes](../../reverse/analysis/WECHAT_4_2.md).
