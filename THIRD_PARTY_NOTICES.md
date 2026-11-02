# Third-party notices

`wechat4/scripts/Get-WeChat4ConfigKeys.ps1` adapts the read-only
`Config.Cipher` object traversal and XOR decoding from
[fanyuantaier/wechatauto-replica](https://github.com/fanyuantaier/wechatauto-replica),
`wechatauto/db.py` at commit
`bc2e6f2461330eb1a53996d2f2afc18416376b52`.

That project is licensed under Apache-2.0. Its license is included in
[third_party/wechatauto-replica/LICENSE](third_party/wechatauto-replica/LICENSE).
The adapter changes the implementation to PowerShell/C#, adds bounded scanning,
process selection, file-only key output and summary-only console output. Keep
this notice and the upstream license with redistributions of that adapter.

The repository's MIT license continues to cover its original code and notes;
it does not replace the upstream terms for the adapted portions.
