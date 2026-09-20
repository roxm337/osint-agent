# Example output

A real end-to-end run of the pipeline against
[`pentest-ground.com`](https://pentest-ground.com) — an intentionally-vulnerable,
publicly-authorized practice target maintained by Pentest-Tools.com.

Run in the default **passive** mode:

```bash
python orchestrator.py -t pentest-ground.com
```

Result: **113 assets, 64 relations, 20 findings** (5 critical, incl. exposed cloud
storage, unauthenticated WebLogic/MinIO, Redis CVEs, and DNS zone transfer), scored to
a max risk of **100/100**.

| File | Contents |
|---|---|
| `pentest-ground.com_report.md` | Full markdown investigation report |
| `pentest-ground.com_executive_summary.md` | Executive summary |
| `pentest-ground.com_findings.json` | Structured findings |
| `pentest-ground.com_summary.json` | Machine-readable run summary + asset inventory |

> Regenerated from persisted state; local paths scrubbed. Your own runs land in
> `reports/<target>/` (git-ignored).
