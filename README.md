# tsdft-ed-url-monitor

Monitors a list of URLs and files for content changes and files a GitHub Issue when a change is detected.

What it does
- Periodically fetches each URL in `sites.txt` (supports HTML pages and PDFs).
- Normalises content to plain text, computes a hash, and detects differences from the last run.
- When a change is found, creates a GitHub Issue containing a clipped unified diff of the changes. If issue creation fails the diff is saved locally to `diffs/`.

Repo usage notes (GitHub-first)
- This project is intended to run on GitHub Actions only. Collaborators should edit `sites.txt` to add/remove monitored URLs.
- To be notified by email or mention, add your GitHub username to the workflow `.github/workflows/monthly.yml` as the mention value (the workflow exposes `GITHUB_ISSUE_MENTION`).
- No further setup is required for collaborators beyond editing those two files in the repo.

Quick facts
- Schedule: the Action runs monthly (see `.github/workflows/monthly.yml`).
- Diff storage: primary — GitHub Issues; fallback — `diffs/` directory.
- State file: `site_state.json` stores per-site hashes between runs.
- Dependencies: see `requirements.txt`.

Troubleshooting
- If issues are saved to `diffs/` instead of created, check the Action logs for API errors and ensure the repo has Issues enabled and the workflow has `issues: write` permission.
- If a site is slow or times out, increase the `MONITOR_TIMEOUT` environment variable in the workflow.

If you want, I can: add an example `sites.txt`, add a simple unit test for `load_sites()`, or add a lint step to CI. Tell me which and I'll implement it.