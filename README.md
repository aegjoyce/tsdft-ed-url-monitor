# TSDFT ED Website Monitor

This simple tool watches websites for changes and lets the team know when something changes.

How it works (very simply)
- A list of websites is kept in `sites.txt`.
- Each month the script checks those sites for any changes.
- If something has changed, the script opens a GitHub Issue describing the change so people get notified.

What you need to do
- To add or remove a site: edit `sites.txt` in this repository and add one website address per line (copy the full web address including `https://`).
- To get personally notified: open `.github/workflows/monthly.yml` and add your GitHub username to the `GITHUB_ISSUE_MENTION` field.

Where it runs
- This runs automatically on GitHub once a month. No local setup is required.

If something goes wrong
- If an issue is not created the change is still saved in the `diffs/` folder so someone can look at it.
- If you need help editing files or getting notifications, open an Issue in this repo and someone will help.

That's it — simple: add a site, add yourself to the workflow to get mentioned, and the monitor will do the rest.