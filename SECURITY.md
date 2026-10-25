# Security

Only the latest release receives fixes. Report a suspected vulnerability using
[GitHub private vulnerability reporting](https://github.com/KanadeK/mtime-window-audit/security/advisories/new).
If that feature is unavailable, open an issue requesting a private contact
without including exploit details or private filenames. Do not upload personal
photos, file contents, tokens or a real directory inventory to a public issue.

Inputs are local and untrusted; the CLI does not contact a network or execute
input as code. Reports can reveal filenames. Run on stable trees or snapshots
with trusted ancestors. Restat checks detect common concurrent changes, but do
not provide an atomic snapshot or a hostile-filesystem security boundary.
