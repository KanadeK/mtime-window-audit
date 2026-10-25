"""Check all reachable commits, without changing any Git configuration."""

import subprocess

expected = "121669563+KanadeK@users.noreply.github.com"
commits = subprocess.check_output(
    ["git", "rev-list", "--all"], text=True, encoding="utf-8"
).splitlines()
if not commits:
    raise SystemExit("No commits to audit")
for commit in commits:
    fields = subprocess.check_output(
        ["git", "show", "-s", "--format=%an%x00%ae%x00%cn%x00%ce%x00%B", commit],
        text=True,
        encoding="utf-8",
    ).split("\0", 4)
    if fields[:4] != ["KanadeK", expected, "KanadeK", expected]:
        raise SystemExit(f"Unexpected identity in {commit}")
    if "co-authored-by:" in fields[4].lower():
        raise SystemExit(f"Unexpected co-author trailer in {commit}")
print(f"Identity verified for {len(commits)} commit(s): KanadeK")
