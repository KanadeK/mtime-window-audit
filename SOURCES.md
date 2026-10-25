# References

Retrieved 2026-10-25. Original implementation; no external source code copied.

- [rsync manual](https://github.com/RsyncProject/rsync/blob/master/rsync.1.md): quick size/mtime check, checksum option, FAT precision and modify-window guidance.
- [rclone global flags](https://rclone.org/flags/): checksum and timestamp tolerance controls.
- [CPython issue 157671](https://github.com/python/cpython/issues/157671): Windows path-stat versus descriptor-fstat ctime mismatch, reproduced locally. The implementation compares each API's ctime against itself, while checking identity/size/mtime across both APIs.

The tool's policies are defined independently and precisely in README.md; these
references establish the practical problem and alternatives, not a promise to
emulate all flags or backend behavior of either synchronization program.
