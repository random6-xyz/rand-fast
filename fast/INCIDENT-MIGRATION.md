# Incident output migration

The daemon now requires a trusted output path because it deletes old incident
bundles during rotation. The output directory must be owned by the daemon's
effective user and must not be writable by group or others. Each ancestor must
be owned by root or that user, and must not be group/other-writable unless it
is a sticky directory such as `/tmp`. Symlink path components are rejected.
The daemon creates missing directories with mode `0700`; it does not change the
ownership or permissions of existing directories. The effective user and root
are trusted, including other processes running under that user.

## Choose an output path

- With effective UID 0, the default is `/var/lib/rand-fast/incidents`, regardless
  of the current directory, `HOME`, or `SUDO_USER`. For example, an operator can
  run `sudo fast daemon --pid PID` from their normal home directory without
  specifying `--output`.
- Otherwise, the default is `$HOME/.local/state/rand-fast/incidents` when `HOME`
  is absolute. If `HOME` is missing or relative, the default is
  `/tmp/rand-fast-UID/incidents`, where `UID` is the effective numeric UID.
  `/tmp` can be cleared by the system and another user could pre-create the
  name to deny service; the daemon rejects a directory owned by that user.
- `--output /absolute/trusted/path` selects another location. Every component
  must satisfy the rules above. In particular, a root daemon must not use a
  path under a normal user's home directory, even if the final directory is
  owned by root. Use a root-owned location outside that home instead. A
  non-root daemon can use its own home when its components satisfy the rules.

If startup reports `unsafe incident output`, check the path components' owners,
permissions and symlinks. Choose a new trusted path or ask the administrator to
prepare one; do not recursively change ownership or permissions of a directory
that other users can modify. Existing group-writable home state directories may
also require choosing a different trusted `--output` location.

## Existing installations

The previous default was `./incidents`. Leave that directory in place as an
archive and start the upgraded daemon with its new default or an explicitly
chosen trusted output. This avoids changing or deleting anyone else's data.
The new output starts with an empty rolling history; inspect the archived
bundles separately when older history is needed. In particular, do not point a
root daemon at a user-owned legacy directory or recursively `chown` it.

If an existing output already meets the trust rules, it can still be selected
with `--output`. The daemon can restore a complete legacy bundle from a trusted
bundle directory, but it never automatically deletes legacy bundles without its
ownership marker. Legacy and unrelated regular files count toward the byte cap;
they are preserved even when that leaves the output above the cap. Manually
archive or remove those files only after verifying their ownership and contents.
Do not copy untrusted ownership markers into a trusted output: a marker in that
trust boundary identifies a bundle as eligible for deletion.

The cap is checked after writing an incident. The newest incident is retained.
If a directory cannot be read, a symlink or special file is encountered, or
rotation fails, the daemon warns that the full output size cannot be verified.
