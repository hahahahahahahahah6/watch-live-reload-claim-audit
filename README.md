# Filesystem observation claim auditor

An offline, standard-library-only Python auditor comparing documentation with
filesystem observation evidence. It parses source without executing project code.
Requires Python 3.9 or newer. Licensed under MIT.

Install with `python3 -m pip install .` in a virtual environment.
Run either entry point:

```sh
watch-live-reload-claim-audit PROJECT
python3 -m watch_live_reload_claim_audit PROJECT
```
Use `--json` for structured output, `--verbose` for locations,
repeatable `--ignore GLOB_OR_DIRECTORY` to exclude paths, and `--fail-on HIGH`
to allow MEDIUM findings. `--version` prints 0.1.0.
Exit codes: 0 for success, 2 for findings, 1 for invalid arguments or errors.

Only root README.md and docs/**/*.md prose provides claims; fenced blocks are
excluded and inline code counts. Symlink files and directories are skipped.
Source is parsed with AST. Tests provide separate MEDIUM evidence; fixtures,
docs and examples do not provide evidence. Virtual environments, build artifacts,
and Git metadata are skipped. The .env file is never read.

Positive claims without production evidence produce HIGH findings (MEDIUM when
only tests provide evidence). Negative claims contradicted by production produce
HIGH findings (MEDIUM when only tests provide evidence). Without source, positive
claims fail and negative claims pass. No claims means PASS.
The rule IDs and exact normalized vocabulary are below. Normalization lowercases,
expands contracted negation, replaces hyphens with spaces and collapses whitespace.
The longest phrase across both families wins within a sentence; remaining negation
suppresses positive phrases.

```text
documented-watch-claim-false
documented-no-watch-claim-false
WATCH:
watches for file changes
watches for changes
watches the file system
watches the filesystem
watches files for changes
watches files
watches the directory
watches a directory
watches directories
file watching support
file watching enabled
automatic reload on change
automatically reloads on change
reloads automatically on change
reloads on file change
reloads when files change
live reload support
live reload enabled
live reload
hot reload support
hot reload enabled
hot reload
auto reload support
auto reload enabled
auto reload
automatically reloads
reloads automatically
file change detection
detects file changes
monitors files for changes
monitors files
monitors file changes
NOWATCH:
does not watch files
does not watch for changes
never watches files
does not support live reload
does not support hot reload
does not support auto reload
no live reload support
no live reload
no hot reload
no auto reload
no file watching
no file watching support
without live reload
without file watching
does not reload automatically
never reloads automatically
must be restarted manually
requires a manual restart
manual restart required
```

Evidence includes imported watchdog observers/handlers, watchfiles calls,
inotify calls, true reload keywords, and stat polling paired with sleep in a loop.
Aliases are resolved and locally shadowed names excluded. Bare imports, comments,
strings, names alone, false flags, one-time reads/listings/stats, sleeping alone,
and polling without sleep are excluded. Static analysis does not prove runtime
behavior or resolve arbitrary dynamic imports and object flows.

Development: create `.venv` with `python3 -m venv .venv`, install with
`.venv/bin/python3 -m pip install -e . pytest build`, run
`PATH="$PWD/.venv/bin:$PATH" .venv/bin/python3 -m pytest`, and build with
`.venv/bin/python3 -m build` (standard isolated build).
