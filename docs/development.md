# Maintaining the plugin

Python 3.10 or newer is needed for the maintenance commands. They use only the
standard library. Reading and using the installed skill requires no Python,
MCP server, credentials, or network connection.

## Sources and generated files

Maintain `plugin.json`, `compatibility.json`, the root `skills.md`,
`interpreter_demo.c`, `interpreter-includes/`, and `LICENSE` as the source files.
Edit the skill's `SKILL.md` and `references/validation.md` directly.
When adding another authored resource, add it to the `AUTHORED` file list in
`tools/plugin.py` so it is included in release archives.

Run from the repository root:

```sh
python tools/plugin.py sync
python tools/plugin.py check
python -m unittest discover -s tests -v
python tools/plugin.py build
```

`sync` updates the Codex/Claude compatibility manifests, the single-plugin
marketplace, and the copies of the guide, demo, license, and headers inside the
skill. It also writes `references/provenance.json` with content hashes. Edit the
source files instead of those generated copies. Obsolete bundled headers are
reported for review, not silently deleted.

`check` is read-only and fails on resource drift, mismatched manifests,
unresolved or escaping skill links, invalid metadata, or stale provenance.
Hashes normalize CRLF to LF so Windows and Unix checkouts agree. `sync` copies
source bytes unchanged; `build` normalizes text in the archive to LF.

`build` first checks the checkout, then writes a deterministic ZIP in `dist/`.
It packages an explicit set of plugin files and maintenance sources, including
hidden manifests, with one `cobalt-strike-beacon-interpreter/` root directory.
It excludes Git data, caches, and unrelated local files. The extracted package
can run the same checks without a Git checkout. The tests also copy just the
skill into a new location and check that its references remain self-contained.

The repository workflow runs the checks on Windows and Linux. These checks do
not execute scripts on Cobalt Strike or establish runtime compatibility. Use
the skill's [validation guide](../skills/cobalt-strike-beacon-interpreter/references/validation.md)
for behavioral and interpreter checks.

## Refreshing the header snapshot

Update the root headers and examples from their maintained source, preserving
notices and the license. Set the source revision and known Cobalt Strike version
in `compatibility.json`. An unknown version stays `null`; do not infer a supported
release from the existence of a declaration. Record actual runtime test results
in `runtime_validation`, then regenerate and review the bundle.

For a release, update the version in root `plugin.json` and run `sync`, checks,
and the build. Manifests and the marketplace obtain the same version from that
source. Refresh the installed plugin through its client's plugin manager and
start a new session after changing it.

## Moving the skill into SpecterOps/skills

The eventual destination is
`plugins/c2-cobaltstrike/skills/cobalt-strike-beacon-interpreter/`. Copy the entire
skill directory, including its license and provenance. Its links do not depend
on this repository's root or the standalone plugin name. At that point, choose
the upstream skill resources as the maintained source or retain an explicit
import process; do not leave two independently edited copies.

Update the existing `c2-cobaltstrike` plugin's ownership, skill listings,
descriptions, prompts, and release metadata according to its current conventions.
Keep this repository's standalone manifests and marketplace here. Regenerate
the applicable upstream catalogs/inventory and run `just check` using the
upstream toolchain. Follow the current
[SpecterOps contribution guide](https://github.com/SpecterOps/skills/blob/main/CONTRIBUTING.md).

## Packaging references

- [OpenAI plugin packaging](https://developers.openai.com/plugins/build/plugins)
- [Agent Plugins manifest schema](https://agent-plugins.org/schemas/1.0.0/plugin.schema.json)
- [Claude plugin manifests](https://code.claude.com/docs/en/plugins-reference)
