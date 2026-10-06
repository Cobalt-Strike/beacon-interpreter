# Beacon Interpreter

A standalone skill plugin for authoring, reviewing, and troubleshooting Cobalt
Strike Beacon Interpreter C scripts. It bundles compatibility guidance, 34
interpreter headers, and a feature demo. The portable skill is named
`cobalt-strike-beacon-interpreter`.

## Install locally

The repository contains a portable `plugin.json`, Codex and Claude compatibility
manifests, and a one-plugin marketplace at `.claude-plugin/marketplace.json`.
This marketplace location is also supported by Codex. The source path points to
this repository's root, so it works from a checkout or an extracted package.

For Codex, run these commands from the repository root:

```sh
codex plugin marketplace add .
codex plugin add cobalt-strike-beacon-interpreter@beacon-interpreter-local
```

Start a new session and invoke `$cobalt-strike-beacon-interpreter`.

For a Claude Code development session, run from the repository root:

```sh
claude --plugin-dir .
```

For a persistent Claude Code installation, use these commands inside Claude Code,
replacing the path with this checkout's absolute path:

```text
/plugin marketplace add /absolute/path/to/beacon-interpreter
/plugin install cobalt-strike-beacon-interpreter@beacon-interpreter-local
```

Claude Code namespaces the skill as
`/cobalt-strike-beacon-interpreter:cobalt-strike-beacon-interpreter`.
For clients that install individual skills, copy the complete
[`skills/cobalt-strike-beacon-interpreter/`](skills/cobalt-strike-beacon-interpreter/)
directory to the client's supported skill location.

## Use

Example requests:

- Explain the bundled interpreter demo.
- Review this script for Beacon Interpreter compatibility.
- Write a script that reads one packed string argument and prints it.

The skill's [entry point](skills/cobalt-strike-beacon-interpreter/SKILL.md) links
to its detailed references. It provides authoring guidance and local resources;
it does not install or connect to Cobalt Strike.

Running generated scripts requires a Cobalt Strike installation with Beacon
Interpreter support and a compatible Team Server header set. The source
snapshot does not identify a Cobalt Strike release, and no runtime-tested
version or architecture is currently claimed. See
[`compatibility.json`](compatibility.json) and the bundled
[provenance](skills/cobalt-strike-beacon-interpreter/references/provenance.json).

## Existing development resources

The original paths remain available:

- [`interpreter-includes/`](interpreter-includes/): the supplied interpreter headers.
- [`interpreter_demo.c`](interpreter_demo.c): supported C features and native API calls.
- [`skills.md`](skills.md): the full interpreter compatibility guide.

These files are the maintained sources for the copies distributed inside the
skill. See [maintenance and packaging](docs/development.md) for synchronization,
checks, ZIP builds, and the future SpecterOps migration.

Licensed under [Apache-2.0](LICENSE). Report plugin defects in the
[source repository](https://github.com/Cobalt-Strike/beacon-interpreter/issues),
including the plugin version and a minimal reproducible example.
