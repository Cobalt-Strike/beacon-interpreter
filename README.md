# Beacon Interpreter

This repository contains support files for developing Beacon Interpreter scripts.

- `interpreter-includes/`: copies of the C headers shipped with Cobalt Strike for Beacon Interpreter development, including Windows, BOF API, CRT, and internal helper declarations.
- `interpreter_demo.c`: an example Beacon Interpreter script showing supported C features and native API calls.
- `skills.md`: guidance for AI agents generating Beacon Interpreter compatible C scripts.
- `situational_awareness/`: Ported examples from the TrustedSec Situational Awareness BOF repository to demonstrate execution under the Beacon Interpreter VM

## Export the interpreter resources

Use Python and Git to export the guide, headers, demo, and license for a reviewed
commit. Run this in a checkout that contains the revision, replacing `COMMIT_SHA`
with its full SHA.

```sh
python tools/export_skill_resources.py COMMIT_SHA beacon-interpreter-resources.zip
```

The ZIP uses the repository paths and records the resolved commit in its ZIP
comment. It reads the committed files, so a refresh can be reproduced from the
same source revision.
