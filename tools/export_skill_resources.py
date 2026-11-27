"""Export the Beacon Interpreter reference files from a Git commit."""

import argparse
import subprocess
from pathlib import Path


RESOURCE_PATHS = ("skills.md", "interpreter-includes/", "interpreter_demo.c", "LICENSE")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("revision", help="Commit, tag, or branch to export")
    parser.add_argument("output", type=Path, help="Destination ZIP file")
    args = parser.parse_args()

    repo = Path(__file__).resolve().parents[1]
    git = ["git", "-C", str(repo)]
    try:
        commit = subprocess.check_output(
            [*git, "rev-parse", "--verify", "--end-of-options", f"{args.revision}^{{commit}}"],
            text=True,
        ).strip()
        archive = subprocess.check_output(
            [*git, "archive", "--format=zip", commit, "--", *RESOURCE_PATHS]
        )
        args.output.write_bytes(archive)
    except (OSError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"Could not export Interpreter resources: {error}\n")

    print(f"Exported {commit} to {args.output}")


if __name__ == "__main__":
    main()
