#!/usr/bin/env python3
"""Synchronize, check, and package this repository's standalone skill plugin."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
from urllib.parse import unquote, urlsplit
import zipfile


ROOT = Path(__file__).resolve().parents[1]
NAME = "cobalt-strike-beacon-interpreter"
SKILL = Path("skills") / NAME
SCHEMA = "https://agent-plugins.org/schemas/1.0.0/plugin.schema.json"
AUTHORED = (
    "README.md", "LICENSE", "skills.md", "interpreter_demo.c", "plugin.json",
    "compatibility.json", "docs/development.md", "tools/plugin.py",
    "tests/test_plugin.py", f"{SKILL.as_posix()}/SKILL.md",
    f"{SKILL.as_posix()}/agents/openai.yaml",
    f"{SKILL.as_posix()}/references/validation.md",
    "assets/cobalt-strike-beacon-interpreter.png",
)


def contained(root, relative):
    """Resolve a package path, rejecting traversal and symlink dependencies."""
    root = root.resolve()
    path = root / relative
    if not path.resolve().is_relative_to(root):
        raise ValueError(f"Path escapes package: {relative}")
    current = path
    while current != root:
        if current.is_symlink():
            raise ValueError(f"Symlink in package path: {relative}")
        current = current.parent
    return path


def normalized(data):
    return data.replace(b"\r\n", b"\n")


def digest(data):
    return hashlib.sha256(normalized(data)).hexdigest()


def json_bytes(value):
    return (json.dumps(value, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def read_json(root, relative):
    return json.loads(contained(root, relative).read_text(encoding="utf-8"))


def read_manifest(root):
    manifest = read_json(root, "plugin.json")
    allowed = {"$schema", "name", "version", "description", "author", "homepage",
               "repository", "license", "keywords", "extensions"}
    if set(manifest) - allowed:
        raise ValueError("Unsupported portable manifest fields")
    if manifest.get("$schema") != SCHEMA or manifest.get("name") != NAME:
        raise ValueError("Invalid portable manifest schema or plugin name")
    if not re.fullmatch(r"\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?", manifest["version"]):
        raise ValueError("Plugin version must be a semantic version")
    for field in ("description", "repository", "license"):
        if not isinstance(manifest.get(field), str) or not manifest[field].strip():
            raise ValueError(f"Missing manifest {field}")
    if not manifest["author"].get("name"):
        raise ValueError("Missing plugin author")
    interface = manifest["extensions"]["com.openai"]["interface"]
    if not 1 <= len(interface["shortDescription"]) <= 30:
        raise ValueError("Plugin shortDescription must be 1-30 characters")
    prompts = interface["defaultPrompt"]
    if not isinstance(prompts, list) or not 1 <= len(prompts) <= 3:
        raise ValueError("Expected one to three plugin prompts")
    if any(not isinstance(prompt, str) or not prompt.strip() for prompt in prompts):
        raise ValueError("Plugin prompts must be nonempty strings")
    return manifest


def source_headers(root):
    return sorted(path.relative_to(root) for path in
                  contained(root, "interpreter-includes").glob("*.h"))


def generated_files(root):
    manifest = read_manifest(root)
    common = {key: value for key, value in manifest.items()
              if key not in ("$schema", "extensions")}
    codex = {**common, "skills": "./skills/",
             "interface": manifest["extensions"]["com.openai"]["interface"]}
    marketplace = {
        "name": "beacon-interpreter-local",
        "owner": manifest["author"],
        "plugins": [{"name": manifest["name"], "source": "./",
                     "description": manifest["description"],
                     "version": manifest["version"]}],
    }
    generated = {
        Path(".codex-plugin/plugin.json"): json_bytes(codex),
        Path(".claude-plugin/plugin.json"): json_bytes(common),
        Path(".claude-plugin/marketplace.json"): json_bytes(marketplace),
    }
    resources = {
        Path("LICENSE"): Path("LICENSE"),
        Path("references/compatibility.md"): Path("skills.md"),
        Path("assets/interpreter_demo.c"): Path("interpreter_demo.c"),
    }
    headers = source_headers(root)
    if not headers:
        raise ValueError("No source interpreter headers found")
    for header in headers:
        resources[Path("references/interpreter-includes") / header.name] = header
    provenance = read_json(root, "compatibility.json")
    if not re.fullmatch(r"[0-9a-f]{40}", provenance["source_revision"]):
        raise ValueError("Source revision must identify the full baseline commit")
    version = provenance["cobalt_strike_version"]
    if version is not None and (not isinstance(version, str) or not version.strip()):
        raise ValueError("Cobalt Strike version must be null or a nonempty string")
    if not isinstance(provenance["runtime_validation"], list):
        raise ValueError("runtime_validation must be a list of recorded results")
    provenance["hash_format"] = "sha256 with CRLF normalized to LF"
    provenance["files"] = {}
    for destination, source in sorted(resources.items()):
        data = contained(root, source).read_bytes()
        generated[SKILL / destination] = data
        provenance["files"][destination.as_posix()] = {
            "source": source.as_posix(), "sha256": digest(data),
        }
    generated[SKILL / "references/provenance.json"] = json_bytes(provenance)
    return generated


def check_links(root, markdown, packaged=None):
    content = markdown.read_text(encoding="utf-8")
    for target in re.findall(r"\[[^\]\n]*\]\(([^)\n]+)\)", content):
        target = target.strip().strip("<>")
        parsed = urlsplit(target)
        if parsed.scheme in ("https", "http", "mailto") or not parsed.path:
            continue
        if (parsed.scheme or parsed.netloc or "\\" in target or
                Path(unquote(parsed.path)).is_absolute()):
            raise ValueError(f"Nonportable link in {markdown.name}: {target}")
        relative = markdown.parent.relative_to(root) / unquote(parsed.path)
        resolved = contained(root, relative)
        if not resolved.exists():
            raise ValueError(f"Broken link in {markdown.name}: {target}")
        if packaged is not None and resolved.is_file() and resolved.resolve() not in packaged:
            raise ValueError(f"Reference missing from archive file list: {target}")


def check_skill(skill):
    """Validate a relocated skill without any dependency on its source repo."""
    skill = skill.resolve()
    text = contained(skill, "SKILL.md").read_text(encoding="utf-8")
    frontmatter = re.match(r"\A---\n(.*?)\n---\n", text, re.DOTALL)
    if not frontmatter:
        raise ValueError("Missing SKILL.md YAML frontmatter")
    fields = dict(re.findall(r"^([a-z-]+): (.+)$", frontmatter[1], re.MULTILINE))
    if fields.get("name") != NAME or skill.name != NAME:
        raise ValueError("Skill name and directory must match")
    description = fields.get("description", "")
    if not description.strip() or len(description) > 1024:
        raise ValueError("Invalid skill description")
    for markdown in sorted(skill.rglob("*.md")):
        contained(skill, markdown.relative_to(skill))
        check_links(skill, markdown)
    provenance = read_json(skill, "references/provenance.json")
    for relative, record in provenance["files"].items():
        if digest(contained(skill, relative).read_bytes()) != record["sha256"]:
            raise ValueError(f"Bundled resource hash mismatch: {relative}")


def sync(root):
    generated = generated_files(root)
    # Preflight every destination before any writes, including parent symlinks.
    for relative in generated:
        contained(root, relative)
    for relative, data in generated.items():
        path = contained(root, relative)
        if not path.exists() or path.read_bytes() != data:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
    return len(generated)


def package_paths(root):
    return sorted(set(map(Path, AUTHORED)) | set(source_headers(root)) |
                  set(generated_files(root)))


def check(root):
    generated = generated_files(root)
    for relative, expected in generated.items():
        path = contained(root, relative)
        if not path.is_file() or normalized(path.read_bytes()) != normalized(expected):
            raise ValueError(f"Missing or stale generated file: {relative}; run sync")
    bundled_headers = contained(root, SKILL / "references/interpreter-includes")
    extras = {path.name for path in bundled_headers.iterdir()} - {
        path.name for path in source_headers(root)
    }
    if extras:
        raise ValueError(f"Unexpected bundled headers; review before removing: {sorted(extras)}")
    check_skill(contained(root, SKILL))
    paths = package_paths(root)
    for relative in paths:
        if not contained(root, relative).is_file():
            raise ValueError(f"Missing package file: {relative}")
    packaged = {contained(root, relative).resolve() for relative in paths}
    interface = read_manifest(root)["extensions"]["com.openai"]["interface"]
    for field in ("logo", "composerIcon", "logoDark", "composerIconDark"):
        if field in interface:
            relative = interface[field]
            if not isinstance(relative, str) or not relative.startswith("./assets/"):
                raise ValueError(f"{field} must reference a packaged asset")
            if contained(root, relative).resolve() not in packaged:
                raise ValueError(f"{field} is missing from the package: {relative}")
    for relative in paths:
        if relative.suffix == ".md":
            check_links(root, contained(root, relative), packaged)


def build(root):
    check(root)
    version = read_manifest(root)["version"]
    output = contained(root, Path("dist") / f"{NAME}-{version}.zip")
    output.parent.mkdir(exist_ok=True)
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for relative in package_paths(root):
            info = zipfile.ZipInfo(f"{NAME}/{relative.as_posix()}", (1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            data = contained(root, relative).read_bytes()
            if relative.suffix in {".py", ".md", ".json", ".c", ".h", ".txt"} or relative.name == "LICENSE":
                data = normalized(data)
            archive.writestr(info, data)
    return output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("sync", "check", "build"))
    args = parser.parse_args()
    try:
        if args.command == "sync":
            print(f"Synchronized {sync(ROOT)} generated files.")
            check(ROOT)
        elif args.command == "build":
            print(build(ROOT))
        else:
            check(ROOT)
            print("Plugin metadata, resources, provenance, and links are valid.")
    except (ValueError, OSError, KeyError, TypeError) as error:
        print(f"Plugin check failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
