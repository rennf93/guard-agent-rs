"""
Version bump helper script for guard-agent-rs.

Updates the version string across the files that reference it:
- Cargo.toml ([package].version for the guard-agent-rs crate)
- Cargo.lock ([[package]] version entry for guard-agent-rs)
- CHANGELOG.md (inserts a version scaffold at the top for manual editing)

Usage:
    python .github/scripts/bump_version.py <version>
    make bump-version VERSION=x.y.z

No external dependencies required - stdlib only.
"""

from __future__ import annotations

import re
import sys
from datetime import datetime, timezone
from pathlib import Path

# Resolve project root relative to this script's location
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent

VERSION_PATTERN = re.compile(r"^\d+\.\d+\.\d+$")


def update_cargo_toml(version: str) -> bool:
    """Update [package].version in Cargo.toml."""
    path = PROJECT_ROOT / "Cargo.toml"
    content = path.read_text()
    pattern = re.compile(r'^(version\s*=\s*)"[^"]*"', re.MULTILINE)
    match = pattern.search(content)
    if not match:
        print("  ERROR: Could not find version field in Cargo.toml")
        return False
    current = re.search(r'"([^"]*)"', match.group(0))
    if current and current.group(1) == version:
        print(f"  Cargo.toml: already set to {version}")
        return True
    new_content = pattern.sub(lambda m: f'{m.group(1)}"{version}"', content, count=1)
    path.write_text(new_content)
    print(f"  Cargo.toml: updated to {version}")
    return True


def update_cargo_lock(version: str) -> bool:
    """Update the guard-agent-rs [[package]] version entry in Cargo.lock."""
    path = PROJECT_ROOT / "Cargo.lock"
    if not path.exists():
        print("  ERROR: Cargo.lock not found")
        return False
    content = path.read_text()
    pattern = re.compile(
        r'(\[\[package\]\]\nname = "guard-agent-rs"\nversion = )"[^"]*"'
    )
    new_content, n = pattern.subn(r'\1"%s"' % version, content)
    if n == 0:
        print("  WARNING: no Cargo.lock entry found for guard-agent-rs")
        return True
    if new_content == content:
        print(f"  Cargo.lock: already set to {version}")
        return True
    path.write_text(new_content)
    print(f"  Cargo.lock: guard-agent-rs updated to {version}")
    return True


def insert_changelog_scaffold(version: str) -> bool:
    """Insert a version scaffold block at the top of CHANGELOG.md.

    Mirrors guard-agent's bump_version.py scaffold behavior, adapted to
    this repo's keep-a-changelog style.
    """
    path = PROJECT_ROOT / "CHANGELOG.md"
    if not path.exists():
        print("  ERROR: CHANGELOG.md not found")
        return False
    content = path.read_text()
    today = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d")

    if f"## [{version}]" in content:
        print(f"  CHANGELOG.md: {version} entry already exists")
        return True

    scaffold = (
        f"## [{version}] - {today}\n"
        f"\n"
        f"### Added\n"
        f"\n"
        f"- (v{version}) describe additions here\n"
        f"\n"
        f"### Changed\n"
        f"\n"
        f"- (v{version}) describe changes here\n"
        f"\n"
    )

    # Insert before the first existing version heading
    heading_pattern = re.compile(r"^## \[", re.MULTILINE)
    match = heading_pattern.search(content)
    if match:
        insert_pos = match.start()
        new_content = content[:insert_pos] + scaffold + content[insert_pos:]
    else:
        new_content = content.rstrip() + "\n\n" + scaffold

    path.write_text(new_content)
    print(f"  CHANGELOG.md: added v{version} scaffold")
    return True


def main() -> int:
    if len(sys.argv) != 2:
        print("Usage: bump_version.py <version>")
        print("  version must be in X.Y.Z format")
        return 1

    version = sys.argv[1]

    if not VERSION_PATTERN.match(version):
        print(f"Error: '{version}' is not a valid version. Expected format: X.Y.Z")
        return 1

    print(f"Bumping version to {version}...\n")

    ok = True
    for name, updater in [
        ("Cargo.toml", update_cargo_toml),
        ("Cargo.lock", update_cargo_lock),
        ("CHANGELOG.md scaffold", insert_changelog_scaffold),
    ]:
        try:
            if not updater(version):
                print(f"\n  FAILED: {name}")
                ok = False
        except Exception as e:
            print(f"\n  ERROR updating {name}: {e}")
            ok = False

    print()
    if ok:
        print("Version bump complete.")
        print("Next steps: edit the CHANGELOG.md scaffold, then commit and tag.")
    else:
        print("Version bump completed with errors.")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
