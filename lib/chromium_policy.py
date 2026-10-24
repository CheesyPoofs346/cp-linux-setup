"""Apply an explicit README pop-up blocking requirement via managed policy.

Never edit a running browser's Preferences file: it can overwrite external edits.
"""
import argparse
import json
from pathlib import Path
import re
import shutil


def configure(root, readme):
    text = readme.lower()
    if not ('chromium' in text and re.search(r'block[^.\n]*pop.?ups', text)):
        return False
    directory = root / 'etc/chromium/policies/managed'
    directory.mkdir(parents=True, exist_ok=True)
    target = directory / '99-cp-popups.json'
    # Preserve unrelated policy values; refuse malformed existing JSON.
    data = json.loads(target.read_text()) if target.exists() else {}
    if target.exists() and not target.with_suffix('.json.bak').exists():
        shutil.copy2(target, target.with_suffix('.json.bak'))
    data.update(DefaultPopupsSetting=2, PopupsAllowedForUrls=[])
    target.write_text(json.dumps(data, indent=2) + '\n')
    target.chmod(0o644)
    for path in (directory, directory.parent, directory.parent.parent, directory.parent.parent.parent):
        path.chmod(0o755)
    return True


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('readme', type=Path)
    parser.add_argument('--root', type=Path, default=Path('/'))
    args = parser.parse_args()
    if configure(args.root, args.readme.read_text()):
        print('Chromium pop-ups blocked by managed policy; verify chrome://policy and scoring separately')
