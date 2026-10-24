#!/usr/bin/env python3
"""Render the independent grader's public report; missing security checks stay hidden."""
import argparse
import datetime
import html
import json
import os
from pathlib import Path
import subprocess
import tempfile


def render(report):
    passed=[c for c in report['checks'] if c['status']=='PASS' and not c['id'].startswith('availability.')]
    business=[c for c in report['checks'] if c['id'].startswith('availability.')]
    rows=''.join('<li>'+html.escape(c['id'])+'</li>' for c in passed)
    health=''.join('<li>'+html.escape(c['id'])+': '+html.escape(c['status'])+'</li>' for c in business)
    stamp=datetime.datetime.fromtimestamp(report['timestamp'],datetime.timezone.utc).isoformat()
    return f'''<!doctype html><html lang="en"><meta charset="utf-8"><meta http-equiv="refresh" content="30">
<title>Advanced Linux Practice Score</title><style>body{{background:#101c2d;color:#e4edf7;font:16px system-ui;max-width:900px;margin:40px auto;padding:24px}}h1{{font-size:28px}}strong{{font-size:36px;color:#8de0ad}}li{{padding:3px}}small{{color:#b8c8dc}}</style>
<h1>Advanced Linux Practice Lab</h1><p>Original training scenario. Not an official CyberPatriot image.</p>
<strong>{report['score']:.2f} / 100</strong><p>{report['earned']} of {report['possible']} security checks passed. Business penalties: {report['penalties']}.</p>
<small>Normalized practice score. Updated {html.escape(stamp)}. Forensic and availability requirements are in the README.</small>
<h2>Business availability</h2><ul>{health}</ul><h2>Completed security checks</h2><ul>{rows}</ul></html>'''


def publish(path,text):
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
    fd,name=tempfile.mkstemp(prefix='.cp-report-',dir=path.parent)
    try:
        with os.fdopen(fd,'w') as stream: stream.write(text)
        os.chmod(name,0o644);os.replace(name,path)
    finally:
        if os.path.exists(name): os.unlink(name)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--seed',type=int,required=True)
    args=parser.parse_args()
    if os.geteuid()!=0 or not Path('/etc/cp-advanced-lab').is_file():
        raise SystemExit('Lab guest root only')
    private=Path(__file__).resolve().parent/'latest.json'
    subprocess.run(['python3',str(Path(__file__).with_name('score.py')),'--seed',str(args.seed),'--output',str(private)],check=True,timeout=180)
    document=render(json.loads(private.read_text()))
    publish('/home/cpoperator/Desktop/ScoringReport.html',document)
    publish('/var/www/html/scoring-report.html',document)
