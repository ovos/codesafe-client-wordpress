"""Render docs/header.svg to docs/header.png (1880x500, the README's header).

The SVG is the source and carries Rajdhani embedded; GitHub would show the
SVG in whatever fonts the reader has, so the README links the PNG. Edit the
SVG's text by hand, then run from the repository root:

    python docs/header.py

Uses Chrome or Edge headless: a 940x250 window at device scale factor 2.
"""
import pathlib
import shutil
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent
CANDIDATES = [
	'C:/Program Files/Google/Chrome/Application/chrome.exe',
	'C:/Program Files (x86)/Google/Chrome/Application/chrome.exe',
	'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe',
	'/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
]

browser = next((path for path in CANDIDATES if pathlib.Path(path).exists()), None) \
	or shutil.which('google-chrome') or shutil.which('chromium') or shutil.which('msedge')
if browser is None:
	sys.exit('no Chrome or Edge found')

subprocess.run([
	browser, '--headless=new', '--disable-gpu', '--hide-scrollbars',
	'--window-size=940,250', '--force-device-scale-factor=2',
	'--screenshot=' + str(HERE / 'header.png'),
	(HERE / 'header.svg').as_uri(),
], check=True)
print('wrote', HERE / 'header.png')
