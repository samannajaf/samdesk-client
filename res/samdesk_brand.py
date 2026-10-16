#!/usr/bin/env python3
# SamDesk build-time rebrand: replace the visible product name "RustDesk" with
# "SamDesk" in the *values* of the translation tables (src/lang/*.rs), leaving
# every key and all source code untouched. Run from the repo root before the
# build. Because it only rewrites the checkout at build time, the tracked source
# stays identical to upstream, so RustDesk updates still merge cleanly.
import glob
import os
import re
import sys

OLD = "RustDesk"
NEW = "SamDesk"
lang_dir = sys.argv[1] if len(sys.argv) > 1 else os.path.join("src", "lang")

# A translation entry is ("<key>", "<value>"); rewrite OLD only inside the value.
# The string classes are escaped-quote aware so \" and \n inside a value are kept.
entry = re.compile(r'(\(\s*"(?:[^"\\]|\\.)*"\s*,\s*")((?:[^"\\]|\\.)*)("\s*\))')


def rebrand_value(m):
    return m.group(1) + m.group(2).replace(OLD, NEW) + m.group(3)


total = 0
for path in sorted(glob.glob(os.path.join(lang_dir, "*.rs"))):
    src = open(path, encoding="utf-8").read()
    out = entry.sub(rebrand_value, src)
    if out != src:
        n = src.count(OLD) - out.count(OLD)
        total += n
        open(path, "w", encoding="utf-8").write(out)
        print(f"  {os.path.basename(path)}: {n} value(s) rebranded")

print(f"samdesk_brand: {total} translation value(s) rebranded to {NEW}")
