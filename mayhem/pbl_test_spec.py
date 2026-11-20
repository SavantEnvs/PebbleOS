#!/usr/bin/env python3
"""Print what upstream's own unit-test build compiles for one clar test.

PebbleOS's host tests are declared as `pbl_clar_test(<name> MODULES .. SOURCES .. DEFINES ..
OVERRIDES .. INCLUDES ..)` in tests/**/CMakeLists.txt, with module source groups in
tests/modules.cmake (cmake/modules/pbl_test.cmake materializes them). mayhem/build.sh builds the
fuzz harnesses and the test runners from those exact lists without configuring the whole CMake
project (which needs nanopb's protoc generator and every image fixture).

usage: pbl_test_spec.py <repo root> <test name> sources|defines|overrides|includes|source
"""
import os
import re
import sys

root, name, what = sys.argv[1], sys.argv[2], sys.argv[3]
KEYS = ("MODULES", "SOURCES", "PLATFORMS", "DEFINES", "INCLUDES", "OVERRIDES", "LIBS", "DEPENDS",
        "REQUIRES", "SOURCE", "TEST_IMAGES")


def calls(path, func):
    text = open(path).read()
    text = re.sub(r"#[^\n]*", "", text)
    for m in re.finditer(r"\b%s\(([^()]*)\)" % func, text):
        toks = m.group(1).split()
        yield toks[0], toks[1:], os.path.dirname(path)


def parse(toks):
    out, key = {}, None
    for t in toks:
        if t in KEYS:
            key = t
            out.setdefault(key, [])
        elif key:
            out[key].append(t.strip('"'))
    return out


modules = {}
for n, toks, _ in calls(os.path.join(root, "tests/modules.cmake"), "pbl_test_module"):
    modules[n] = parse(toks)

test = None
for dirpath, _, files in os.walk(os.path.join(root, "tests")):
    if "CMakeLists.txt" in files:
        for n, toks, d in calls(os.path.join(dirpath, "CMakeLists.txt"), "pbl_clar_test"):
            if n == name:
                test = parse(toks), d
if test is None:
    sys.exit("pbl_test_spec: no pbl_clar_test(%s)" % name)
spec, testdir = test


def module_sources(names, seen):
    out = []
    for m in names:
        if m in seen:
            continue
        seen.add(m)
        out += module_sources(modules[m].get("REQUIRES", []), seen)
        out += modules[m].get("SOURCES", [])
    return out


if what == "sources":
    srcs = []
    for s in module_sources(spec.get("MODULES", []), set()) + spec.get("SOURCES", []):
        s = s.replace("@PLATFORM@", "emery").replace("@BITDEPTH@", "8")
        if s not in srcs:
            srcs.append(s)
    print("\n".join(srcs))
elif what == "source":
    src = (spec.get("SOURCE") or [name + ".c"])[0]
    print(os.path.relpath(os.path.join(testdir, src), root))
else:
    print("\n".join(spec.get(what.upper(), [])))
