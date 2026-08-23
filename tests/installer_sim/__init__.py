"""Installer simulation harness (packet 019).

Prove installer DECISION PATHS without touching a live host: a fake-command directory on PATH +
extracted shell functions run against temp install roots, plus pure-Python simulators for the sharpest
logic (e.g. git-credential-store host matching). Deliberately minimal — not a fake OS.
"""
