def _build_number() -> str:
    # Version = git commit count. PREFER the installer/updater-written stamp (corpusfm/_build.txt)
    # so the running service NEVER depends on `git` being on its PATH at runtime — the 0.0 class of
    # bug (a service PATH without git, a dubious-ownership refusal, a tree mid-swap, a slow git). git
    # is only the DEV fallback (a working-tree checkout has no stamp). Defensive: any failure →
    # "0", never breaks `import corpusfm`. See corpusfm/buildstamp.py.
    try:
        from corpusfm import buildstamp
        return buildstamp.read_stamp() or buildstamp.source_build_number(timeout=2) or "0"
    except Exception:
        return "0"


__version__ = f"0.{_build_number()}"
