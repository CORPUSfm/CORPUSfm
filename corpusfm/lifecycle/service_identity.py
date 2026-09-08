"""Who the CORPUSfm services run as, and the definitions that say so (packet 1246-03, E3).

Parent D4: the web and scheduler services are genuinely unprivileged. Linux already had that — a
non-login `corpusfm` system user. Windows did not, and the way it did not is the point:

    the WinSW service XML carries NO <serviceaccount> element at all

so both services run as **LocalSystem by omission**. There is nothing to un-set and no branch to
remove. A test asserting "the identity is not LocalSystem" would pass against a definition that names
no identity whatsoever, which is exactly the shape of the current defect. So the emitter here does not
*prefer* an identity — it **cannot produce a definition without one**, and `assert_unprivileged`
refuses the privileged names before anything is rendered.

**The `.mcp_env` exception (developer ruling, 2026-08-02).** Read-only secrets would have silently
broken the approved token-regeneration UI, which is a service writing a secret. The ruling grants the
narrowest capability that works, and the mechanism is ordinary POSIX/NTFS semantics rather than a new
privileged helper: **directory permission governs create/delete/rename; file permission governs
content.** A `root:root 0755` secrets directory containing one `corpusfm:corpusfm 0600` file lets the
service rewrite that file's contents and do nothing else there — it cannot add a secret, replace one,
or remove one. Windows gets the equivalent: write on the one file, no `FILE_ADD_FILE` or
`FILE_DELETE_CHILD` on the directory.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath, PureWindowsPath
from xml.sax.saxutils import escape as _xml_escape, quoteattr as _xml_quoteattr

from .errors import LifecycleError
from .layout import POSIX, WINDOWS
from .os_layout import DEFAULT_POSIX_INSTALL_DIR, DEFAULT_WINDOWS_INSTALL_DIR, OsLayout

WEB_ROLE = "web"

#: The standalone `corpusfm-scheduler` service is RETIRED (packet 1361-01, round 3). Scheduling is a
#: background component of the web process now: it starts from the same database-readiness resume
#: path that starts the catalog synchronizer and the queue workers, and it stops with the service. A
#: second process could not honour the process-wide readiness gate — it kept reading and writing
#: FileMaker while CORPUSfm was PAUSED — and `python -m corpusfm.server.scheduler` now refuses.
#:
#: The role SURVIVES here, and the distinction is load-bearing: it is no longer RENDERED (nothing
#: composes, registers, grants to or starts it) but it is still MANAGED (an installation made by an
#: earlier build recorded one, and an uninstall must be able to stop and remove it by name). Those
#: are the two tuples below.
SCHEDULER_ROLE = "scheduler"

#: The services this build RENDERS and publishes. One.
SERVICE_ROLES: tuple[str, ...] = (WEB_ROLE,)

#: Roles a PREVIOUS build registered and this one only ever removes. Never rendered, never granted
#: to, never started — but nameable, so an upgrade and an uninstall can act on what is really there.
RETIRED_SERVICE_ROLES: tuple[str, ...] = (SCHEDULER_ROLE,)

#: Every role that is (or was) a platform SERVICE, as opposed to the updater's scheduled task. This
#: is the set a removal path iterates; `SERVICE_ROLES` is the set a renderer iterates.
REMOVABLE_SERVICE_ROLES: tuple[str, ...] = SERVICE_ROLES + RETIRED_SERVICE_ROLES

POSIX_SERVICE_USER = "corpusfm"

# Windows accounts that carry authority the web and scheduler have no business holding. Compared
# case-insensitively and with the `NT AUTHORITY\` prefix optional, because that is how they are
# spelled in the wild.
WINDOWS_PRIVILEGED_ACCOUNTS: frozenset[str] = frozenset(
    {
        "localsystem",
        "system",
        "nt authority\\system",
        ".\\localsystem",
        "localservice",
        "nt authority\\localservice",
        "nt authority\\local service",
        "networkservice",
        "nt authority\\networkservice",
        "nt authority\\network service",
        "administrator",
        "builtin\\administrators",
        ".\\administrator",
    }
)

POSIX_PRIVILEGED_ACCOUNTS: frozenset[str] = frozenset({"root", "0"})

# The privileged part of a qualified Windows name. `MACHINE\Administrator` and
# `CONTOSO\Domain Admins` are as privileged as `Administrator`, and an exact-spelling blacklist
# passes both — the domain or machine prefix is attacker-supplied in the sense that matters here:
# whoever writes the installer config chooses it. So the LEAF is what gets compared.
WINDOWS_PRIVILEGED_LEAVES: frozenset[str] = frozenset(
    {
        "administrator", "administrators", "system", "localsystem",
        "localservice", "local service", "networkservice", "network service",
        "domain admins", "enterprise admins", "schema admins", "domain administrators",
        "backup operators", "power users", "account operators", "server operators",
        "print operators", "replicator", "trustedinstaller",
    }
)

# The virtual service account Windows creates implicitly for a service configured with this name.
# It cannot log on interactively and exists only for the duration of the service's registration.
WINDOWS_VIRTUAL_PREFIX = "NT SERVICE\\"

class PrivilegedIdentityRefused(LifecycleError):
    """A service was asked to run as an account carrying authority it must not have."""


class ServiceIdentityMissing(LifecycleError):
    """A service definition was requested without naming an identity. Never defaulted."""


class DefinitionNotLayoutDerived(LifecycleError):
    """A definition named a path the published layout does not account for.

    Its own error class because it is a different failure from a privileged identity: the identity
    is right and the *geography* is invented. An installer literal that happens to match today is
    the failure mode — it stops matching the first time the layout moves, and nothing says so.
    """


@dataclass(frozen=True)
class ServiceIdentity:
    """The account one CORPUSfm service runs as."""

    flavour: str
    account: str
    role: str

    def describe(self) -> str:
        return f"{self.role} as {self.account}"


def windows_virtual_account(service_id: str) -> ServiceIdentity:
    role = SCHEDULER_ROLE if "sched" in service_id.lower() else WEB_ROLE
    return ServiceIdentity(
        flavour=WINDOWS, account=f"{WINDOWS_VIRTUAL_PREFIX}{service_id}", role=role
    )


def posix_identity(role: str, account: str = POSIX_SERVICE_USER) -> ServiceIdentity:
    return ServiceIdentity(flavour=POSIX, account=account, role=role)


def _normalise(account: str) -> str:
    return account.strip().strip('"').lower().replace("/", "\\")


def assert_unprivileged(identity: ServiceIdentity) -> ServiceIdentity:
    """Refuse an account that carries privilege the service must not have.

    Raises rather than returning a verdict: a caller that forgets to check a boolean produces the
    exact silent failure this function exists to prevent.
    """
    if not isinstance(identity, ServiceIdentity) or not (identity.account or "").strip():
        raise ServiceIdentityMissing(
            "a CORPUSfm service definition must name the account it runs as; there is no default "
            "and an unnamed identity is how Windows silently ran these services as LocalSystem"
        )
    # REMOVABLE, not rendered. An uninstall names the identity of a service that really exists on
    # the box, including the retired scheduler one (packet 1361-01, round 3); refusing it here would
    # make an installation from an earlier build unremovable.
    if identity.role not in REMOVABLE_SERVICE_ROLES:
        raise PrivilegedIdentityRefused(
            f"unknown service role {identity.role!r}; expected one of {REMOVABLE_SERVICE_ROLES}"
        )
    account = _normalise(identity.account)
    if identity.flavour == WINDOWS:
        leaf = account.rsplit("\\", 1)[-1].strip()
        # No `NT SERVICE\` exemption. A virtual service account's leaf is the service id, which is
        # never in this set, so the exemption changed nothing for a legitimate name — and it would
        # have waved through `NT SERVICE\administrator`, which is the opposite of the point.
        if leaf in WINDOWS_PRIVILEGED_LEAVES:
            raise PrivilegedIdentityRefused(
                f"refusing to run the CORPUSfm {identity.role} service as {identity.account!r} — "
                f"{leaf!r} is a privileged Windows account however it is qualified. Use a "
                "dedicated virtual service account (NT SERVICE\\<service id>)."
            )
        if account in WINDOWS_PRIVILEGED_ACCOUNTS:
            raise PrivilegedIdentityRefused(
                f"refusing to run the CORPUSfm {identity.role} service as {identity.account!r} — "
                "the web and scheduler hold no authority beyond their own state, logs and patch "
                "compartment. Use a dedicated virtual service account."
            )
        if account.startswith("builtin\\") or account.endswith("\\administrators"):
            raise PrivilegedIdentityRefused(
                f"refusing to run the CORPUSfm {identity.role} service as the administrative group "
                f"{identity.account!r}"
            )
    elif identity.flavour == POSIX:
        if account in POSIX_PRIVILEGED_ACCOUNTS:
            raise PrivilegedIdentityRefused(
                f"refusing to run the CORPUSfm {identity.role} service as {identity.account!r}"
            )
    else:
        raise PrivilegedIdentityRefused(f"unknown platform flavour {identity.flavour!r}")
    return identity



# ── the service command, structurally ─────────────────────────────────────────────────
#
# F2. Validating a command STRING is a losing game: `/opt/CORPUSfm/py --config /tmp/outside.yml`
# has a layout-derived first token and an outside path three tokens later, and scanning the rest
# for "path-like" fragments is a heuristic pretending to be a boundary. So a caller no longer
# supplies a command at all. The role and the layout determine the executable and the whole argv,
# and every argument is one of exactly two kinds:
#
#   Literal  — a non-path value, allowlisted by exact spelling
#   PathArg  — a path, validated against the resolved layout like any other path field
#
# There is no third kind and no free-text escape, so "a future path argument" cannot arrive as an
# opaque string: it has to be a PathArg, which is checked by construction.

POSIX_INTERPRETER = "venv/bin/python"
WINDOWS_INTERPRETER = r"python\python.exe"

#: role → the module the service runs. The only per-role variation there is.
#:
#: `corpusfm.server.scheduler` is GONE from this map (packet 1361-01, round 3). It is no longer a
#: runnable module: scheduling is a background component of the web process, and the module's
#: `__main__` exits 2 with the reason so an obsolete unit stops loudly instead of crash-looping in
#: silence. A definition that named it would therefore render a service that cannot start, which is
#: why the role is removed from `SERVICE_ROLES` and its module from here in the same change.
SERVICE_MODULES: dict = {
    "web": "corpusfm.app.web",
}

#: Every non-path argument any CORPUSfm service definition may carry, by exact spelling. Widening
#: this is a visible edit; passing an unlisted one is a refusal, not a warning.
ALLOWED_ARGUMENT_LITERALS: frozenset = frozenset({"-m"} | set(SERVICE_MODULES.values()))

#: Environment variable names whose VALUE is a path. Listed separately from the literal-valued ones
#: so that "is this name allowed" has an answer before anything looks at what kind of value it
#: carries — a `PathArg` used to skip the name check entirely by `continue`-ing past it.
ALLOWED_PATH_ENVIRONMENT: frozenset = frozenset({"CORPUSFM_ARCHIVE_DIR"})

#: Environment variables a definition may set, each with the exact values it may take.
ALLOWED_ENVIRONMENT: dict = {
    "CORPUSFM_MODE": frozenset({"server"}),
    "PYTHONUNBUFFERED": frozenset({"1"}),
    "PYTHONDONTWRITEBYTECODE": frozenset({"1"}),
}

class CommandNotRoleDerived(LifecycleError):
    """A definition's command is not the one its role and layout determine."""


@dataclass(frozen=True)
class Literal:
    """A non-path argument, accepted only if allowlisted by exact spelling."""

    value: str


@dataclass(frozen=True)
class PathArg:
    """A path argument. Validated against the layout exactly like a path field, because it is one."""

    path: str


@dataclass(frozen=True)
class ServiceCommand:
    """What a service runs: a derived interpreter plus a structural argv."""

    executable: str
    argv: tuple = ()

    def path_parts(self) -> tuple:
        return (self.executable,) + tuple(a.path for a in self.argv if isinstance(a, PathArg))


def interpreter_for(flavour: str, install_dir) -> str:
    root = canonical_install_dir(flavour, install_dir)
    sep = "/" if flavour == POSIX else "\\"
    return f"{root.rstrip(sep)}{sep}" + (POSIX_INTERPRETER if flavour == POSIX
                                         else WINDOWS_INTERPRETER)


def service_command(role: str, layout: OsLayout, install_dir) -> ServiceCommand:
    """The command for one role — derived, never supplied.

    *(1246-04 owns making the installed bundle match these constants; this child owns the fact that
    there is exactly one place the command comes from.)*
    """
    if role not in SERVICE_MODULES:
        raise PrivilegedIdentityRefused(f"unknown service role {role!r}")
    return ServiceCommand(
        executable=interpreter_for(layout.flavour, install_dir),
        argv=(Literal("-m"), Literal(SERVICE_MODULES[role])),
    )


def assert_command_is_role_derived(command: ServiceCommand, role: str, layout: OsLayout,
                                   install_dir) -> None:
    """The renderer's own check, so constructing the dataclass directly is not a way around the
    builder. A boundary only the builder enforces is a boundary the next caller skips."""
    if not isinstance(command, ServiceCommand):
        raise CommandNotRoleDerived(
            f"the {role} definition's command must be a ServiceCommand, not {type(command).__name__}"
        )
    expected = service_command(role, layout, install_dir)
    if command.executable != expected.executable:
        raise CommandNotRoleDerived(
            f"the {role} definition runs {command.executable!r}; this role and layout determine "
            f"{expected.executable!r}. The command is derived, not chosen."
        )
    for argument in command.argv:
        if isinstance(argument, Literal):
            if argument.value not in ALLOWED_ARGUMENT_LITERALS:
                raise CommandNotRoleDerived(
                    f"the {role} definition passes {argument.value!r}, which is not an allowlisted "
                    "argument. A non-path argument must be listed by exact spelling; a path "
                    "argument must be a PathArg so the layout check applies to it."
                )
        elif isinstance(argument, PathArg):
            assert_paths_are_layout_derived((argument.path,), layout, install_dir=install_dir,
                                            what=f"{role} command")
        else:
            raise CommandNotRoleDerived(
                f"the {role} definition carries a {type(argument).__name__} argument; the only "
                "kinds are Literal and PathArg, and an opaque string is neither"
            )
    if command.argv != expected.argv:
        raise CommandNotRoleDerived(
            f"the {role} definition's arguments are not the ones its role determines "
            f"({expected.argv!r})"
        )


def assert_environment_is_allowlisted(environment, layout: OsLayout, role: str,
                                      install_dir) -> None:
    """Same rule for `Environment=`/`<env>`: a listed literal, or a PathArg that gets checked."""
    for name, value in environment:
        # The NAME first, always. Dispatching on the value's kind before authorizing the name let a
        # PathArg introduce any variable it liked — `LD_PRELOAD`, say — as long as its value
        # happened to sit inside the layout.
        key = str(name)
        if key not in ALLOWED_ENVIRONMENT and key not in ALLOWED_PATH_ENVIRONMENT:
            raise CommandNotRoleDerived(
                f"the {role} definition sets {name!r}, which is not an allowlisted environment "
                "variable for a CORPUSfm service definition"
            )
        if isinstance(value, PathArg):
            if key in ALLOWED_ENVIRONMENT:
                raise CommandNotRoleDerived(
                    f"the {role} definition gives {name!r} a path value; that variable is declared "
                    "as carrying an allowlisted literal, not a path"
                )
            assert_paths_are_layout_derived((value.path,), layout, install_dir=install_dir,
                                            what=f"{role} environment {name}")
            continue
        allowed = ALLOWED_ENVIRONMENT.get(key)
        if allowed is None:
            raise CommandNotRoleDerived(
                f"the {role} definition gives {name!r} a literal value; that variable is declared "
                "as carrying a path"
            )
        if str(value) not in allowed:
            raise CommandNotRoleDerived(
                f"the {role} definition sets {name}={value!r}; the allowed values are "
                f"{sorted(allowed)}"
            )


def _systemd_quote(word: str) -> str:
    """systemd splits ExecStart on whitespace unless quoted, and honours backslash escapes."""
    if word and not any(c.isspace() or c in '"\'' for c in word):
        return word
    return '"' + word.replace("\\", "\\\\").replace('"', '\\"') + '"'


def render_command(command: ServiceCommand) -> str:
    words = [command.executable] + [
        a.value if isinstance(a, Literal) else a.path for a in command.argv
    ]
    return " ".join(_systemd_quote(w) for w in words)


def command_arguments(command: ServiceCommand) -> str:
    """The argv WITHOUT the executable — what WinSW puts in `<arguments>`."""
    return " ".join(
        _systemd_quote(a.value if isinstance(a, Literal) else a.path) for a in command.argv
    )


# ── systemd ───────────────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class SystemdUnitSpec:
    """One unit's definition. `layout` is REQUIRED, not optional, and that is deliverable 2.

    An optional layout is the same hole with a politer name: whatever a caller may omit, some
    caller eventually does. Carrying it on the spec means there is no way to reach a renderer
    without having said which installation the paths belong to.
    """

    layout: OsLayout
    identity: ServiceIdentity
    install_dir: str
    description: str
    command: ServiceCommand
    working_directory: str
    read_write_paths: tuple[str, ...]
    environment: tuple = ()
    after: str = "network.target"
    environment_file: str | None = None
    uses_scoped_privilege_brokers: bool = False


def render_systemd_unit(spec: SystemdUnitSpec) -> str:
    """Render one unit, refusing anything privileged before a byte is produced.

    `ReadWritePaths` names the role's derived writable paths. Both roles receive **state, logs, run
    and the patch compartment**. The web role also receives the config-directory mount needed by
    the application-owned `install.yaml` writer; POSIX ownership remains the entry-level boundary
    (`/etc/corpusfm` and `locator.json` are root-owned, while only `install.yaml` is service-owned).
    The secrets directory is absent, and now so is every file inside it: the runtime reads secrets
    and does not write them (parent D4). The one former exception, `.mcp_env`, went with the
    server-wide MCP token (packet 1258) — there is no runtime-writable secret at all.

    There is ONE field that can carry a write grant. A spec used to have three — `read_write_paths`,
    a file-level `extra_read_write_files`, and `inaccessible_paths` to fence the scheduler off the
    file the second one granted. All three existed for `.mcp_env`, and an early version validated
    only the first, so the secrets directory reached `ReadWritePaths` intact through the second door.
    The doors are gone with the secret (packet 1258): one field, one check, nothing to keep in sync.
    """
    assert_unprivileged(spec.identity)
    if spec.identity.flavour != POSIX:
        raise PrivilegedIdentityRefused(
            f"a systemd unit needs a POSIX identity, got {spec.identity.flavour!r}"
        )
    if not spec.read_write_paths:
        raise ServiceIdentityMissing(
            "a CORPUSfm systemd unit must name the paths it may write; an empty ReadWritePaths "
            "with ProtectSystem=strict is either a mistake or a service that cannot run"
        )
    if spec.uses_scoped_privilege_brokers and spec.identity.role != WEB_ROLE:
        raise PrivilegedIdentityRefused(
            "only the web role owns installer-provisioned scoped privilege brokers"
        )
    for path in spec.read_write_paths:
        if _looks_like_secrets_dir(path):
            raise PrivilegedIdentityRefused(
                f"refusing to grant the CORPUSfm {spec.identity.role} service write access to the "
                f"secrets directory {path!r}. Installed secrets are read-only to the runtime, "
                "without exception (packet 1258)."
            )
    _assert_layout(spec.layout, spec.identity.role)
    for label, value in (
            ("the service account", spec.identity.account),
            ("the description", spec.description),
            ("the After= dependency", spec.after),
            ("the working directory", spec.working_directory),
            ("the executable", spec.command.executable),
            ("the environment file", spec.environment_file or ""),
    ):
        if value:
            _assert_systemd_safe(value, what=label)
    for argument in spec.command.argv:
        _assert_systemd_safe(getattr(argument, "value", getattr(argument, "path", argument)),
                             what="a command argument")
    for path in tuple(spec.read_write_paths):
        _assert_systemd_safe(path, what="a granted path")
    for name, value in spec.environment:
        _assert_systemd_safe(name, what="an environment variable name")
        _assert_systemd_safe(getattr(value, "path", value), what="an environment value")
    assert_command_is_role_derived(spec.command, spec.identity.role, spec.layout, spec.install_dir)
    assert_environment_is_allowlisted(spec.environment, spec.layout, spec.identity.role,
                                      spec.install_dir)
    assert_paths_are_layout_derived(
        tuple(spec.read_write_paths) + spec.command.path_parts()
        + ((spec.environment_file,) if spec.environment_file else ())
        + (spec.working_directory,),
        spec.layout, install_dir=spec.install_dir, what=f"{spec.identity.role} systemd unit")
    env_lines = "".join(
        f"Environment={k}={v.path if isinstance(v, PathArg) else v}\n"
        for k, v in spec.environment)
    if spec.environment_file:
        env_lines += f"EnvironmentFile={spec.environment_file}\n"
    rw = "".join(f"ReadWritePaths={p}\n" for p in spec.read_write_paths)
    return (
        "[Unit]\n"
        f"Description={spec.description}\n"
        f"After={spec.after}\n"
        "StartLimitIntervalSec=60\n"
        "StartLimitBurst=5\n"
        "\n"
        "[Service]\n"
        "Type=simple\n"
        f"User={spec.identity.account}\n"
        f"Group={spec.identity.account}\n"
        f"WorkingDirectory={spec.working_directory}\n"
        f"{env_lines}"
        f"NoNewPrivileges={'no' if spec.uses_scoped_privilege_brokers else 'yes'}\n"
        "ProtectSystem=strict\n"
        "ProtectHome=yes\n"
        "PrivateTmp=yes\n"
        f"{rw}"
        f"ExecStart={render_command(spec.command)}\n"
        "Restart=always\n"
        "RestartSec=5\n"
        "StandardOutput=journal\n"
        "StandardError=journal\n"
        "\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n"
    )


def _assert_layout(layout, role: str) -> None:
    """A required dataclass field can still be handed `None`. Rendering is where that stops."""
    if not isinstance(layout, OsLayout):
        raise DefinitionNotLayoutDerived(
            f"the {role} definition carries no layout ({layout!r}); every path in a definition is "
            "checked against the installation it belongs to, and there is nothing to check against"
        )


def _looks_like_secrets_dir(path: str) -> bool:
    """True when this entry hands over a whole secrets directory rather than one file.

    Name-based rather than layout-based on purpose: the renderer must refuse the shape even when it
    is handed a literal from somewhere it does not recognise, which is precisely the case the
    layout-derivation check cannot see. Any `secrets` component counts, not only the basename — a
    grant of `…/secrets/sub` is directory authority inside the compartment just the same.

    There is no longer any exempt basename: `.mcp_env` was the only one and it no longer exists
    (packet 1258), so ANY path through a secrets directory is refused.
    """
    p = PurePosixPath(str(path))
    return any(part.lower() == "secrets" for part in p.parts)


# ── WinSW ─────────────────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class WinswServiceSpec:
    """See `SystemdUnitSpec`: `layout` is required for the same reason."""

    layout: OsLayout
    identity: ServiceIdentity
    service_id: str
    display_name: str
    description: str
    command: ServiceCommand
    working_directory: str
    log_path: str
    install_dir: str = ""
    environment: tuple = ()


def render_winsw_service(spec: WinswServiceSpec) -> str:
    """Render one WinSW definition. **Always** carries `<serviceaccount>`.

    There is no code path that omits it, which is the whole correction: the previous definition was
    privileged not because it chose LocalSystem but because it said nothing, and silence is a choice
    Windows makes for you.
    """
    assert_unprivileged(spec.identity)
    if spec.identity.flavour != WINDOWS:
        raise PrivilegedIdentityRefused(
            f"a WinSW definition needs a Windows identity, got {spec.identity.flavour!r}"
        )
    _assert_layout(spec.layout, spec.identity.role)
    assert_command_is_role_derived(spec.command, spec.identity.role, spec.layout, spec.install_dir)
    assert_environment_is_allowlisted(spec.environment, spec.layout, spec.identity.role,
                                      spec.install_dir)
    assert_paths_are_layout_derived(
        (spec.working_directory, spec.log_path) + spec.command.path_parts(), spec.layout,
        install_dir=spec.install_dir, what=f"{spec.identity.role} WinSW definition")
    t = _xml_escape  # every interpolated value; see _assert_xml_safe for why escaping is not enough
    for value in (spec.service_id, spec.display_name, spec.description, spec.command.executable,
                  command_arguments(spec.command), spec.working_directory, spec.log_path,
                  spec.identity.account):
        _assert_xml_safe(value)
    env = "".join(
        f"  <env name={_xml_quoteattr(str(k))} "
        f"value={_xml_quoteattr(v.path if isinstance(v, PathArg) else str(v))} />\n"
        for k, v in spec.environment
    )
    return (
        "<service>\n"
        f"  <id>{t(spec.service_id)}</id>\n"
        f"  <name>{t(spec.display_name)}</name>\n"
        f"  <description>{t(spec.description)}</description>\n"
        f"  <executable>{t(spec.command.executable)}</executable>\n"
        f"  <arguments>{t(command_arguments(spec.command))}</arguments>\n"
        f"  <workingdirectory>{t(spec.working_directory)}</workingdirectory>\n"
        "  <serviceaccount>\n"
        f"    <username>{t(spec.identity.account)}</username>\n"
        "    <allowservicelogon>true</allowservicelogon>\n"
        "  </serviceaccount>\n"
        f"{env}"
        '  <onfailure action="restart" delay="5 sec" />\n'
        "  <log mode=\"roll-by-size\"><sizeThreshold>10240</sizeThreshold>"
        "<keepFiles>4</keepFiles></log>\n"
        f"  <logpath>{t(spec.log_path)}</logpath>\n"
        "</service>\n"
    )


#: Characters that end a systemd directive. A value carrying one does not "contain a newline" — it
#: appends a directive of the attacker's choosing to the unit, which is a different kind of defect
#: from a malformed string.
_SYSTEMD_FORBIDDEN = frozenset("\n\r\x00")


def _assert_systemd_safe(value, *, what: str) -> None:
    """Refuse any value that could create a second directive. Never strip, never fold.

    Stripping would silently render something other than what the caller asked for, and folding a
    newline into a space produces a plausible-looking unit nobody wrote. The WinSW XML boundary is
    kept SEPARATE and unchanged: two output formats, two escaping rules, and one that happens to be
    correct is no evidence about the other.
    """
    text = str(value)
    bad = [c for c in text if c in _SYSTEMD_FORBIDDEN or (ord(c) < 0x20 and c != "\t")]
    if bad:
        raise DefinitionNotLayoutDerived(
            f"refusing to render {what}: the value contains {bad[0]!r}, which would end the "
            "directive and start another one inside the unit"
        )


def _assert_xml_safe(value: str) -> None:
    """Refuse a value XML cannot carry, instead of escaping it into something plausible.

    Escaping handles `&`, `<` and `>`. It does not handle a NUL or a stray control character —
    those are not representable in XML 1.0 at all, and an escaper that silently emits them produces
    a definition that parses on this machine and is rejected by the service manager on the box.
    """
    text = str(value)
    bad = [c for c in text if ord(c) < 0x20 and c not in "\t\n\r"]
    if bad:
        raise DefinitionNotLayoutDerived(
            f"refusing to render a service definition containing a control character "
            f"({bad[0]!r}) — XML cannot carry it and the service manager would reject the result"
        )


def service_definition_names_an_identity(text: str) -> bool:
    """True when a rendered WinSW definition names a service account.

    A helper rather than a regex at each call site, because the guard tests need to assert the
    ABSENCE case — and asserting absence against a hand-written pattern is how the original defect
    stayed invisible.
    """
    lowered = text.lower()
    return "<serviceaccount>" in lowered and "<username>" in lowered


def systemd_definition_names_an_identity(text: str) -> bool:
    """True when a rendered systemd unit names an UNPRIVILEGED identity in both directives.

    **The Linux read-back used the WinSW predicate above (packet 1246-10-04).** That one looks for
    `<serviceaccount>` and `<username>`, which no systemd unit contains, so the phase-20 read-back
    could never pass — measured on fms-server 2026-08-08, where a correctly rendered
    `User=corpusfm` / `Group=corpusfm` unit was refused as naming no identity. It had never fired
    because no Linux run had reached phase 20 before.

    Both directives are required, and `root` is refused explicitly: a unit that names the superuser
    names an identity, and it is exactly the one this check exists to keep out.
    """
    found: dict[str, str] = {}
    for line in text.splitlines():
        stripped = line.strip()
        for directive in ("User", "Group"):
            prefix = f"{directive}="
            if stripped.startswith(prefix):
                found[directive] = stripped[len(prefix):].strip()
    if set(found) != {"User", "Group"}:
        return False
    return all(value and value.lower() != "root" and value != "0" for value in found.values())


# ── definitions derived from the published layout ─────────────────────────────────────
#
# Deliverable 2. The renderers above accept strings, because a renderer that resolved its own
# layout could not be tested against a temporary one. That freedom is exactly the hole: an
# installer literal that happens to match today keeps rendering after the layout moves, and the
# resulting definition is wrong in the one way nothing reports — it names a directory the
# application no longer uses. So the specs a real installation uses are BUILT here, from an
# `OsLayout`, and `assert_paths_are_layout_derived` is available to any caller holding a spec it
# did not build.

PATCH_COMPARTMENT_DIRNAME = "patch"


class InstallDirNotSupplied(LifecycleError):
    """A definition was built without being told which installation it belongs to.

    Its own error class because it is the failure the DEFAULT ROOT used to hide. `_install_dir_for`
    answered `DEFAULT_POSIX_INSTALL_DIR` / `DEFAULT_WINDOWS_INSTALL_DIR` for every caller, so a
    definition built for an installation at `/srv/CORPUSfm` or `D:\\CORPUSfm` silently named the
    platform default instead - and it named it in `ExecStart`, in `<executable>`, and in the root
    every other path was checked against. Nothing reported it: the definition rendered, the
    read-back compared the same wrong value to itself, and only starting the service found out.
    So there is no default any more, and no fallback: the install directory is supplied or the
    build refuses.
    """


def canonical_install_dir(flavour: str, install_dir) -> str:
    """The one authoritative install directory for a definition - validated, never defaulted.

    Absolute and canonical for the TARGET platform, checked with that platform's own semantics even
    when the definition is rendered elsewhere. `DEFAULT_POSIX_INSTALL_DIR` and
    `DEFAULT_WINDOWS_INSTALL_DIR` remain as what a stock installation chooses; they are no longer
    what a caller gets for saying nothing.
    """
    if install_dir is None or not str(install_dir).strip():
        raise InstallDirNotSupplied(
            "a service definition must be told its install directory; there is no platform default "
            "to fall back to, because falling back is how a definition comes to name a directory "
            "the installation does not use"
        )
    canon = str(_canonical_path(flavour, install_dir, what="the install directory"))
    _assert_agrees_with_published(flavour, canon)
    return canon


def _assert_agrees_with_published(flavour: str, canon: str) -> None:
    """A SUPPLIED root is an input, never a nomination. It must agree with the published record.

    This is the surviving half of the rule the retired no-parameter design was protecting: *a
    boundary the caller draws is not a boundary*. Removing the parameter did protect it - and paid
    for it with a silent platform default that named the wrong directory on any installation not at
    the stock root, which is the defect correction E removes. So the parameter comes back and the
    rule is enforced where it belongs: **on a PUBLISHED installation the supplied root must be the
    published one.**

    Before publication there is nothing to disagree with. That is not a gap: on a fresh box the
    invocation IS the authority, and `composition foundation` publishes exactly the root the
    installer was invoked with - after which every later build is bound by this check.
    """
    try:
        from .published import InstallationNotPublished, read_published_installation
    except Exception:  # pragma: no cover - the reader is part of this package
        return
    try:
        record = read_published_installation()
    except InstallationNotPublished:
        return
    except LifecycleError:
        # An installation that publishes something unreadable is 03-01's refusal to make, not a
        # licence for this module to fall back to a default and render against a guess.
        raise
    try:
        published_root = str(_canonical_path(flavour, record.install_dir,
                                             what="the published install directory"))
    except DefinitionNotLayoutDerived:
        raise
    if _pure(flavour, published_root) != _pure(flavour, canon):
        raise DefinitionNotLayoutDerived(
            f"a service definition was built for install directory {canon!r}, but this installation "
            f"publishes {published_root!r}. The supplied root is an input, not a nomination: a "
            "definition that names a root the installation does not use is wrong in the one way "
            "nothing reports until the service fails to start."
        )


def _pure(flavour: str, value):
    return PurePosixPath(str(value)) if flavour == POSIX else PureWindowsPath(str(value))


def layout_writable_paths(layout: OsLayout) -> tuple[str, ...]:
    """What a CORPUSfm service may write: its own state, logs, run directory and compartment.

    The secrets directory is absent and stays absent. `patch/` is a child of state rather than a
    sixth top-level location, so the layout owns it without OsLayout having to grow a field the
    manifest does not record.
    """
    return (
        str(layout.state_dir),
        str(layout.log_dir),
        str(layout.run_dir),
        str(layout.state_dir / PATCH_COMPARTMENT_DIRNAME),
    )


def assert_paths_are_layout_derived(paths, layout: OsLayout, *, install_dir,
                                    what: str = "definition") -> None:
    """Every path must sit inside the published layout or the install directory. No exceptions.

    **Canonical, never lexical.** `PurePath.relative_to()` does not collapse `..`, so
    `/opt/CORPUSfm/../../tmp/outside` compared equal to something inside the install root while
    resolving well outside it. Both the candidate and every authorized root are canonicalized first,
    with the target platform's own semantics — Windows keeps its drive/UNC anchor and its
    case-insensitivity even when the definition is rendered on a POSIX machine.

    On POSIX, canonicalization is **effective**: `realpath` resolves symbolic links, so an existing
    link inside an authorized root cannot point out of it. Anything unevaluable — empty, relative,
    drive-relative, or climbing above its own anchor — is **refused rather than guessed at**.
    """
    roots = [_canonical_path(layout.flavour, d, what="the published layout")
             for d in layout.all_dirs()]
    roots.append(_canonical_path(layout.flavour,
                                 canonical_install_dir(layout.flavour, install_dir),
                                 what="the install directory"))
    for raw in paths:
        candidate = _canonical_path(layout.flavour, raw, what=what)
        if not any(candidate == root or _is_relative_to(candidate, root) for root in roots):
            raise DefinitionNotLayoutDerived(
                f"the {what} names {raw!r}, which resolves to {str(candidate)!r} — not inside the "
                f"published layout ({', '.join(str(r) for r in roots)}). Every path a definition "
                "grants is derived from the resolved layout; an installer literal is how a "
                "definition and an application end up disagreeing about where the installation is."
            )


def _canonical_path(flavour: str, raw, *, what: str):
    """One absolute, `..`-free, platform-correct form of a path — or a refusal."""
    text = str(raw)
    if not text.strip():
        raise DefinitionNotLayoutDerived(f"the {what} names an empty path")
    pure = _pure(flavour, text)
    if not pure.is_absolute():
        # Covers a bare relative path AND a Windows drive-relative one (`C:foo`), which names a
        # different directory per-process and cannot be evaluated here at all.
        raise DefinitionNotLayoutDerived(
            f"the {what} names {text!r}, which is not an absolute path; a definition's paths are "
            "evaluated against the installation, and a relative one has no evaluable meaning here"
        )
    anchor, parts = pure.anchor, pure.parts[1:] if pure.anchor else pure.parts
    collapsed: list = []
    for part in parts:
        if part in (".", ""):
            continue
        if part == "..":
            if not collapsed:
                raise DefinitionNotLayoutDerived(
                    f"the {what} names {text!r}, which climbs above {anchor!r}"
                )
            collapsed.pop()
            continue
        collapsed.append(part)
    canon = _pure(flavour, anchor).joinpath(*collapsed)
    if flavour == POSIX and os.name != "nt":
        # The real filesystem is available, so resolve links too: lexical canonicalization alone
        # leaves `secrets -> /tmp/elsewhere` looking like it is inside the layout.
        return PurePosixPath(os.path.realpath(str(canon)))
    return canon


def _is_relative_to(candidate, root) -> bool:
    try:
        candidate.relative_to(root)
        return True
    except ValueError:
        return False


def systemd_unit_spec(role: str, layout: OsLayout, *, install_dir, description: str,
                      environment: tuple = ()) -> SystemdUnitSpec:
    """The unit spec for one role, with every path taken from `layout`.

    The web service carries the config-directory mount grant needed to update its service-owned
    `install.yaml`; the scheduler does not. That asymmetry is a role boundary: both services run as
    the same `corpusfm` account, so the separation cannot come from account identity alone. The
    second asymmetry — the web-only `.mcp_env` grant and the scheduler's matching
    `InaccessiblePaths=` — went with the server-wide MCP token (packet 1258): no definition carries
    a secret, so neither role needs to be fenced off from one.
    The root-owned 0755 config directory still refuses the web role creation/deletion authority;
    making the mount writable only lets it update the existing service-owned 0600 marker. A second
    Unix account was explicitly ruled out, and inventing one here would look like tidying up.
    """
    if role not in SERVICE_ROLES:
        raise PrivilegedIdentityRefused(f"unknown service role {role!r}")
    if layout.flavour != POSIX:
        raise DefinitionNotLayoutDerived(
            f"a systemd unit needs the POSIX layout, got {layout.flavour!r}"
        )
    root = canonical_install_dir(POSIX, install_dir)
    writable = layout_writable_paths(layout)
    if role == WEB_ROLE:
        # OP-015, directly measured under ProtectSystem=strict: an exact-file ReadWritePaths grant
        # fails with EROFS because the existing private writer unlinks before falling back to an
        # in-place truncate. Mount the PUBLISHED config directory writable in this namespace instead.
        # This does not bypass POSIX DAC: the directory + locator stay root:root 0755/0644, so the
        # service cannot create siblings or replace the locator; only its existing 0600 install.yaml
        # is writable. The scheduler has no settings writer and receives no such mount grant.
        writable += (str(layout.config_dir),)
    command = service_command(role, layout, root)
    assert_paths_are_layout_derived(
        writable + (root,) + command.path_parts(), layout, install_dir=root,
        what=f"{role} systemd unit")
    return SystemdUnitSpec(
        layout=layout,
        identity=posix_identity(role),
        install_dir=root,
        description=description,
        command=command,
        working_directory=root,
        read_write_paths=writable,
        environment=environment,
        # No unit loads an environment file any more: the only secret one ever carried was the
        # server-wide MCP token (packet 1258). The web process authenticates MCP callers against
        # the user store instead, so there is nothing to place, protect, or withhold.
        environment_file=None,
        # The web process calls only installer-provisioned sudoers brokers: the fixed DB helper
        # and `systemctl start corpusfm-update.service`. `NoNewPrivileges=yes` prevents sudo's
        # setuid transition before sudoers can enforce either narrow grant, making both installed
        # capabilities unusable. The scheduler owns no broker and retains the restriction.
        uses_scoped_privilege_brokers=role == WEB_ROLE,
    )


def winsw_service_spec(role: str, layout: OsLayout, *, install_dir, service_id: str,
                       display_name: str, description: str,
                       environment: tuple = ()) -> WinswServiceSpec:
    """The WinSW spec for one role, with every path taken from `layout`.

    No role's definition carries a secret. WinSW has no `EnvironmentFile=` equivalent, so a
    secret-bearing definition on Windows meant a literal token in the XML protected only by its
    DACL; the server-wide MCP token that forced that shape is gone (packet 1258), and with it the
    only reason a service definition ever held a credential.
    """
    if role not in SERVICE_ROLES:
        raise PrivilegedIdentityRefused(f"unknown service role {role!r}")
    if layout.flavour != WINDOWS:
        raise DefinitionNotLayoutDerived(
            f"a WinSW definition needs the Windows layout, got {layout.flavour!r}"
        )
    root = canonical_install_dir(WINDOWS, install_dir)
    log_path = str(layout.log_dir)
    command = service_command(role, layout, root)
    assert_paths_are_layout_derived(
        (log_path, root) + command.path_parts(), layout, install_dir=root,
        what=f"{role} WinSW definition")
    return WinswServiceSpec(
        layout=layout,
        identity=windows_virtual_account(service_id),
        install_dir=root,
        service_id=service_id,
        display_name=display_name,
        description=description,
        command=command,
        working_directory=root,
        log_path=log_path,
        environment=environment,
    )


# ── canonical service RECORDS (packet 1246-09, stage 1) ───────────────────────────────────────
#
# The uninstaller may not remove a service on a name. O4 requires role, name, definition path,
# observed resolution, executable containment and identity — and the first three have to be
# RECORDED at install time, because afterwards nothing on the box can supply them.
#
# The names below were previously constants inside each installer, and the two disagreed: Linux
# called the web unit `corpusfm`, Windows called it `corpusfm-web`. That disagreement is exactly why
# they belong here — a name held in two places is a name that can differ.

POSIX_SERVICE_NAMES: dict[str, str] = {WEB_ROLE: "corpusfm", SCHEDULER_ROLE: "corpusfm-scheduler"}
WINDOWS_SERVICE_NAMES: dict[str, str] = {WEB_ROLE: "corpusfm-web",
                                         SCHEDULER_ROLE: "corpusfm-scheduler"}

#: Where each platform's service manager reads its definition from.
POSIX_UNIT_DIR = "/etc/systemd/system"
WINDOWS_SERVICE_SUBDIR = "services"

# ── the MANAGED UNIT vocabulary (packet 1246-09 §Y) ───────────────────────────────────────────
#
# `SERVICE_ROLES` means *the CORPUSfm services the definition renderer produces* — the web service,
# and since packet 1361-01 round 3 that is all of them. The privileged updater is not one: on POSIX
# it is a one-shot systemd unit, and on Windows it is a **scheduled task**, not a service at all.
# Neither is the retired scheduler service, which is removable and never rendered.
#
# It was previously nowhere. An uninstall that must remove it had no recorded name, no recorded
# definition path and no expected identity, so both executors invented constants — the same
# category of authority this packet retired for services. **A broader vocabulary is the honest
# answer**: the updater is a MANAGED UNIT this installation created, and it is recorded like one,
# without pretending it is a WinSW service or widening the rendering roles to include it.

UPDATER_ROLE = "updater"

#: Every role the installation records and may later remove. The renderer still produces only
#: `SERVICE_ROLES`; a role here that is not there is managed but not rendered — which is true of the
#: updater (a scheduled task on Windows) and, since packet 1361-01 round 3, of the retired scheduler
#: service. Both must stay valid in a stored record, or an installation made by an earlier build
#: would fail to validate and could not be uninstalled.
MANAGED_ROLES: tuple[str, ...] = REMOVABLE_SERVICE_ROLES + (UPDATER_ROLE,)

#: How each managed role is registered with the platform, because removal differs by kind.
UNIT_KIND_SERVICE = "service"
UNIT_KIND_SCHEDULED_TASK = "scheduled_task"
UNIT_KINDS: tuple[str, ...] = (UNIT_KIND_SERVICE, UNIT_KIND_SCHEDULED_TASK)

POSIX_UPDATER_UNIT_NAME = "corpusfm-update"
POSIX_UPDATER_UNIT_PATH = f"{POSIX_UNIT_DIR}/{POSIX_UPDATER_UNIT_NAME}.service"

#: The Windows updater is a SCHEDULED TASK. Its display name is the registration identity, and the
#: script it runs is the recorded definition.
WINDOWS_UPDATER_TASK_NAME = "CORPUSfm Update"
WINDOWS_UPDATER_SCRIPT_RELATIVE = r"bin\corpusfm-update.ps1"

#: The updater runs privileged — that is its entire reason for existing (packet 1246-03: the
#: services are unprivileged, and a privileged one-shot performs what they may not).
POSIX_UPDATER_IDENTITY = "root"
WINDOWS_UPDATER_IDENTITY = "SYSTEM"


def updater_records(flavour: str, install_dir) -> dict:
    """The updater's managed-unit facts, per platform. Recorded, never inferred at removal time."""
    if flavour == POSIX:
        return {
            "role": UPDATER_ROLE,
            "name": POSIX_UPDATER_UNIT_NAME,
            "identity": POSIX_UPDATER_IDENTITY,
            "unit": POSIX_UPDATER_UNIT_PATH,
            "unit_kind": UNIT_KIND_SERVICE,
        }
    if flavour == WINDOWS:
        root = canonical_install_dir(WINDOWS, install_dir)
        separator = "" if root.endswith("\\") else "\\"
        return {
            "role": UPDATER_ROLE,
            "name": WINDOWS_UPDATER_TASK_NAME,
            "identity": WINDOWS_UPDATER_IDENTITY,
            "unit": f"{root}{separator}{WINDOWS_UPDATER_SCRIPT_RELATIVE}",
            "unit_kind": UNIT_KIND_SCHEDULED_TASK,
        }
    raise PrivilegedIdentityRefused(f"unknown platform flavour {flavour!r}")


def service_name(role: str, flavour: str) -> str:
    # REMOVABLE, not rendered: an uninstall of a box that still carries the retired scheduler
    # service must be able to name it (packet 1361-01, round 3).
    if role not in REMOVABLE_SERVICE_ROLES:
        raise PrivilegedIdentityRefused(f"unknown service role {role!r}")
    try:
        return {POSIX: POSIX_SERVICE_NAMES, WINDOWS: WINDOWS_SERVICE_NAMES}[flavour][role]
    except KeyError as exc:
        raise PrivilegedIdentityRefused(f"unknown platform flavour {flavour!r}") from exc


def service_definition_path(role: str, flavour: str, install_dir) -> str:
    """The ABSOLUTE path of the file the service manager reads for this role.

    POSIX: the systemd unit under ``/etc/systemd/system``. Windows: the WinSW XML inside the
    installation's own ``services\\`` directory. Recorded so a later uninstall can require that the
    observed service resolves to THIS file rather than to a same-named one somebody else installed.
    """
    name = service_name(role, flavour)
    if flavour == POSIX:
        return f"{POSIX_UNIT_DIR}/{name}.service"
    root = canonical_install_dir(WINDOWS, install_dir)
    separator = "" if root.endswith("\\") else "\\"
    return f"{root}{separator}{WINDOWS_SERVICE_SUBDIR}\\{name}.xml"


def expected_service_identity(role: str, flavour: str) -> str:
    """The account this role is expected to run as — the fifth element of O4's conjunction."""
    if flavour == POSIX:
        return posix_identity(role).account
    return windows_virtual_account(service_name(role, flavour)).account


def canonical_service_records(flavour: str, install_dir) -> tuple:
    """One `ServiceEntry` per role, for the foundation to publish.

    Returned as plain dicts rather than schema objects so this module keeps its existing direction
    of dependency — `schema` imports nothing from here, and the composition layer builds the typed
    records.
    """
    rendered = tuple(
        {
            "role": role,
            "name": service_name(role, flavour),
            "identity": expected_service_identity(role, flavour),
            "unit": service_definition_path(role, flavour, install_dir),
            "unit_kind": UNIT_KIND_SERVICE,
        }
        for role in SERVICE_ROLES
    )
    return rendered + (updater_records(flavour, install_dir),)
