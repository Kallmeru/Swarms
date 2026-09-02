"""Policy as configuration.

The enforcement rules are the same for everyone; the *things being enforced*
are not. A payments team guards `charge_card`, an infra team guards
`run_migration`, nobody outside this repo guards the three verbs that used to
be hardcoded in the policy module. So actions, their control arguments, and
who may invoke them all come from a file the operator owns.

    policy = Policy.load("swarms.yaml")

The file is small on purpose. Every field it does not have is a field an
operator cannot get wrong, and the defaults are the safe direction: an action
nobody declared is denied, a value nobody labeled is untrusted.

Loading is separate from enforcing. `swarms/policy.py` never reads a file and
never imports yaml, so the hot path stays dependency-free and a malformed
config fails at startup rather than at the moment an action needs deciding.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Iterable

DEFAULT_POLICY_FILENAMES = ("swarms.yaml", "swarms.yml", "swarms.json")


class PolicyError(ValueError):
    """Configuration that cannot be loaded. Raised at startup, never at
    decision time: a gateway that discovers its policy is broken while
    deciding an action has already failed."""


@dataclass(frozen=True)
class ActionSpec:
    """One privileged operation the system is allowed to know about."""

    name: str
    capability: str
    control_args: tuple[str, ...] = ()
    data_args: tuple[str, ...] = ()
    require_approval: bool = False
    description: str = ""

    def is_control(self, arg: str) -> bool:
        return arg in self.control_args

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "capability": self.capability,
            "control_args": list(self.control_args),
            "data_args": list(self.data_args),
            "require_approval": self.require_approval,
            "description": self.description,
        }


@dataclass(frozen=True)
class Principal:
    """An agent, service, or role, and what it was granted."""

    name: str
    capabilities: frozenset[str] = frozenset()
    description: str = ""

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "capabilities": sorted(self.capabilities),
            "description": self.description,
        }


@dataclass(frozen=True)
class Policy:
    version: int = 1
    name: str = "default"
    actions: dict[str, ActionSpec] = field(default_factory=dict)
    principals: dict[str, Principal] = field(default_factory=dict)
    # Fail-closed defaults. Both are settable because there are legitimate
    # staging setups that want to observe before enforcing, but neither
    # default is the permissive one.
    unknown_action: str = "deny"
    unknown_principal: str = "deny"
    unlabeled_value: str = "untrusted"
    # Shortest value that may be matched against ingested content when
    # recovering provenance. Below this, substring matching produces noise
    # rather than signal (see Session.classify).
    min_match_length: int = 4
    source_path: str | None = None

    # -- lookups -------------------------------------------------------------

    def action(self, name: str) -> ActionSpec | None:
        return self.actions.get(name)

    def capabilities_of(self, principal: str) -> frozenset[str]:
        known = self.principals.get(principal)
        if known is not None:
            return known.capabilities
        # An unrecognized principal gets nothing, so a typo in a principal
        # name fails safe instead of inheriting someone else's authority.
        return frozenset()

    def knows_principal(self, principal: str) -> bool:
        return principal in self.principals

    def to_dict(self) -> dict:
        return {
            "version": self.version,
            "name": self.name,
            "actions": {k: v.to_dict() for k, v in self.actions.items()},
            "principals": {k: v.to_dict() for k, v in self.principals.items()},
            "defaults": {
                "unknown_action": self.unknown_action,
                "unknown_principal": self.unknown_principal,
                "unlabeled_value": self.unlabeled_value,
                "min_match_length": self.min_match_length,
            },
            "source_path": self.source_path,
        }

    # -- construction --------------------------------------------------------

    @classmethod
    def from_dict(cls, raw: dict, source_path: str | None = None) -> "Policy":
        if not isinstance(raw, dict):
            raise PolicyError("policy must be a mapping")

        version = raw.get("version", 1)
        if version != 1:
            raise PolicyError(f"unsupported policy version {version!r}, this build understands version 1")

        actions: dict[str, ActionSpec] = {}
        for name, spec in (raw.get("actions") or {}).items():
            spec = spec or {}
            if not isinstance(spec, dict):
                raise PolicyError(f"action {name!r}: expected a mapping, got {type(spec).__name__}")
            control = tuple(spec.get("control_args") or ())
            data = tuple(spec.get("data_args") or ())
            overlap = set(control) & set(data)
            if overlap:
                raise PolicyError(
                    f"action {name!r}: {sorted(overlap)} listed as both control and data arguments. "
                    "An argument is either allowed to carry untrusted content or it is not."
                )
            capability = spec.get("capability")
            if not capability:
                raise PolicyError(
                    f"action {name!r}: no capability. Every action needs one, otherwise nothing "
                    "distinguishes who may call it."
                )
            # Omitting control_args is a mistake; declaring it empty is a
            # choice. An action with nothing grounded accepts a target chosen
            # by untrusted content, so it has to be written down deliberately
            # rather than arrived at by forgetting a line. lint() still flags it.
            if "control_args" not in spec:
                raise PolicyError(
                    f"action {name!r}: no control_args. Name the arguments that decide what this "
                    "action does to the world (recipient, path, url, amount). If this action really "
                    "has none, say so explicitly with 'control_args: []'."
                )
            actions[name] = ActionSpec(
                name=name,
                capability=capability,
                control_args=control,
                data_args=data,
                require_approval=bool(spec.get("require_approval", False)),
                description=spec.get("description", ""),
            )

        principals: dict[str, Principal] = {}
        for name, spec in (raw.get("principals") or {}).items():
            spec = spec or {}
            caps = frozenset(spec.get("capabilities") or ())
            principals[name] = Principal(name=name, capabilities=caps, description=spec.get("description", ""))

        defaults = raw.get("defaults") or {}
        policy = cls(
            version=version,
            name=raw.get("name", "default"),
            actions=actions,
            principals=principals,
            unknown_action=_enum(defaults, "unknown_action", ("deny", "allow"), "deny"),
            unknown_principal=_enum(defaults, "unknown_principal", ("deny", "allow"), "deny"),
            unlabeled_value=_enum(defaults, "unlabeled_value", ("untrusted", "trusted"), "untrusted"),
            min_match_length=int(defaults.get("min_match_length", 4)),
            source_path=source_path,
        )
        policy.validate()
        return policy

    @classmethod
    def load(cls, path: str) -> "Policy":
        if not os.path.exists(path):
            raise PolicyError(f"no policy file at {path}")
        with open(path, encoding="utf-8") as f:
            text = f.read()
        if path.endswith(".json"):
            raw = json.loads(text)
        else:
            # Imported here, not at module scope: the enforcement path must
            # stay importable without yaml installed.
            try:
                import yaml
            except ImportError as exc:  # pragma: no cover - depends on env
                raise PolicyError(
                    "reading a .yaml policy needs PyYAML (pip install pyyaml), "
                    "or write the policy as .json"
                ) from exc
            raw = yaml.safe_load(text)
        return cls.from_dict(raw or {}, source_path=os.path.abspath(path))

    @classmethod
    def discover(cls, start: str | None = None) -> "Policy":
        """Find a policy file by walking up from `start`, the way git finds a
        repo root. Falls back to the bundled default so that importing the
        library never hard-fails on a missing file."""
        env_path = os.environ.get("SWARMS_POLICY")
        if env_path:
            return cls.load(env_path)

        directory = os.path.abspath(start or os.getcwd())
        while True:
            for filename in DEFAULT_POLICY_FILENAMES:
                candidate = os.path.join(directory, filename)
                if os.path.exists(candidate):
                    return cls.load(candidate)
            parent = os.path.dirname(directory)
            if parent == directory:
                break
            directory = parent
        return cls.builtin()

    @classmethod
    def builtin(cls) -> "Policy":
        """The policy shipped with the package. Enough to run the red-team
        suite and to have something coherent before an operator writes their
        own; not a recommendation for anyone's production tool set."""
        return cls.load(os.path.join(os.path.dirname(os.path.abspath(__file__)), "default_policy.yaml"))

    # -- checks --------------------------------------------------------------

    def validate(self) -> "Policy":
        """Catch the mistakes that would otherwise show up as a silently
        permissive system."""
        problems: list[str] = []

        granted = {c for p in self.principals.values() for c in p.capabilities}
        required = {a.capability for a in self.actions.values()}

        for cap in sorted(granted - required):
            if "*" in cap:
                continue  # a wildcard grant covering actions added later is fine
            problems.append(
                f"capability {cap!r} is granted to a principal but no action requires it "
                "(typo, or a leftover grant)"
            )
        for name, action in self.actions.items():
            if not any(_capability_matches(c, action.capability) for c in granted):
                problems.append(
                    f"action {name!r} requires capability {action.capability!r}, which no principal holds, "
                    "so it can never be authorized"
                )
        if not self.actions:
            problems.append("policy declares no actions, so every privileged call will be denied")

        if problems:
            raise PolicyError(
                "policy problems:\n  - " + "\n  - ".join(problems)
            )
        return self

    def lint(self) -> list[str]:
        """Non-fatal advisories, for `swarms policy check`. Separate from
        validate() because an operator should be able to see these without
        being blocked from starting."""
        notes: list[str] = []
        for name, action in self.actions.items():
            if not action.control_args:
                notes.append(f"{name}: no control arguments, so nothing about this action is grounded")
            if action.require_approval and not action.control_args:
                notes.append(f"{name}: requires approval but grounds nothing, approval is carrying the whole check")
        for name, principal in self.principals.items():
            wildcards = [c for c in principal.capabilities if "*" in c]
            if wildcards:
                notes.append(f"{name}: holds wildcard capability {wildcards}, which will cover actions added later")
        return notes


def _enum(mapping: dict, key: str, allowed: Iterable[str], default: str) -> str:
    value = mapping.get(key, default)
    if value not in allowed:
        raise PolicyError(f"defaults.{key}: expected one of {sorted(allowed)}, got {value!r}")
    return value


def _capability_matches(granted: str, required: str) -> bool:
    """Wildcard-aware capability comparison. `email.*` covers `email.send`.

    fnmatch rather than a bespoke matcher, and `fnmatchcase` rather than
    `fnmatch`, because the latter lowercases on Windows and a capability
    check whose result depends on the host OS is a bug waiting to happen.
    """
    from fnmatch import fnmatchcase
    return granted == required or fnmatchcase(required, granted)
