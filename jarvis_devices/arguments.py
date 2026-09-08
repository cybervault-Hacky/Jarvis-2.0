"""Argument schemas and validation (Phase 1).

Tools declare what arguments they accept; the framework validates them *before*
any permission check and before any execution. Unknown keys are rejected, so a
tool can never be fed arguments it did not declare.

The schema is intentionally tiny and dependency free - it is not a JSON Schema
engine, just enough to keep tool inputs predictable.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Tuple, Type

__all__ = ["ArgumentSpec", "ArgumentSchema"]

_NAME_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")

#: Primitive types a tool argument may use.
ALLOWED_TYPES: Tuple[type, ...] = (str, int, float, bool)


@dataclass(frozen=True)
class ArgumentSpec:
    """Declaration of a single tool argument."""

    name: str
    type: Type[Any] = str
    required: bool = True
    default: Any = None
    choices: Optional[Tuple[Any, ...]] = None
    min_value: Optional[float] = None
    max_value: Optional[float] = None
    max_length: Optional[int] = None
    pattern: Optional[str] = None
    description: str = ""

    def __post_init__(self) -> None:
        if not _NAME_RE.match(self.name):
            raise ValueError(f"Invalid argument name: {self.name!r}")
        if self.type not in ALLOWED_TYPES:
            raise ValueError(f"Unsupported argument type for {self.name!r}: {self.type!r}")
        if self.choices is not None:
            object.__setattr__(self, "choices", tuple(self.choices))
            for choice in self.choices:
                if not isinstance(choice, self.type):
                    raise ValueError(f"Choice {choice!r} is not a {self.type.__name__} for {self.name!r}")
        if self.pattern is not None:
            re.compile(self.pattern)
        if self.required and self.default is not None:
            raise ValueError(f"Required argument {self.name!r} must not declare a default")

    # ------------------------------------------------------------------
    def validate_value(self, value: Any) -> List[str]:
        """Return a list of human readable problems for ``value``."""
        errors: List[str] = []
        name = self.name

        # bool is a subclass of int, so it has to be rejected explicitly.
        if self.type is not bool and isinstance(value, bool):
            errors.append(f"{name}: expected {self.type.__name__}, got bool")
            return errors
        if not isinstance(value, self.type):
            errors.append(f"{name}: expected {self.type.__name__}, got {type(value).__name__}")
            return errors

        if self.choices is not None and value not in self.choices:
            errors.append(f"{name}: {value!r} is not one of {list(self.choices)}")
        if self.min_value is not None and value < self.min_value:
            errors.append(f"{name}: {value!r} is below the minimum {self.min_value}")
        if self.max_value is not None and value > self.max_value:
            errors.append(f"{name}: {value!r} is above the maximum {self.max_value}")
        if self.max_length is not None and isinstance(value, (str, list, tuple)):
            if len(value) > self.max_length:
                errors.append(f"{name}: longer than {self.max_length} items")
        if self.pattern is not None and isinstance(value, str):
            if not re.search(self.pattern, value):
                errors.append(f"{name}: does not match the required pattern")
        return errors


class ArgumentSchema:
    """An ordered, immutable collection of :class:`ArgumentSpec`."""

    __slots__ = ("_specs", "_by_name")

    def __init__(self, *specs: ArgumentSpec) -> None:
        for spec in specs:
            if not isinstance(spec, ArgumentSpec):
                raise TypeError(f"ArgumentSchema expects ArgumentSpec, got {type(spec).__name__}")
        names = [spec.name for spec in specs]
        if len(set(names)) != len(names):
            raise ValueError("Duplicate argument names in schema")
        self._specs: Tuple[ArgumentSpec, ...] = tuple(specs)
        self._by_name: Dict[str, ArgumentSpec] = {spec.name: spec for spec in specs}

    # ------------------------------------------------------------------
    @classmethod
    def empty(cls) -> "ArgumentSchema":
        """A schema for tools that take no arguments at all."""
        return cls()

    # ------------------------------------------------------------------
    @property
    def specs(self) -> Tuple[ArgumentSpec, ...]:
        return self._specs

    @property
    def names(self) -> Tuple[str, ...]:
        return tuple(self._by_name)

    def __iter__(self):
        return iter(self._specs)

    def __len__(self) -> int:
        return len(self._specs)

    def __repr__(self) -> str:  # pragma: no cover - debugging helper
        return f"ArgumentSchema({', '.join(self.names)})"

    # ------------------------------------------------------------------
    def validate(self, raw: Optional[Mapping[str, Any]]) -> Tuple[Dict[str, Any], List[str]]:
        """Validate ``raw`` arguments.

        Returns ``(validated_arguments, errors)``. When ``errors`` is empty the
        validated mapping contains defaults filled in for optional arguments and
        nothing else.
        """
        errors: List[str] = []
        validated: Dict[str, Any] = {}
        provided = dict(raw or {})

        if not isinstance(provided, dict):
            return {}, ["arguments must be an object of name -> value"]

        for key in provided:
            if key not in self._by_name:
                errors.append(f"unexpected argument: {key!r}")

        for spec in self._specs:
            if spec.name not in provided:
                if spec.required:
                    errors.append(f"missing required argument: {spec.name!r}")
                else:
                    validated[spec.name] = spec.default
                continue
            value = provided[spec.name]
            spec_errors = spec.validate_value(value)
            if spec_errors:
                errors.extend(spec_errors)
            else:
                validated[spec.name] = value

        return validated, errors

    def to_json_schema(self) -> Dict[str, Any]:
        """Return a JSON Schema style description (used by later phases)."""
        properties: Dict[str, Any] = {}
        for spec in self._specs:
            entry: Dict[str, Any] = {"type": _JSON_TYPES[spec.type]}
            if spec.description:
                entry["description"] = spec.description
            if spec.choices is not None:
                entry["enum"] = list(spec.choices)
            if spec.min_value is not None:
                entry["minimum"] = spec.min_value
            if spec.max_value is not None:
                entry["maximum"] = spec.max_value
            if spec.max_length is not None:
                entry["maxLength"] = spec.max_length
            properties[spec.name] = entry
        return {
            "type": "object",
            "properties": properties,
            "required": [spec.name for spec in self._specs if spec.required],
            "additionalProperties": False,
        }


_JSON_TYPES: Dict[type, str] = {str: "string", int: "integer", float: "number", bool: "boolean"}
