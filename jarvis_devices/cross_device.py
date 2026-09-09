"""Bounded, capability-aware cross-device planning (Phase 9).

This module is deliberately an orchestration *layer*, not a second execution
system.  It sees only a minimal, point-in-time device inventory, creates a
short-lived immutable plan, and then delegates exactly once to
:meth:`DeviceActionManager.request`.  The manager remains responsible for
schema validation, permission enforcement, confirmation binding, adapter
selection and tool execution.

There is no device discovery, polling, transport access, command dispatch,
remote-PC registry, generic action endpoint, retry, migration or fan-out here.
The sole PC entry represents the host running JARVIS (``pc-local``); Android
identities retain the canonical ``adev-...`` identifier issued by the existing
bridge.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from types import MappingProxyType
from typing import Any, Callable, Dict, FrozenSet, Iterable, Mapping, Optional, Tuple

from .android_identity import ConnectionState, HealthState, TrustState
from .pc_apps import PC_APPLICATION_TOOL_NAMES
from .pc_power import PC_POWER_TOOL_NAMES
from .pc_system import PC_SYSTEM_TOOL_NAMES
from .android_protocol import (
    CAPABILITY_CALL_ANSWER,
    CAPABILITY_CALL_DIAL,
    CAPABILITY_CALL_END,
    CAPABILITY_CALL_REJECT,
    CAPABILITY_CALL_STATUS,
    CAPABILITY_DEVICE_STATUS,
    CAPABILITY_MESSAGE_SEND,
    CAPABILITY_MESSAGE_STATUS,
    CAPABILITY_SYSTEM_BLUETOOTH,
    CAPABILITY_SYSTEM_BRIGHTNESS,
    CAPABILITY_SYSTEM_VOLUME,
    CAPABILITY_SYSTEM_WIFI,
)
from .confirmation import utcnow
from .enums import Platform, RiskLevel, ToolLifecycleEvent, ToolResultStatus
from .errors import ErrorCode
from .ids import new_plan_id
from .manager import DeviceActionManager
from .registry import DeviceToolRegistry
from .results import ToolResult
from .tools import BaseDeviceTool, ToolContext
from .arguments import ArgumentSchema
from .permissions import PERMISSION_DEVICE_STATUS_READ

__all__ = [
    "LOCAL_PC_DEVICE_ID",
    "DEFAULT_PLAN_TTL",
    "MAX_PLAN_TTL",
    "MAX_STORED_PLANS",
    "MAX_PLAN_ARGUMENTS",
    "MAX_PLAN_STRING_CHARACTERS",
    "CrossDeviceAvailability",
    "CrossDevicePlanStatus",
    "CrossDeviceInventoryEntry",
    "CrossDeviceInventorySnapshot",
    "CrossDevicePlan",
    "CrossDeviceResult",
    "ANDROID_TOOL_CAPABILITY_POLICY",
    "PC_TOOL_ALLOWLIST",
    "CrossDeviceInventory",
    "CrossDevicePlanStore",
    "CrossDevicePlanner",
    "CrossDeviceStatusTool",
    "CrossDeviceCapabilitiesTool",
    "CROSS_DEVICE_TOOL_NAMES",
    "build_cross_device_tools",
]

LOCAL_PC_DEVICE_ID = "pc-local"
DEFAULT_PLAN_TTL = timedelta(minutes=5)
MAX_PLAN_TTL = timedelta(minutes=10)
MAX_STORED_PLANS = 64
MAX_PLAN_ARGUMENTS = 16
MAX_PLAN_STRING_CHARACTERS = 4_096


class CrossDeviceAvailability(str, Enum):
    """Minimal eligibility state derived from existing registry/bridge state."""

    AVAILABLE = "available"
    UNAVAILABLE = "unavailable"
    UNTRUSTED = "untrusted"
    REVOKED = "revoked"
    DISCONNECTED = "disconnected"
    STALE = "stale"


class CrossDevicePlanStatus(str, Enum):
    """Planning and submission outcomes; this is not an execution authority."""

    READY = "ready"
    SUBMITTED = "submitted"
    AMBIGUOUS = "ambiguous"
    UNSUPPORTED = "unsupported"
    UNAVAILABLE = "unavailable"
    PERMISSION_DENIED = "permission_denied"
    INVALID_ARGUMENT = "invalid_argument"
    EXPIRED = "expired"
    REPLAYED = "replayed"
    INVALIDATED = "invalidated"
    FAILED = "failed"


@dataclass(frozen=True)
class AndroidToolCapabilityPolicy:
    """Static bridge-protocol capability binding for one registered Android tool.

    The protocol has a finite set of operation-specific capabilities but legacy
    Phase 5--8 tool metadata predates a common capability attribute.  This
    table is intentionally small, immutable and fail-closed: only listed tools
    are routable, and a listed Android tool must still be registered.  Tests
    compare the table to every registered Android operation and verify each
    protocol capability is advertised before a plan can be made.
    """

    capabilities: FrozenSet[str]
    any_capability: bool = False


# This is policy metadata only.  It never dispatches a bridge request or
# creates a capability.  Values are the existing protocol constants used by
# Phase 5--8 controls, preserving their exact allowlist boundaries.
#: The existing local-PC tool namespaces are a closed Phase 2--4 set.  A
#: future registered ``pc.*`` tool is not automatically made cross-device
#: routable merely by its name.
PC_TOOL_ALLOWLIST: FrozenSet[str] = frozenset(
    (*PC_APPLICATION_TOOL_NAMES, *PC_SYSTEM_TOOL_NAMES, *PC_POWER_TOOL_NAMES)
)

ANDROID_TOOL_CAPABILITY_POLICY: Mapping[str, AndroidToolCapabilityPolicy] = MappingProxyType(
    {
        "android.device.status": AndroidToolCapabilityPolicy(frozenset({CAPABILITY_DEVICE_STATUS})),
        "android.system.status": AndroidToolCapabilityPolicy(
            frozenset(
                {
                    CAPABILITY_SYSTEM_VOLUME,
                    CAPABILITY_SYSTEM_BRIGHTNESS,
                    CAPABILITY_SYSTEM_WIFI,
                    CAPABILITY_SYSTEM_BLUETOOTH,
                }
            ),
            any_capability=True,
        ),
        "android.system.get_volume": AndroidToolCapabilityPolicy(frozenset({CAPABILITY_SYSTEM_VOLUME})),
        "android.system.set_volume": AndroidToolCapabilityPolicy(frozenset({CAPABILITY_SYSTEM_VOLUME})),
        "android.system.mute": AndroidToolCapabilityPolicy(frozenset({CAPABILITY_SYSTEM_VOLUME})),
        "android.system.unmute": AndroidToolCapabilityPolicy(frozenset({CAPABILITY_SYSTEM_VOLUME})),
        "android.system.get_brightness": AndroidToolCapabilityPolicy(frozenset({CAPABILITY_SYSTEM_BRIGHTNESS})),
        "android.system.set_brightness": AndroidToolCapabilityPolicy(frozenset({CAPABILITY_SYSTEM_BRIGHTNESS})),
        "android.system.wifi.status": AndroidToolCapabilityPolicy(frozenset({CAPABILITY_SYSTEM_WIFI})),
        "android.system.wifi.enable": AndroidToolCapabilityPolicy(frozenset({CAPABILITY_SYSTEM_WIFI})),
        "android.system.wifi.disable": AndroidToolCapabilityPolicy(frozenset({CAPABILITY_SYSTEM_WIFI})),
        "android.system.bluetooth.status": AndroidToolCapabilityPolicy(frozenset({CAPABILITY_SYSTEM_BLUETOOTH})),
        "android.system.bluetooth.enable": AndroidToolCapabilityPolicy(frozenset({CAPABILITY_SYSTEM_BLUETOOTH})),
        "android.system.bluetooth.disable": AndroidToolCapabilityPolicy(frozenset({CAPABILITY_SYSTEM_BLUETOOTH})),
        "android.call.status": AndroidToolCapabilityPolicy(frozenset({CAPABILITY_CALL_STATUS})),
        "android.call.dial": AndroidToolCapabilityPolicy(frozenset({CAPABILITY_CALL_DIAL})),
        "android.call.answer": AndroidToolCapabilityPolicy(frozenset({CAPABILITY_CALL_ANSWER})),
        "android.call.reject": AndroidToolCapabilityPolicy(frozenset({CAPABILITY_CALL_REJECT})),
        "android.call.end": AndroidToolCapabilityPolicy(frozenset({CAPABILITY_CALL_END})),
        "android.message.status": AndroidToolCapabilityPolicy(frozenset({CAPABILITY_MESSAGE_STATUS})),
        # Phase 8 send explicitly verifies both status metadata and send
        # authority before it emits the dedicated message frame.
        "android.message.send": AndroidToolCapabilityPolicy(
            frozenset({CAPABILITY_MESSAGE_STATUS, CAPABILITY_MESSAGE_SEND})
        ),
    }
)


@dataclass(frozen=True)
class CrossDeviceInventoryEntry:
    """A privacy-minimized immutable inventory record.

    ``capabilities`` contains registered tool names, not raw bridge protocol
    details.  The record intentionally excludes display names, public-key
    fingerprints, timestamps, transport/address data and all personal content.
    """

    device_id: str
    platform: Platform
    availability: CrossDeviceAvailability
    trust_state: str
    connection_state: str
    freshness: str
    capabilities: Tuple[str, ...]
    available_capabilities: Tuple[str, ...]

    @property
    def eligible(self) -> bool:
        return self.availability is CrossDeviceAvailability.AVAILABLE

    @property
    def state_token(self) -> Tuple[str, str, str, str, Tuple[str, ...]]:
        """Stable non-secret snapshot used for execution-time invalidation."""
        return (
            self.availability.value,
            self.trust_state,
            self.connection_state,
            self.freshness,
            self.available_capabilities,
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "device_id": self.device_id,
            "platform": self.platform.value,
            "availability": self.availability.value,
            "trust_state": self.trust_state,
            "connection_state": self.connection_state,
            "freshness": self.freshness,
            "capabilities": list(self.capabilities),
            "available_capabilities": list(self.available_capabilities),
        }


@dataclass(frozen=True)
class CrossDeviceInventorySnapshot:
    """Point-in-time safe inventory.  It never authorizes later execution."""

    entries: Tuple[CrossDeviceInventoryEntry, ...]
    created_at: datetime

    def find(self, device_id: str) -> Optional[CrossDeviceInventoryEntry]:
        for entry in self.entries:
            if entry.device_id == device_id:
                return entry
        return None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "devices": [entry.to_dict() for entry in self.entries],
            "count": len(self.entries),
        }


@dataclass(frozen=True)
class CrossDevicePlan:
    """One immutable, short-lived internal request binding.

    The normalized argument values are kept only in this in-memory plan until
    its bounded expiry.  They are not repr'd, serialized, inventoried or put in
    audit records.  This limited retention is necessary so a manager-created
    confirmation can bind the exact canonical action; it is never a historical
    data cache.
    """

    plan_id: str
    tool_name: str
    device_id: str
    platform: Platform
    risk_level: RiskLevel
    required_permissions: Tuple[str, ...]
    confirmation_required: bool
    created_at: datetime
    expires_at: datetime
    device_state_token: Tuple[str, str, str, str, Tuple[str, ...]]
    _arguments: Tuple[Tuple[str, Any], ...] = field(repr=False, compare=True)

    @property
    def arguments(self) -> Dict[str, Any]:
        """Fresh copy; callers cannot mutate a stored plan."""
        return dict(self._arguments)

    def to_dict(self) -> Dict[str, Any]:
        """Safe plan summary, deliberately excluding argument values."""
        return {
            "plan_id": self.plan_id,
            "tool_name": self.tool_name,
            "device_id": self.device_id,
            "platform": self.platform.value,
            "risk_level": self.risk_level.value,
            "required_permissions": list(self.required_permissions),
            "confirmation_required": self.confirmation_required,
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "argument_names": [name for name, _value in self._arguments],
        }


@dataclass(frozen=True)
class CrossDeviceResult:
    """Structured privacy-safe cross-device outcome.

    The optional original ``ToolResult`` is intentionally not serialized: a
    caller that invokes this internal API may use it for the existing
    confirmation handoff, while model-facing status tools never receive action
    arguments or raw action data.
    """

    status: CrossDevicePlanStatus
    message: str
    error_code: str = ""
    plan: Optional[CrossDevicePlan] = None
    candidates: Tuple[str, ...] = ()
    tool_result: Optional[ToolResult] = field(default=None, repr=False, compare=False)

    @property
    def planned(self) -> bool:
        return self.status is CrossDevicePlanStatus.READY and self.plan is not None

    @property
    def executed(self) -> bool:
        return bool(self.tool_result and self.tool_result.executed)

    def to_dict(self) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "status": self.status.value,
            "message": self.message,
            "error_code": self.error_code,
            "candidates": list(self.candidates),
        }
        if self.plan is not None:
            payload["plan"] = self.plan.to_dict()
        if self.tool_result is not None:
            # Do not turn this layer into a broad cross-device result/data API.
            # The standard manager already owns the full trusted UI handoff.
            payload["tool_result"] = {
                "status": self.tool_result.status.value,
                "success": self.tool_result.success,
                "executed": self.tool_result.executed,
                "error_code": self.tool_result.error_code,
                "tool_name": self.tool_result.tool_name,
                "execution_id": self.tool_result.execution_id,
            }
        return payload


class CrossDeviceInventory:
    """Builds on-demand minimal snapshots from the registry and Android bridge."""

    def __init__(
        self,
        registry: DeviceToolRegistry,
        manager: DeviceActionManager,
        *,
        android_bridge: Optional[Any] = None,
        clock: Callable[[], datetime] = utcnow,
    ) -> None:
        self.registry = registry
        self.manager = manager
        self.android_bridge = android_bridge
        self.clock = clock

    def snapshot(self) -> CrossDeviceInventorySnapshot:
        """Collect one bounded snapshot; a broken source is isolated safely."""
        entries = [self._pc_entry()]
        entries.extend(self._android_entries())
        return CrossDeviceInventorySnapshot(
            entries=tuple(sorted(entries, key=lambda entry: entry.device_id)),
            created_at=self.clock(),
        )

    def _pc_entry(self) -> CrossDeviceInventoryEntry:
        capabilities = tuple(
            tool.name
            for tool in self.registry.list_tools()
            if tool.name in PC_TOOL_ALLOWLIST
        )
        available_capabilities = tuple(
            name for name in capabilities if self.registry.is_available(name)
        )
        adapter = self.manager.platforms.get(Platform.PC)
        platform_available = bool(adapter and adapter.is_available())
        availability = (
            CrossDeviceAvailability.AVAILABLE
            if platform_available
            else CrossDeviceAvailability.UNAVAILABLE
        )
        return CrossDeviceInventoryEntry(
            device_id=LOCAL_PC_DEVICE_ID,
            platform=Platform.PC,
            availability=availability,
            trust_state="local",
            connection_state="local",
            freshness="current" if platform_available else "unknown",
            capabilities=capabilities,
            available_capabilities=available_capabilities if platform_available else (),
        )

    def _android_entries(self) -> Iterable[CrossDeviceInventoryEntry]:
        bridge = self.android_bridge
        if bridge is None:
            return ()
        try:
            known_devices = bridge.list_devices()
            bridge_available = bool(bridge.available)
        except Exception:  # noqa: BLE001 - inventory must never break the agent
            return ()

        entries = []
        for device in known_devices:
            try:
                device_id = str(device["device_id"])
                advertised = frozenset(str(item) for item in (device.get("capabilities") or ()))
                trust = str(device.get("trust_state", TrustState.UNKNOWN.value))
                connection = str((device.get("connection") or {}).get("state", ConnectionState.DISCONNECTED.value))
                health = str(bridge.health(device_id).value)
                availability = self._android_availability(
                    bridge_available=bridge_available,
                    trust=trust,
                    connection=connection,
                    health=health,
                )
                capabilities = tuple(
                    name
                    for name, policy in ANDROID_TOOL_CAPABILITY_POLICY.items()
                    if self.registry.find(name) is not None and self._advertises(advertised, policy)
                )
                available_capabilities = (
                    tuple(name for name in capabilities if self.registry.is_available(name))
                    if availability is CrossDeviceAvailability.AVAILABLE
                    else ()
                )
                entries.append(
                    CrossDeviceInventoryEntry(
                        device_id=device_id,
                        platform=Platform.ANDROID,
                        availability=availability,
                        trust_state=trust,
                        connection_state=connection,
                        freshness=health,
                        capabilities=capabilities,
                        available_capabilities=available_capabilities,
                    )
                )
            except Exception:  # noqa: BLE001 - one malformed identity must not hide others
                continue
        return tuple(entries)

    @staticmethod
    def _advertises(advertised: FrozenSet[str], policy: AndroidToolCapabilityPolicy) -> bool:
        if not policy.capabilities:
            return False
        if policy.any_capability:
            return bool(advertised & policy.capabilities)
        return policy.capabilities.issubset(advertised)

    @staticmethod
    def _android_availability(
        *, bridge_available: bool, trust: str, connection: str, health: str
    ) -> CrossDeviceAvailability:
        if trust == TrustState.REVOKED.value:
            return CrossDeviceAvailability.REVOKED
        # Phase 5 calls PAIRED/CONNECTED/DISCONNECTED its privileged trusted
        # states; there is intentionally no separate mutable "trusted" flag.
        if trust not in {
            TrustState.PAIRED.value,
            TrustState.CONNECTED.value,
            TrustState.DISCONNECTED.value,
        }:
            return CrossDeviceAvailability.UNTRUSTED
        if not bridge_available:
            return CrossDeviceAvailability.UNAVAILABLE
        if connection != ConnectionState.CONNECTED.value:
            return CrossDeviceAvailability.DISCONNECTED
        if health == HealthState.STALE.value:
            return CrossDeviceAvailability.STALE
        return CrossDeviceAvailability.AVAILABLE


@dataclass
class _StoredPlan:
    plan: CrossDevicePlan
    submitted: bool = False


class CrossDevicePlanStore:
    """Small lock-protected in-memory plan store; plan IDs are never authority."""

    def __init__(
        self, *, max_plans: int = MAX_STORED_PLANS, clock: Callable[[], datetime] = utcnow
    ) -> None:
        self.max_plans = max(1, int(max_plans))
        self.clock = clock
        self._plans: Dict[str, _StoredPlan] = {}
        self._lock = threading.RLock()

    def add(self, plan: CrossDevicePlan) -> bool:
        with self._lock:
            self._purge_locked()
            if len(self._plans) >= self.max_plans:
                return False
            self._plans[plan.plan_id] = _StoredPlan(plan=plan)
            return True

    def get(self, plan_id: str) -> Optional[CrossDevicePlan]:
        with self._lock:
            # Keep an expired record just long enough for the caller to return
            # an honest EXPIRED result; add() performs bounded expiry cleanup.
            stored = self._plans.get(plan_id)
            return stored.plan if stored is not None else None

    def claim(self, plan_id: str) -> Tuple[Optional[CrossDevicePlan], CrossDevicePlanStatus]:
        """Atomically consume a current plan before handing it to the manager."""
        with self._lock:
            now = self.clock()
            stored = self._plans.get(plan_id)
            if stored is None:
                return None, CrossDevicePlanStatus.INVALIDATED
            if now >= stored.plan.expires_at:
                self._plans.pop(plan_id, None)
                return None, CrossDevicePlanStatus.EXPIRED
            if stored.submitted:
                return None, CrossDevicePlanStatus.REPLAYED
            stored.submitted = True
            return stored.plan, CrossDevicePlanStatus.SUBMITTED

    def invalidate(self, plan_id: str) -> None:
        with self._lock:
            self._plans.pop(plan_id, None)

    def _purge_locked(self) -> None:
        now = self.clock()
        for plan_id, stored in tuple(self._plans.items()):
            if now >= stored.plan.expires_at:
                self._plans.pop(plan_id, None)


class CrossDevicePlanner:
    """Makes immutable plans and delegates their final submission to the manager.

    Selection policy is intentionally narrow and documented:

    * an explicit canonical target is the only target considered;
    * one eligible target may be selected;
    * multiple targets are *always* ambiguous for non-safe operations;
    * safe read-only operations may use stable canonical-id ordering only when
      the caller explicitly opts into ``allow_read_fallback``.

    It never uses a display name, address, network/proximity metadata or a
    prior target as a tie-breaker.  There is no fallback after a target is
    selected, including when execution later fails.
    """

    def __init__(
        self,
        manager: DeviceActionManager,
        *,
        android_bridge: Optional[Any] = None,
        inventory: Optional[CrossDeviceInventory] = None,
        plan_store: Optional[CrossDevicePlanStore] = None,
        clock: Callable[[], datetime] = utcnow,
        plan_ttl: timedelta = DEFAULT_PLAN_TTL,
    ) -> None:
        self.manager = manager
        self.registry = manager.registry
        self.clock = clock
        self.plan_ttl = self._bounded_ttl(plan_ttl)
        self.inventory = inventory or CrossDeviceInventory(
            self.registry, manager, android_bridge=android_bridge, clock=clock
        )
        self.plan_store = plan_store or CrossDevicePlanStore(clock=clock)

    @staticmethod
    def _bounded_ttl(value: timedelta) -> timedelta:
        if not isinstance(value, timedelta) or value <= timedelta(0):
            raise ValueError("plan_ttl must be a positive timedelta")
        return min(value, MAX_PLAN_TTL)

    def status(self) -> CrossDeviceInventorySnapshot:
        return self.inventory.snapshot()

    def create_plan(
        self,
        tool_name: str,
        arguments: Optional[Mapping[str, Any]] = None,
        *,
        device_id: Optional[str] = None,
        allow_read_fallback: bool = False,
    ) -> CrossDeviceResult:
        """Validate and bind a registered operation without executing anything."""
        requested = str(tool_name or "").strip().lower()
        tool = self.registry.find(requested)
        if tool is None or not self._is_routable(tool):
            return self._failure(
                CrossDevicePlanStatus.UNSUPPORTED,
                "This operation is not an allowlisted cross-device capability.",
                ErrorCode.CROSS_DEVICE_UNSUPPORTED,
            )
        if not isinstance(arguments or {}, Mapping):
            return self._failure(
                CrossDevicePlanStatus.INVALID_ARGUMENT,
                "Plan arguments must be an object.",
                ErrorCode.INVALID_ARGUMENT,
            )
        raw_arguments = dict(arguments or {})
        explicit = self._explicit_target(raw_arguments, device_id)
        if isinstance(explicit, CrossDeviceResult):
            return explicit
        # Permission is part of candidate eligibility, not an after-the-fact
        # cosmetic result.  It is checked again at final submission.
        decision = self.manager.permissions.check(tool)
        if not decision.allowed:
            return self._failure(
                CrossDevicePlanStatus.PERMISSION_DENIED,
                "The selected operation is not permitted; no plan was created.",
                decision.error_code or ErrorCode.PERMISSION_DENIED,
            )

        snapshot = self.inventory.snapshot()
        targetable = tool.name in ANDROID_TOOL_CAPABILITY_POLICY
        if targetable:
            selection = self._select_android(
                tool, snapshot, explicit, allow_read_fallback=allow_read_fallback
            )
        else:
            selection = self._select_pc(tool, snapshot, explicit)
        if isinstance(selection, CrossDeviceResult):
            return selection
        entry = selection

        planned_arguments = dict(raw_arguments)
        if targetable:
            planned_arguments["device"] = entry.device_id
        validated, errors = tool.argument_schema.validate(planned_arguments)
        if errors:
            return self._failure(
                CrossDevicePlanStatus.INVALID_ARGUMENT,
                "Invalid arguments for the selected registered capability.",
                ErrorCode.INVALID_ARGUMENT,
            )
        try:
            normalized = tool.normalize_arguments(validated)
            frozen_arguments = self._freeze_arguments(normalized)
        except (TypeError, ValueError):
            return self._failure(
                CrossDevicePlanStatus.INVALID_ARGUMENT,
                "Arguments are not safe for a bounded immutable plan.",
                ErrorCode.INVALID_ARGUMENT,
            )
        except Exception:  # noqa: BLE001 - plan creation is an input boundary too
            return self._failure(
                CrossDevicePlanStatus.INVALID_ARGUMENT,
                "Invalid arguments for the selected registered capability.",
                ErrorCode.INVALID_ARGUMENT,
            )
        if not self._tool_available(tool):
            return self._failure(
                CrossDevicePlanStatus.UNAVAILABLE,
                "The selected registered capability is unavailable; no plan was created.",
                ErrorCode.TOOL_UNAVAILABLE,
            )

        created_at = self.clock()
        plan = CrossDevicePlan(
            plan_id=new_plan_id(),
            tool_name=tool.name,
            device_id=entry.device_id,
            platform=entry.platform,
            risk_level=tool.risk_level,
            required_permissions=tuple(tool.required_permissions),
            confirmation_required=self.manager.confirmation_policy.is_required(tool),
            created_at=created_at,
            expires_at=created_at + self.plan_ttl,
            device_state_token=entry.state_token,
            _arguments=frozen_arguments,
        )
        if not self.plan_store.add(plan):
            return self._failure(
                CrossDevicePlanStatus.UNAVAILABLE,
                "Cross-device planning is temporarily at capacity; no plan was created.",
                ErrorCode.CROSS_DEVICE_PLAN_CAPACITY,
            )
        self._audit(ToolLifecycleEvent.CROSS_DEVICE_PLAN_CREATED, plan)
        return CrossDeviceResult(
            status=CrossDevicePlanStatus.READY,
            message="A bounded plan was created. Nothing has been executed.",
            plan=plan,
        )

    async def execute_plan(self, plan_id: str) -> CrossDeviceResult:
        """Final-revalidate one internal plan and delegate only to the manager."""
        plan_id = str(plan_id or "").strip()
        plan = self.plan_store.get(plan_id)
        if plan is None:
            return self._failure(
                CrossDevicePlanStatus.INVALIDATED,
                "This plan is unknown, expired, or was invalidated; nothing was executed.",
                ErrorCode.CROSS_DEVICE_PLAN_INVALIDATED,
            )
        invalid = self._revalidate(plan)
        if invalid is not None:
            self.plan_store.invalidate(plan_id)
            self._audit(ToolLifecycleEvent.CROSS_DEVICE_PLAN_INVALIDATED, plan)
            return invalid
        claimed, claim_status = self.plan_store.claim(plan_id)
        if claimed is None:
            status = claim_status
            code = (
                ErrorCode.CROSS_DEVICE_PLAN_EXPIRED
                if status is CrossDevicePlanStatus.EXPIRED
                else ErrorCode.CROSS_DEVICE_PLAN_REPLAYED
                if status is CrossDevicePlanStatus.REPLAYED
                else ErrorCode.CROSS_DEVICE_PLAN_INVALIDATED
            )
            return self._failure(
                status,
                "This plan cannot be submitted again; nothing was executed.",
                code,
            )
        # Revalidate again immediately before the sole manager handoff.  The
        # bridge/tool will repeat its own trust/capability checks inside that
        # handoff, closing the remaining state-change race without bypassing it.
        invalid = self._revalidate(claimed)
        if invalid is not None:
            self.plan_store.invalidate(plan_id)
            self._audit(ToolLifecycleEvent.CROSS_DEVICE_PLAN_INVALIDATED, claimed)
            return invalid
        self._audit(ToolLifecycleEvent.CROSS_DEVICE_PLAN_SUBMITTED, claimed)
        result = await self.manager.request(claimed.tool_name, claimed.arguments)
        event = (
            ToolLifecycleEvent.CROSS_DEVICE_PLAN_PENDING
            if result.status is ToolResultStatus.PENDING_CONFIRMATION
            else ToolLifecycleEvent.CROSS_DEVICE_PLAN_COMPLETED
            if result.success
            else ToolLifecycleEvent.CROSS_DEVICE_PLAN_FAILED
        )
        self._audit(event, claimed, tool_result=result)
        return CrossDeviceResult(
            status=CrossDevicePlanStatus.SUBMITTED,
            message=(
                "The registered action is awaiting the existing confirmation flow."
                if result.status is ToolResultStatus.PENDING_CONFIRMATION
                else "The plan was submitted through the registered action manager."
            ),
            plan=claimed,
            tool_result=result,
        )

    def _revalidate(self, plan: CrossDevicePlan) -> Optional[CrossDeviceResult]:
        if self.clock() >= plan.expires_at:
            return self._failure(
                CrossDevicePlanStatus.EXPIRED,
                "The plan expired before submission; nothing was executed.",
                ErrorCode.CROSS_DEVICE_PLAN_EXPIRED,
            )
        tool = self.registry.find(plan.tool_name)
        if tool is None or not self._is_routable(tool):
            return self._failure(
                CrossDevicePlanStatus.INVALIDATED,
                "The registered capability changed; nothing was executed.",
                ErrorCode.CROSS_DEVICE_PLAN_INVALIDATED,
            )
        if (
            tuple(tool.required_permissions) != plan.required_permissions
            or tool.risk_level is not plan.risk_level
            or self.manager.confirmation_policy.is_required(tool) != plan.confirmation_required
        ):
            return self._failure(
                CrossDevicePlanStatus.INVALIDATED,
                "The operation policy or confirmation requirement changed; nothing was executed.",
                ErrorCode.CROSS_DEVICE_PLAN_INVALIDATED,
            )
        validated, errors = tool.argument_schema.validate(plan.arguments)
        if errors:
            return self._failure(
                CrossDevicePlanStatus.INVALIDATED,
                "The plan arguments no longer validate; nothing was executed.",
                ErrorCode.CROSS_DEVICE_PLAN_INVALIDATED,
            )
        try:
            if self._freeze_arguments(tool.normalize_arguments(validated)) != plan._arguments:
                return self._failure(
                    CrossDevicePlanStatus.INVALIDATED,
                    "The normalized plan binding changed; nothing was executed.",
                    ErrorCode.CROSS_DEVICE_PLAN_INVALIDATED,
                )
        except Exception:  # noqa: BLE001 - fail closed if a normalizer changes
            return self._failure(
                CrossDevicePlanStatus.INVALIDATED,
                "The plan arguments no longer validate; nothing was executed.",
                ErrorCode.CROSS_DEVICE_PLAN_INVALIDATED,
            )
        if not self.manager.permissions.check(tool).allowed:
            return self._failure(
                CrossDevicePlanStatus.PERMISSION_DENIED,
                "Permission changed after planning; nothing was executed.",
                ErrorCode.PERMISSION_DENIED,
            )
        if not self._tool_available(tool):
            return self._failure(
                CrossDevicePlanStatus.UNAVAILABLE,
                "The registered capability is unavailable; nothing was executed.",
                ErrorCode.TOOL_UNAVAILABLE,
            )
        entry = self.inventory.snapshot().find(plan.device_id)
        if (
            entry is None
            or entry.platform is not plan.platform
            or plan.tool_name not in entry.available_capabilities
            or not entry.eligible
            or entry.state_token != plan.device_state_token
        ):
            return self._failure(
                CrossDevicePlanStatus.INVALIDATED,
                "The device trust, connection, freshness, or capability changed; nothing was executed.",
                ErrorCode.CROSS_DEVICE_PLAN_INVALIDATED,
            )
        return None

    def _select_android(
        self,
        tool: BaseDeviceTool,
        snapshot: CrossDeviceInventorySnapshot,
        explicit: Optional[str],
        *,
        allow_read_fallback: bool,
    ) -> CrossDeviceInventoryEntry | CrossDeviceResult:
        entries = [entry for entry in snapshot.entries if entry.platform is Platform.ANDROID]
        if explicit:
            entry = snapshot.find(explicit)
            if entry is None or entry.platform is not Platform.ANDROID:
                return self._unavailable_explicit()
            if tool.name not in entry.available_capabilities or not entry.eligible:
                return self._unavailable_explicit()
            return entry
        candidates = tuple(
            entry for entry in entries if entry.eligible and tool.name in entry.available_capabilities
        )
        if not candidates:
            return self._failure(
                CrossDevicePlanStatus.UNAVAILABLE,
                "No trusted, connected, fresh Android device supports this registered capability.",
                ErrorCode.CROSS_DEVICE_TARGET_UNAVAILABLE,
            )
        if len(candidates) == 1:
            return candidates[0]
        if tool.risk_level is RiskLevel.SAFE and allow_read_fallback:
            return sorted(candidates, key=lambda item: item.device_id)[0]
        return CrossDeviceResult(
            status=CrossDevicePlanStatus.AMBIGUOUS,
            message="Multiple eligible devices exist. Select one canonical device id; nothing was executed.",
            error_code=ErrorCode.CROSS_DEVICE_AMBIGUOUS,
            candidates=tuple(entry.device_id for entry in sorted(candidates, key=lambda item: item.device_id)),
        )

    def _select_pc(
        self,
        tool: BaseDeviceTool,
        snapshot: CrossDeviceInventorySnapshot,
        explicit: Optional[str],
    ) -> CrossDeviceInventoryEntry | CrossDeviceResult:
        if explicit and explicit != LOCAL_PC_DEVICE_ID:
            return self._unavailable_explicit()
        entry = snapshot.find(LOCAL_PC_DEVICE_ID)
        if entry is None or not entry.eligible or tool.name not in entry.available_capabilities:
            return self._unavailable_explicit()
        return entry

    def _explicit_target(
        self, arguments: Dict[str, Any], device_id: Optional[str]
    ) -> Optional[str] | CrossDeviceResult:
        embedded = arguments.get("device")
        supplied = str(device_id).strip() if device_id is not None else ""
        if embedded is not None and not isinstance(embedded, str):
            return self._failure(
                CrossDevicePlanStatus.INVALID_ARGUMENT,
                "The device target must be a canonical device id string.",
                ErrorCode.INVALID_ARGUMENT,
            )
        embedded_text = embedded.strip() if isinstance(embedded, str) else ""
        if supplied and embedded_text and supplied != embedded_text:
            return self._failure(
                CrossDevicePlanStatus.INVALID_ARGUMENT,
                "Conflicting explicit device targets were supplied.",
                ErrorCode.INVALID_ARGUMENT,
            )
        return supplied or embedded_text or None

    @staticmethod
    def _is_routable(tool: BaseDeviceTool) -> bool:
        # No generic registry execution: only the fixed local-PC allowlist and
        # protocol-backed Android operation policy above are eligible.
        return tool.name in PC_TOOL_ALLOWLIST or tool.name in ANDROID_TOOL_CAPABILITY_POLICY

    @staticmethod
    def _tool_available(tool: BaseDeviceTool) -> bool:
        try:
            return bool(tool.is_available())
        except Exception:  # noqa: BLE001
            return False

    @staticmethod
    def _freeze_arguments(arguments: Mapping[str, Any]) -> Tuple[Tuple[str, Any], ...]:
        """Admit only bounded scalar values into an immutable internal plan.

        Every existing Phase 1--8 routable schema normalizes to these scalar
        values.  Refusing a future complex custom value is safer than retaining
        a mutable object or silently serializing/deserializing it.
        """
        if not isinstance(arguments, Mapping) or len(arguments) > MAX_PLAN_ARGUMENTS:
            raise ValueError("too many plan arguments")
        frozen = []
        for key, value in sorted(arguments.items(), key=lambda item: str(item[0])):
            if not isinstance(key, str) or not key:
                raise TypeError("argument names must be non-empty strings")
            if isinstance(value, str):
                if len(value) > MAX_PLAN_STRING_CHARACTERS:
                    raise ValueError("argument string is too long for a plan")
            elif value is not None and not isinstance(value, (bool, int, float)):
                raise TypeError("only scalar arguments can be held in a plan")
            frozen.append((key, value))
        return tuple(frozen)

    @staticmethod
    def _failure(status: CrossDevicePlanStatus, message: str, error_code: str) -> CrossDeviceResult:
        return CrossDeviceResult(status=status, message=message, error_code=str(error_code))

    def _unavailable_explicit(self) -> CrossDeviceResult:
        return self._failure(
            CrossDevicePlanStatus.UNAVAILABLE,
            "The explicitly selected device is unavailable or does not support this capability; no fallback was used.",
            ErrorCode.CROSS_DEVICE_TARGET_UNAVAILABLE,
        )

    def _audit(
        self,
        event: ToolLifecycleEvent,
        plan: CrossDevicePlan,
        *,
        tool_result: Optional[ToolResult] = None,
    ) -> None:
        fields: Dict[str, Any] = {
            "plan_id": plan.plan_id,
            "device_id": plan.device_id,
            "capability": plan.tool_name,
            "risk_level": plan.risk_level.value,
            "argument_names": [name for name, _value in plan._arguments],
        }
        if tool_result is not None:
            fields.update(
                status=tool_result.status.value,
                success=tool_result.success,
                error_code=tool_result.error_code,
            )
        self.manager.audit.log(event, tool_name=plan.tool_name, **fields)


class _CrossDeviceReadTool(BaseDeviceTool):
    """Shared manager-registered read-only inventory surface."""

    platform = Platform.UNKNOWN
    risk_level = RiskLevel.SAFE
    required_permissions = (PERMISSION_DEVICE_STATUS_READ,)
    argument_schema = ArgumentSchema.empty()

    def __init__(self, planner: CrossDevicePlanner) -> None:
        self.planner = planner

    def is_available(self) -> bool:
        # A status read is available even if every controlled device is offline.
        return True


class CrossDeviceStatusTool(_CrossDeviceReadTool):
    name = "cross.device.status"
    description = "Read the minimal current cross-device inventory; no device action is performed."

    async def run(self, arguments: Dict[str, Any], context: ToolContext) -> ToolResult:
        snapshot = self.planner.status()
        return ToolResult.ok(
            f"{len(snapshot.entries)} device inventory record(s) available.", data=snapshot.to_dict()
        )


class CrossDeviceCapabilitiesTool(_CrossDeviceReadTool):
    name = "cross.device.capabilities"
    description = "Read registered, currently available capabilities per known device; no device action is performed."

    async def run(self, arguments: Dict[str, Any], context: ToolContext) -> ToolResult:
        snapshot = self.planner.status()
        return ToolResult.ok(
            f"Capability metadata for {len(snapshot.entries)} device record(s) available.",
            data=snapshot.to_dict(),
        )


CROSS_DEVICE_TOOL_NAMES: Tuple[str, ...] = (
    CrossDeviceStatusTool.name,
    CrossDeviceCapabilitiesTool.name,
)


def build_cross_device_tools(planner: CrossDevicePlanner) -> Tuple[BaseDeviceTool, ...]:
    """Build the only model-facing Phase 9 tools (read-only, no executor)."""
    return (CrossDeviceStatusTool(planner), CrossDeviceCapabilitiesTool(planner))
