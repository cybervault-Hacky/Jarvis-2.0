"""The device action manager - the only path from a request to an execution.

Pipeline::

    JARVIS core
        |
        v
    DeviceActionManager.request(tool_name, arguments)
        |
        +-- 1. registry lookup ............ unknown tool -> FAILED
        +-- 2. tool availability .......... unavailable  -> UNAVAILABLE
        +-- 3. argument validation ........ bad input    -> INVALID_ARGUMENT
        +-- 4. permission check ........... not allowed  -> PERMISSION_DENIED
        +-- 5. platform / device check .... no adapter   -> UNAVAILABLE
        +-- 6. confirmation check ......... needs a "yes"-> PENDING_CONFIRMATION
        +-- 7. execution via adapter .................... -> SUCCESS / FAILED

Every branch emits audit events and returns a :class:`ToolResult`. Nothing in
this module touches a shell, and nothing runs unless a registered tool reports
success.
"""

from __future__ import annotations

import asyncio
from typing import Any, Dict, Mapping, Optional, Tuple

from .audit import AuditLogger
from .confirmation import ConfirmationManager, ConfirmationPolicy
from .enums import ConfirmationStatus, Platform, ToolLifecycleEvent, ToolResultStatus
from .errors import (
    ConfirmationExpiredError,
    ConfirmationStateError,
    ErrorCode,
    UnknownConfirmationError,
)
from .ids import new_execution_id
from .permissions import PermissionPolicy
from .platform import PlatformRegistry
from .registry import DeviceToolRegistry
from .results import ToolResult
from .tools import BaseDeviceTool, ToolContext

__all__ = ["DeviceActionManager"]


class DeviceActionManager:
    """Coordinates registry, permissions, confirmations and platform adapters."""

    def __init__(
        self,
        registry: Optional[DeviceToolRegistry] = None,
        permissions: Optional[PermissionPolicy] = None,
        confirmations: Optional[ConfirmationManager] = None,
        platforms: Optional[PlatformRegistry] = None,
        audit: Optional[AuditLogger] = None,
        *,
        confirmation_policy: Optional[ConfirmationPolicy] = None,
        execution_timeout: Optional[float] = None,
    ) -> None:
        self.registry = registry if registry is not None else DeviceToolRegistry()
        self.permissions = permissions if permissions is not None else PermissionPolicy.with_local_defaults()
        self.confirmation_policy = confirmation_policy or ConfirmationPolicy()
        self.confirmations = confirmations if confirmations is not None else ConfirmationManager(
            policy=self.confirmation_policy
        )
        self.platforms = platforms if platforms is not None else PlatformRegistry()
        self.audit = audit if audit is not None else AuditLogger()
        self.execution_timeout = execution_timeout

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------
    def list_tools(self, **filters: Any) -> Tuple[BaseDeviceTool, ...]:
        """Registered tools (see :meth:`DeviceToolRegistry.list_tools`)."""
        return self.registry.list_tools(**filters)

    def describe_tools(self) -> Tuple[Dict[str, Any], ...]:
        """Metadata for every registered tool."""
        return self.registry.describe()

    def pending_confirmations(self) -> Tuple[Dict[str, Any], ...]:
        """Safe summaries of the confirmations waiting for an answer."""
        return tuple(request.to_dict() for request in self.confirmations.pending())

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------
    async def request(
        self,
        tool_name: str,
        arguments: Optional[Mapping[str, Any]] = None,
        *,
        confirmation_id: Optional[str] = None,
        target: str = "",
        session_id: str = "",
    ) -> ToolResult:
        """Ask JARVIS to run a registered device tool.

        Returns a :class:`ToolResult`. ``result.success`` is ``True`` only when
        the tool itself reported :attr:`ToolResultStatus.SUCCESS`.
        """
        execution_id = new_execution_id()
        requested_tool = str(tool_name or "").strip()

        self.audit.log(
            ToolLifecycleEvent.TOOL_REQUESTED,
            execution_id=execution_id,
            tool_name=requested_tool,
            session_id=session_id,
            confirmation_supplied=bool(confirmation_id),
            argument_names=sorted(arguments or {}),
        )

        # 1 - registry lookup ------------------------------------------------
        tool = self.registry.find(requested_tool)
        if tool is None:
            return self._log_failure(
                ToolResult.failure(
                    f"No device tool named {requested_tool!r} is registered, so nothing was executed.",
                    error_code=ErrorCode.UNKNOWN_TOOL,
                    tool_name=requested_tool,
                    execution_id=execution_id,
                    data={"registered_tools": list(self.registry.names())},
                )
            )

        # 2 - tool availability ---------------------------------------------
        if not tool.is_available():
            return self._log_failure(
                ToolResult.unavailable(
                    f"Tool {tool.name} is not available right now.",
                    error_code=ErrorCode.TOOL_UNAVAILABLE,
                    tool_name=tool.name,
                    execution_id=execution_id,
                    data={"platform": tool.platform.value},
                )
            )

        # 3 - argument validation -------------------------------------------
        validated, errors = tool.argument_schema.validate(arguments)
        if errors:
            return self._log_failure(
                ToolResult.invalid_argument(
                    f"Invalid arguments for {tool.name}: " + "; ".join(errors),
                    error="; ".join(errors),
                    tool_name=tool.name,
                    execution_id=execution_id,
                )
            )
        # Canonicalize before anything is stored for approval.  This is vital
        # for destination-bearing tools: an approval binds the actual request,
        # not merely an equivalent-looking presentation string.
        try:
            validated = tool.normalize_arguments(validated)
        except (TypeError, ValueError):
            return self._log_failure(
                ToolResult.invalid_argument(
                    f"Invalid arguments for {tool.name}.",
                    error_code=ErrorCode.INVALID_ARGUMENT,
                    tool_name=tool.name,
                    execution_id=execution_id,
                )
            )

        # 4 - permission check ----------------------------------------------
        decision = self.permissions.check(tool)
        self.audit.log(
            ToolLifecycleEvent.PERMISSION_CHECKED,
            execution_id=execution_id,
            tool_name=tool.name,
            allowed=decision.allowed,
            missing_permissions=list(decision.missing_permissions),
            reason=decision.reason,
        )
        if not decision.allowed:
            message = decision.reason or f"Tool {tool.name} is not permitted."
            return self._log_failure(
                ToolResult.permission_denied(
                    message,
                    missing_permissions={"missing_permissions": list(decision.missing_permissions)},
                    error_code=decision.error_code,
                    tool_name=tool.name,
                    execution_id=execution_id,
                )
            )

        # 5 - platform / device availability --------------------------------
        adapter = None
        if tool.platform is not Platform.UNKNOWN:
            adapter = self.platforms.get(tool.platform)
            if adapter is None:
                return self._log_failure(
                    ToolResult.unavailable(
                        f"JARVIS has no adapter for platform {tool.platform.value}.",
                        error_code=ErrorCode.PLATFORM_UNAVAILABLE,
                        tool_name=tool.name,
                        execution_id=execution_id,
                        data={"platform": tool.platform.value},
                    )
                )
            if not adapter.is_available():
                return self._log_failure(
                    ToolResult.unavailable(
                        f"The {tool.platform.value} device is not reachable right now.",
                        error_code=ErrorCode.DEVICE_UNAVAILABLE,
                        tool_name=tool.name,
                        execution_id=execution_id,
                        data={"platform": tool.platform.value},
                    )
                )

        # 6 - confirmation check --------------------------------------------
        if self.confirmation_policy.is_required(tool):
            gate = self._confirmation_gate(
                tool=tool,
                validated=validated,
                confirmation_id=confirmation_id,
                target=target,
                execution_id=execution_id,
            )
            if gate is not None:
                return self._log_failure(gate)

        # 7 - execution ------------------------------------------------------
        return await self._execute(
            tool=tool,
            validated=validated,
            adapter=adapter,
            execution_id=execution_id,
            session_id=session_id,
            confirmation_id=confirmation_id,
        )

    # ------------------------------------------------------------------
    # Confirmation handling
    # ------------------------------------------------------------------
    def _confirmation_gate(
        self,
        *,
        tool: BaseDeviceTool,
        validated: Dict[str, Any],
        confirmation_id: Optional[str],
        target: str,
        execution_id: str,
    ) -> Optional[ToolResult]:
        """Return a blocking result, or ``None`` when execution may continue."""
        if not confirmation_id:
            # Let a trusted tool render its own human-facing target.  The
            # manager never logs this value; it is held only in the pending
            # confirmation/UI so an explicit destination can be approved.
            confirmation_target = target or tool.confirmation_target(validated)
            pending = self.confirmations.create(
                tool.name,
                confirmation_target,
                arguments=validated,
                risk_level=tool.risk_level,
            )
            self.audit.log(
                ToolLifecycleEvent.CONFIRMATION_REQUESTED,
                execution_id=execution_id,
                tool_name=tool.name,
                confirmation_id=pending.confirmation_id,
                risk_level=tool.risk_level.value,
                expires_at=pending.expires_at.isoformat(),
            )
            prompt = (
                f"{confirmation_target} needs your confirmation before it runs. "
                f"Nothing has happened yet. Confirmation id: {pending.confirmation_id}."
            )
            return ToolResult.pending_confirmation(
                prompt,
                confirmation_id=pending.confirmation_id,
                tool_name=tool.name,
                execution_id=execution_id,
                data={
                    "target": pending.target,
                    "risk_level": tool.risk_level.value,
                    "expires_at": pending.expires_at.isoformat(),
                },
            )

        try:
            pending = self.confirmations.require(confirmation_id)
        except UnknownConfirmationError:
            return ToolResult.failure(
                f"Confirmation {confirmation_id!r} is unknown, so nothing was executed.",
                error_code=ErrorCode.UNKNOWN_CONFIRMATION,
                tool_name=tool.name,
                execution_id=execution_id,
            )

        self.audit.log(
            ToolLifecycleEvent.CONFIRMATION_RECEIVED,
            execution_id=execution_id,
            tool_name=tool.name,
            confirmation_id=pending.confirmation_id,
            status=pending.status.value,
        )

        if pending.action != tool.name:
            return ToolResult.failure(
                f"Confirmation {confirmation_id!r} was created for {pending.action!r}, "
                f"not for {tool.name!r}.",
                error_code=ErrorCode.CONFIRMATION_MISMATCH,
                tool_name=tool.name,
                execution_id=execution_id,
            )
        # A confirmation is cryptographically unrelated to model input, so
        # bind it explicitly to the full normalized argument mapping as well
        # as the tool.  Without this check a caller could present a valid id
        # for one device/destination while requesting another.
        if pending.arguments != validated:
            return ToolResult.failure(
                "The confirmation was created for a different validated request; nothing was executed.",
                error_code=ErrorCode.CONFIRMATION_MISMATCH,
                tool_name=tool.name,
                execution_id=execution_id,
            )

        if pending.status is ConfirmationStatus.CONFIRMED:
            if pending.consumed:
                return ToolResult.failure(
                    f"Confirmation {confirmation_id!r} has already been used.",
                    error_code=ErrorCode.CONFIRMATION_REUSED,
                    tool_name=tool.name,
                    execution_id=execution_id,
                )
            return None

        if pending.status is ConfirmationStatus.DENIED:
            return ToolResult.denied(
                f"The user declined {tool.name}; nothing was executed.",
                error_code=ErrorCode.CONFIRMATION_DENIED,
                tool_name=tool.name,
                execution_id=execution_id,
            )
        if pending.status is ConfirmationStatus.CANCELLED:
            return ToolResult.cancelled(
                f"The confirmation for {tool.name} was cancelled.",
                error_code=ErrorCode.CONFIRMATION_CANCELLED,
                tool_name=tool.name,
                execution_id=execution_id,
            )
        if pending.status is ConfirmationStatus.EXPIRED:
            return ToolResult.timeout(
                f"The confirmation for {tool.name} expired before an answer arrived.",
                error_code=ErrorCode.CONFIRMATION_EXPIRED,
                tool_name=tool.name,
                execution_id=execution_id,
            )
        # Still pending: the human has not answered yet.
        return ToolResult(
            status=ToolResultStatus.PENDING_CONFIRMATION,
            message=f"Still waiting for an answer to confirmation {confirmation_id!r}.",
            tool_name=tool.name,
            execution_id=execution_id,
            data={"confirmation_id": pending.confirmation_id, "confirmation_required": True},
            error_code=ErrorCode.CONFIRMATION_PENDING,
        )

    async def resolve_confirmation(
        self,
        confirmation_id: str,
        approved: bool,
        *,
        session_id: str = "",
    ) -> ToolResult:
        """Apply the user's yes/no and run the stored action when approved."""
        try:
            pending = self.confirmations.require(confirmation_id)
        except UnknownConfirmationError:
            return self._log_failure(
                ToolResult.failure(
                    f"Confirmation {confirmation_id!r} is unknown or has been forgotten.",
                    error_code=ErrorCode.UNKNOWN_CONFIRMATION,
                    execution_id=new_execution_id(),
                )
            )

        if not approved:
            try:
                self.confirmations.deny(confirmation_id)
            except ConfirmationExpiredError:
                return self._log_failure(
                    ToolResult.timeout(
                        f"Confirmation {confirmation_id!r} had already expired.",
                        error_code=ErrorCode.CONFIRMATION_EXPIRED,
                        tool_name=pending.action,
                    )
                )
            except ConfirmationStateError:
                return self._log_failure(
                    ToolResult.failure(
                        f"Confirmation {confirmation_id!r} was already "
                        f"{pending.status.value}.",
                        error_code=ErrorCode.CONFIRMATION_REUSED,
                        tool_name=pending.action,
                    )
                )
            return self._log_failure(
                ToolResult.denied(
                    f"{pending.action} was declined. Nothing was executed.",
                    error_code=ErrorCode.CONFIRMATION_DENIED,
                    tool_name=pending.action,
                    data={"confirmation_id": confirmation_id},
                )
            )

        try:
            self.confirmations.confirm(confirmation_id)
        except ConfirmationExpiredError:
            return self._log_failure(
                ToolResult.timeout(
                    f"Confirmation {confirmation_id!r} expired before it could be used.",
                    error_code=ErrorCode.CONFIRMATION_EXPIRED,
                    tool_name=pending.action,
                )
            )
        except ConfirmationStateError:
            return self._log_failure(
                ToolResult.failure(
                    f"Confirmation {confirmation_id!r} was already {pending.status.value}.",
                    error_code=ErrorCode.CONFIRMATION_REUSED,
                    tool_name=pending.action,
                )
            )

        return await self.request(
            pending.action,
            pending.arguments,
            confirmation_id=confirmation_id,
            target=pending.target,
            session_id=session_id,
        )

    async def cancel_confirmation(self, confirmation_id: str) -> ToolResult:
        """Cancel a pending confirmation without running anything."""
        known = self.confirmations.get(confirmation_id)
        action = known.action if known is not None else ""
        try:
            pending = self.confirmations.cancel(confirmation_id)
        except UnknownConfirmationError:
            return self._log_failure(
                ToolResult.failure(
                    f"Confirmation {confirmation_id!r} is unknown.",
                    error_code=ErrorCode.UNKNOWN_CONFIRMATION,
                    execution_id=new_execution_id(),
                )
            )
        except ConfirmationExpiredError:
            return self._log_failure(
                ToolResult.timeout(
                    f"Confirmation {confirmation_id!r} had already expired.",
                    error_code=ErrorCode.CONFIRMATION_EXPIRED,
                    tool_name=action,
                )
            )
        except ConfirmationStateError:
            return self._log_failure(
                ToolResult.cancelled(
                    f"Confirmation {confirmation_id!r} was already resolved.",
                    error_code=ErrorCode.CONFIRMATION_REUSED,
                    tool_name=action,
                )
            )
        return self._log_failure(
            ToolResult.cancelled(
                f"{pending.action} was cancelled. Nothing was executed.",
                tool_name=pending.action,
                data={"confirmation_id": confirmation_id},
            )
        )

    # ------------------------------------------------------------------
    # Execution
    # ------------------------------------------------------------------
    async def _execute(
        self,
        *,
        tool: BaseDeviceTool,
        validated: Dict[str, Any],
        adapter: Any,
        execution_id: str,
        session_id: str,
        confirmation_id: Optional[str],
    ) -> ToolResult:
        context = ToolContext(
            execution_id=execution_id,
            tool_name=tool.name,
            platform=tool.platform,
            arguments=validated,
            session_id=session_id,
            adapter=adapter,
        )
        self.audit.log(
            ToolLifecycleEvent.EXECUTION_STARTED,
            execution_id=execution_id,
            tool_name=tool.name,
            platform=tool.platform.value,
            risk_level=tool.risk_level.value,
            adapter=type(adapter).__name__ if adapter is not None else None,
        )

        try:
            if self.execution_timeout:
                result = await asyncio.wait_for(
                    self._dispatch(tool, validated, context, adapter),
                    timeout=self.execution_timeout,
                )
            else:
                result = await self._dispatch(tool, validated, context, adapter)
        except asyncio.TimeoutError:
            result = ToolResult.timeout(
                f"Tool {tool.name} did not finish within {self.execution_timeout}s.",
                error_code=ErrorCode.TOOL_ERROR,
                tool_name=tool.name,
                execution_id=execution_id,
            )
        except Exception as exc:  # noqa: BLE001 - framework boundary
            result = ToolResult.failure(
                f"Tool {tool.name} raised an error and did not complete.",
                error=f"{type(exc).__name__}: {exc}"[:300],
                error_code=ErrorCode.TOOL_ERROR,
                tool_name=tool.name,
                execution_id=execution_id,
            )

        # The tool really was dispatched from here on, whatever came back.
        result = self._finalise(result, tool, execution_id).marked_executed()

        # A confirmation is spent as soon as the action has been dispatched.
        if confirmation_id:
            self.confirmations.consume(confirmation_id)

        if result.success:
            self.audit.log_result(ToolLifecycleEvent.EXECUTION_COMPLETED, result)
        else:
            self.audit.log_result(ToolLifecycleEvent.EXECUTION_FAILED, result)
        return result

    @staticmethod
    async def _dispatch(
        tool: BaseDeviceTool,
        validated: Dict[str, Any],
        context: ToolContext,
        adapter: Any,
    ) -> ToolResult:
        if adapter is not None:
            return await adapter.execute(tool, validated, context)
        return await tool.execute(validated, context)

    @staticmethod
    def _finalise(result: Any, tool: BaseDeviceTool, execution_id: str) -> ToolResult:
        """Stamp ids and make sure a non-result can never look like success."""
        if not isinstance(result, ToolResult):
            return ToolResult.failure(
                f"Tool {tool.name} returned {type(result).__name__} instead of ToolResult.",
                error_code=ErrorCode.TOOL_ERROR,
                tool_name=tool.name,
                execution_id=execution_id,
            )
        return result.with_ids(tool_name=tool.name, execution_id=execution_id)

    def _log_failure(self, result: ToolResult) -> ToolResult:
        """Emit an audit line for a request that never reached execution.

        Every rejected request gets a lifecycle record, so nothing fails
        silently. A request waiting for a human answer is not a failure - it is
        already covered by ``CONFIRMATION_REQUESTED``.
        """
        if not result.execution_id:
            result = result.with_ids(execution_id=new_execution_id())
        if result.status is not ToolResultStatus.PENDING_CONFIRMATION:
            self.audit.log_result(ToolLifecycleEvent.EXECUTION_FAILED, result)
        return result
