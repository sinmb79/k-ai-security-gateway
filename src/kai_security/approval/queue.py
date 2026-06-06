"""In-memory approval queue implementation."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from threading import RLock
from typing import ClassVar
from uuid import uuid4


APPROVAL_STATUS_PENDING = "pending"
APPROVAL_STATUS_EXECUTING = "executing"
APPROVAL_STATUS_APPROVED = "approved"
APPROVAL_STATUS_REJECTED = "rejected"


@dataclass(frozen=True, slots=True)
class ApprovalRequest:
    approval_id: str
    request_id: str
    requested_by: str
    reason: str
    action: str
    created_at: datetime
    status: str
    resolved_by: str | None = None
    resolved_at: datetime | None = None
    resolution_comment: str = ""
    execution_attempt_id: str | None = None
    attempt_count: int = 0
    execution_started_at: datetime | None = None
    last_execution_started_at: datetime | None = None
    first_failed_at: datetime | None = None
    last_failed_at: datetime | None = None
    last_execution_error: str | None = None
    context: dict[str, object] | None = None


class InMemoryApprovalQueue:
    """In-memory queue that stores approval requests."""

    _status_pending: ClassVar[str] = APPROVAL_STATUS_PENDING
    _status_executing: ClassVar[str] = APPROVAL_STATUS_EXECUTING
    _status_approved: ClassVar[str] = APPROVAL_STATUS_APPROVED
    _status_rejected: ClassVar[str] = APPROVAL_STATUS_REJECTED

    def __init__(self) -> None:
        self._requests: dict[str, ApprovalRequest] = {}
        self._lock = RLock()

    def create(
        self,
        request_id: str,
        requested_by: str,
        reason: str,
        action: str,
        context: dict[str, object] | None = None,
    ) -> ApprovalRequest:
        request = ApprovalRequest(
            approval_id=self._generate_id(),
            request_id=request_id,
            requested_by=requested_by,
            reason=reason,
            action=action,
            created_at=datetime.now(UTC),
            status=self._status_pending,
            context=deepcopy(context) if context is not None else None,
        )
        with self._lock:
            self._requests[request.approval_id] = request
            return self._copy(request)

    def list_pending(self) -> list[ApprovalRequest]:
        with self._lock:
            pending = [
                request for request in self._requests.values() if request.status == self._status_pending
            ]
            return [self._copy(request) for request in pending]

    def begin_execution(
        self,
        approval_id: str,
        *,
        resolved_by: str,
        comment: str = "",
    ) -> ApprovalRequest:
        with self._lock:
            request = self._requests.get(approval_id)
            if request is None:
                raise KeyError(f"Approval request not found: {approval_id}")
            if request.status != self._status_pending:
                raise ValueError(f"Approval request already resolved or executing: {approval_id}")
            started_at = datetime.now(UTC)
            executing = replace(
                request,
                status=self._status_executing,
                resolved_by=resolved_by,
                resolution_comment=comment,
                execution_attempt_id=self._generate_id(),
                attempt_count=request.attempt_count + 1,
                execution_started_at=started_at,
                last_execution_started_at=started_at,
            )
            self._requests[approval_id] = executing
            return self._copy(executing)

    def fail_execution(
        self,
        approval_id: str,
        *,
        expected_execution_attempt_id: str,
        error_type: str,
    ) -> ApprovalRequest:
        with self._lock:
            request = self._requests.get(approval_id)
            if request is None:
                raise KeyError(f"Approval request not found: {approval_id}")
            self._require_current_execution_attempt(
                request,
                expected_execution_attempt_id=expected_execution_attempt_id,
            )
            failed_at = datetime.now(UTC)
            pending = replace(
                request,
                status=self._status_pending,
                execution_started_at=None,
                last_execution_started_at=request.execution_started_at
                or request.last_execution_started_at,
                first_failed_at=request.first_failed_at or failed_at,
                last_failed_at=failed_at,
                last_execution_error=error_type,
            )
            self._requests[approval_id] = pending
            return self._copy(pending)

    def finish_execution_success(
        self,
        approval_id: str,
        *,
        expected_execution_attempt_id: str,
        resolved_by: str,
        comment: str = "",
    ) -> ApprovalRequest:
        with self._lock:
            request = self._requests.get(approval_id)
            if request is None:
                raise KeyError(f"Approval request not found: {approval_id}")
            self._require_current_execution_attempt(
                request,
                expected_execution_attempt_id=expected_execution_attempt_id,
            )
            resolved_request = replace(
                request,
                status=self._status_approved,
                resolved_by=resolved_by,
                resolved_at=datetime.now(UTC),
                resolution_comment=comment,
                execution_started_at=None,
                last_execution_error=None,
                context=deepcopy(request.context),
            )
            self._requests[approval_id] = resolved_request
            return self._copy(resolved_request)

    def reject_pending(
        self,
        approval_id: str,
        *,
        resolved_by: str,
        comment: str = "",
    ) -> ApprovalRequest:
        with self._lock:
            request = self._requests.get(approval_id)
            if request is None:
                raise KeyError(f"Approval request not found: {approval_id}")
            if request.status != self._status_pending:
                raise ValueError(f"Approval request already resolved or executing: {approval_id}")
            resolved_request = replace(
                request,
                status=self._status_rejected,
                resolved_by=resolved_by,
                resolved_at=datetime.now(UTC),
                resolution_comment=comment,
                execution_started_at=None,
                context=deepcopy(request.context),
            )
            self._requests[approval_id] = resolved_request
            return self._copy(resolved_request)

    def resolve(
        self,
        approval_id: str,
        approved: bool,
        resolved_by: str,
        comment: str = "",
    ) -> ApprovalRequest:
        if approved:
            raise ValueError("Approved resolution requires an explicit execution attempt.")
        return self.reject_pending(approval_id, resolved_by=resolved_by, comment=comment)

    def assert_execution_attempt(
        self,
        approval_id: str,
        *,
        expected_execution_attempt_id: str,
    ) -> ApprovalRequest:
        with self._lock:
            request = self._requests.get(approval_id)
            if request is None:
                raise KeyError(f"Approval request not found: {approval_id}")
            self._require_current_execution_attempt(
                request,
                expected_execution_attempt_id=expected_execution_attempt_id,
            )
            return self._copy(request)

    def recover_stale_executions(
        self,
        *,
        timeout_seconds: float,
        reason: str = "execution_timeout",
        now: datetime | None = None,
        limit: int | None = None,
    ) -> list[ApprovalRequest]:
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        if limit is not None and limit <= 0:
            raise ValueError("limit must be positive")
        current_time = (now or datetime.now(UTC)).astimezone(UTC)
        recovered: list[ApprovalRequest] = []
        with self._lock:
            for approval_id, request in list(self._requests.items()):
                if not self._is_stale_execution(
                    request,
                    timeout_seconds=timeout_seconds,
                    current_time=current_time,
                ):
                    continue
                started_at = request.execution_started_at
                if started_at is not None and started_at.tzinfo is None:
                    started_at = started_at.replace(tzinfo=UTC)
                recovered_request = replace(
                    request,
                    status=self._status_pending,
                    execution_started_at=None,
                    last_execution_started_at=started_at,
                    first_failed_at=request.first_failed_at or current_time,
                    last_failed_at=current_time,
                    last_execution_error=reason,
                )
                self._requests[approval_id] = recovered_request
                recovered.append(self._copy(recovered_request))
                if limit is not None and len(recovered) >= limit:
                    break
        return recovered

    def list_stale_executions(
        self,
        *,
        timeout_seconds: float,
        now: datetime | None = None,
        limit: int | None = None,
    ) -> list[ApprovalRequest]:
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        if limit is not None and limit <= 0:
            raise ValueError("limit must be positive")
        current_time = (now or datetime.now(UTC)).astimezone(UTC)
        stale: list[ApprovalRequest] = []
        with self._lock:
            for request in self._requests.values():
                if not self._is_stale_execution(
                    request,
                    timeout_seconds=timeout_seconds,
                    current_time=current_time,
                ):
                    continue
                stale.append(self._copy(request))
                if limit is not None and len(stale) >= limit:
                    break
        return stale

    def get(self, approval_id: str) -> ApprovalRequest | None:
        with self._lock:
            request = self._requests.get(approval_id)
            return self._copy(request) if request is not None else None

    def attach_context(self, approval_id: str, context: dict[str, object]) -> ApprovalRequest:
        with self._lock:
            request = self._requests.get(approval_id)
            if request is None:
                raise KeyError(f"Approval request not found: {approval_id}")
            if request.status != self._status_pending:
                raise ValueError(f"Approval request already resolved or executing: {approval_id}")
            updated = replace(request, context=deepcopy(context))
            self._requests[approval_id] = updated
            return self._copy(updated)

    def _copy(self, request: ApprovalRequest) -> ApprovalRequest:
        return deepcopy(request)

    def _generate_id(self) -> str:
        return uuid4().hex

    def _require_current_execution_attempt(
        self,
        request: ApprovalRequest,
        *,
        expected_execution_attempt_id: str,
    ) -> None:
        expected_attempt = str(expected_execution_attempt_id or "").strip()
        if not expected_attempt:
            raise ValueError("expected_execution_attempt_id is required")
        if request.status != self._status_executing:
            raise ValueError(f"Approval request is not executing: {request.approval_id}")
        if request.execution_attempt_id != expected_attempt:
            raise ValueError(f"Approval execution attempt changed: {request.approval_id}")

    def _is_stale_execution(
        self,
        request: ApprovalRequest,
        *,
        timeout_seconds: float,
        current_time: datetime,
    ) -> bool:
        if request.status != self._status_executing or request.execution_started_at is None:
            return False
        started_at = request.execution_started_at
        if started_at.tzinfo is None:
            started_at = started_at.replace(tzinfo=UTC)
        elapsed = (current_time - started_at.astimezone(UTC)).total_seconds()
        return elapsed >= timeout_seconds

