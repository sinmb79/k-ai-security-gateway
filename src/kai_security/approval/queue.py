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
            executing = replace(
                request,
                status=self._status_executing,
                resolved_by=resolved_by,
                resolution_comment=comment,
                execution_attempt_id=self._generate_id(),
                attempt_count=request.attempt_count + 1,
                execution_started_at=datetime.now(UTC),
            )
            self._requests[approval_id] = executing
            return self._copy(executing)

    def fail_execution(self, approval_id: str, *, error_type: str) -> ApprovalRequest:
        with self._lock:
            request = self._requests.get(approval_id)
            if request is None:
                raise KeyError(f"Approval request not found: {approval_id}")
            if request.status != self._status_executing:
                raise ValueError(f"Approval request is not executing: {approval_id}")
            failed_at = datetime.now(UTC)
            pending = replace(
                request,
                status=self._status_pending,
                execution_started_at=None,
                first_failed_at=request.first_failed_at or failed_at,
                last_failed_at=failed_at,
                last_execution_error=error_type,
            )
            self._requests[approval_id] = pending
            return self._copy(pending)

    def resolve(
        self,
        approval_id: str,
        approved: bool,
        resolved_by: str,
        comment: str = "",
    ) -> ApprovalRequest:
        with self._lock:
            request = self._requests.get(approval_id)
            if request is None:
                raise KeyError(f"Approval request not found: {approval_id}")
            expected_statuses = {self._status_pending}
            if approved:
                expected_statuses.add(self._status_executing)
            if request.status not in expected_statuses:
                raise ValueError(f"Approval request already resolved or executing: {approval_id}")

            resolved_request = replace(
                request,
                status=self._status_approved if approved else self._status_rejected,
                resolved_by=resolved_by,
                resolved_at=datetime.now(UTC),
                resolution_comment=comment,
                execution_started_at=None,
                context=deepcopy(request.context),
            )
            self._requests[approval_id] = resolved_request
            return self._copy(resolved_request)

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

