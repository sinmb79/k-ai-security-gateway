"""In-memory approval queue implementation."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import ClassVar
from uuid import uuid4


APPROVAL_STATUS_PENDING = "pending"
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
    context: dict[str, object] | None = None


class InMemoryApprovalQueue:
    """In-memory queue that stores approval requests."""

    _status_pending: ClassVar[str] = APPROVAL_STATUS_PENDING
    _status_approved: ClassVar[str] = APPROVAL_STATUS_APPROVED
    _status_rejected: ClassVar[str] = APPROVAL_STATUS_REJECTED

    def __init__(self) -> None:
        self._requests: dict[str, ApprovalRequest] = {}

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
        self._requests[request.approval_id] = request
        return self._copy(request)

    def list_pending(self) -> list[ApprovalRequest]:
        pending = [request for request in self._requests.values() if request.status == self._status_pending]
        return [self._copy(request) for request in pending]

    def resolve(
        self,
        approval_id: str,
        approved: bool,
        resolved_by: str,
        comment: str = "",
    ) -> ApprovalRequest:
        request = self._requests.get(approval_id)
        if request is None:
            raise KeyError(f"Approval request not found: {approval_id}")
        if request.status != self._status_pending:
            raise ValueError(f"Approval request already resolved: {approval_id}")

        resolved_request = ApprovalRequest(
            approval_id=request.approval_id,
            request_id=request.request_id,
            requested_by=request.requested_by,
            reason=request.reason,
            action=request.action,
            created_at=request.created_at,
            status=self._status_approved if approved else self._status_rejected,
            resolved_by=resolved_by,
            resolved_at=datetime.now(UTC),
            resolution_comment=comment,
            context=deepcopy(request.context),
        )
        self._requests[approval_id] = resolved_request
        return self._copy(resolved_request)

    def get(self, approval_id: str) -> ApprovalRequest | None:
        request = self._requests.get(approval_id)
        return self._copy(request) if request is not None else None

    def attach_context(self, approval_id: str, context: dict[str, object]) -> ApprovalRequest:
        request = self._requests.get(approval_id)
        if request is None:
            raise KeyError(f"Approval request not found: {approval_id}")
        if request.status != self._status_pending:
            raise ValueError(f"Approval request already resolved: {approval_id}")
        updated = ApprovalRequest(
            approval_id=request.approval_id,
            request_id=request.request_id,
            requested_by=request.requested_by,
            reason=request.reason,
            action=request.action,
            created_at=request.created_at,
            status=request.status,
            resolved_by=request.resolved_by,
            resolved_at=request.resolved_at,
            resolution_comment=request.resolution_comment,
            context=deepcopy(context),
        )
        self._requests[approval_id] = updated
        return self._copy(updated)

    def _copy(self, request: ApprovalRequest) -> ApprovalRequest:
        return deepcopy(request)

    def _generate_id(self) -> str:
        return uuid4().hex

