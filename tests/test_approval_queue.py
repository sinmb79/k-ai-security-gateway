import unittest

from dataclasses import FrozenInstanceError, replace
from datetime import UTC, datetime, timedelta

from kai_security.approval.queue import (
    APPROVAL_STATUS_APPROVED,
    APPROVAL_STATUS_EXECUTING,
    APPROVAL_STATUS_INVALID_CONTEXT,
    APPROVAL_STATUS_PENDING,
    APPROVAL_STATUS_REJECTED,
    InMemoryApprovalQueue,
)


class ApprovalQueueTests(unittest.TestCase):
    def setUp(self) -> None:
        self.queue = InMemoryApprovalQueue()

    def test_create_request(self) -> None:
        request = self.queue.create(
            request_id="req-001",
            requested_by="alice",
            reason="Need human review",
            action="route_external",
        )

        self.assertEqual(request.request_id, "req-001")
        self.assertEqual(request.requested_by, "alice")
        self.assertEqual(request.status, APPROVAL_STATUS_PENDING)
        self.assertIsNone(request.resolved_by)
        self.assertIsNone(request.resolved_at)
        self.assertEqual(request.resolution_comment, "")

        pending = self.queue.list_pending()
        self.assertEqual(len(pending), 1)
        self.assertEqual(pending[0].approval_id, request.approval_id)

    def test_list_pending_and_finish_execution_success(self) -> None:
        first = self.queue.create(
            request_id="req-001",
            requested_by="alice",
            reason="first",
            action="route_external",
        )
        self.queue.create(
            request_id="req-002",
            requested_by="bob",
            reason="second",
            action="route_private",
        )

        self.assertEqual(len(self.queue.list_pending()), 2)

        executing = self.queue.begin_execution(
            first.approval_id,
            resolved_by="manager",
            comment="approved",
        )
        approved = self.queue.finish_execution_success(
            executing.approval_id,
            expected_execution_attempt_id=executing.execution_attempt_id,
            resolved_by="manager",
            comment="approved",
        )
        self.assertEqual(approved.status, APPROVAL_STATUS_APPROVED)
        self.assertEqual(approved.resolved_by, "manager")
        self.assertEqual(approved.resolution_comment, "approved")

        pending = self.queue.list_pending()
        self.assertEqual(len(pending), 1)
        self.assertNotEqual(pending[0].approval_id, first.approval_id)

    def test_reject_request(self) -> None:
        request = self.queue.create(
            request_id="req-003",
            requested_by="alice",
            reason="policy risk",
            action="external_action",
        )
        rejected = self.queue.reject_pending(
            request.approval_id,
            resolved_by="security",
            comment="rejected_by_policy",
        )

        self.assertEqual(rejected.status, APPROVAL_STATUS_REJECTED)
        self.assertEqual(rejected.resolution_comment, "rejected_by_policy")
        self.assertEqual(len(self.queue.list_pending()), 0)

    def test_double_resolve_not_allowed(self) -> None:
        request = self.queue.create(
            request_id="req-004",
            requested_by="alice",
            reason="one-pass",
            action="route_external",
        )
        executing = self.queue.begin_execution(request.approval_id, resolved_by="manager")
        self.queue.finish_execution_success(
            executing.approval_id,
            expected_execution_attempt_id=executing.execution_attempt_id,
            resolved_by="manager",
        )

        with self.assertRaises(ValueError):
            self.queue.reject_pending(request.approval_id, resolved_by="manager")

        current = self.queue.get(request.approval_id)
        self.assertIsNotNone(current)
        self.assertEqual(current.status, APPROVAL_STATUS_APPROVED)

    def test_resolve_does_not_allow_pending_direct_approve(self) -> None:
        request = self.queue.create(
            request_id="req-direct",
            requested_by="alice",
            reason="must execute first",
            action="require_approval",
        )

        with self.assertRaises(ValueError):
            self.queue.resolve(request.approval_id, approved=True, resolved_by="manager")

        current = self.queue.get(request.approval_id)
        self.assertIsNotNone(current)
        self.assertEqual(current.status, APPROVAL_STATUS_PENDING)

    def test_execution_state_blocks_duplicate_execution_and_can_retry_after_failure(self) -> None:
        request = self.queue.create(
            request_id="req-exec",
            requested_by="alice",
            reason="provider review",
            action="require_approval",
        )

        executing = self.queue.begin_execution(
            request.approval_id,
            resolved_by="manager-1",
            comment="approve",
        )

        self.assertEqual(executing.status, APPROVAL_STATUS_EXECUTING)
        self.assertEqual(executing.attempt_count, 1)
        self.assertIsNotNone(executing.execution_attempt_id)
        self.assertEqual(len(self.queue.list_pending()), 0)
        with self.assertRaises(ValueError):
            self.queue.begin_execution(request.approval_id, resolved_by="manager-2")

        pending = self.queue.fail_execution(
            request.approval_id,
            expected_execution_attempt_id=executing.execution_attempt_id,
            error_type="provider_timeout",
            retryable=True,
        )

        self.assertEqual(pending.status, APPROVAL_STATUS_PENDING)
        self.assertEqual(pending.attempt_count, 1)
        self.assertEqual(pending.last_execution_error, "provider_timeout")
        self.assertTrue(pending.last_execution_retryable)
        self.assertIsNotNone(pending.first_failed_at)
        self.assertIsNotNone(pending.last_failed_at)
        self.assertEqual(len(self.queue.list_pending()), 1)

        retry = self.queue.begin_execution(request.approval_id, resolved_by="manager-1")
        self.assertEqual(retry.status, APPROVAL_STATUS_EXECUTING)
        self.assertEqual(retry.attempt_count, 2)
        self.assertNotEqual(retry.execution_attempt_id, executing.execution_attempt_id)

        approved = self.queue.finish_execution_success(
            retry.approval_id,
            expected_execution_attempt_id=retry.execution_attempt_id,
            resolved_by="manager-1",
        )
        self.assertEqual(approved.status, APPROVAL_STATUS_APPROVED)
        self.assertIsNone(approved.execution_started_at)
        self.assertIsNone(approved.last_execution_error)
        self.assertIsNone(approved.last_execution_retryable)

    def test_non_retryable_provider_failure_requires_admin_reset_before_retry(self) -> None:
        request = self.queue.create(
            request_id="req-non-retryable",
            requested_by="alice",
            reason="provider review",
            action="require_approval",
        )
        executing = self.queue.begin_execution(request.approval_id, resolved_by="manager-1")
        pending = self.queue.fail_execution(
            request.approval_id,
            expected_execution_attempt_id=executing.execution_attempt_id,
            error_type="provider_http_error",
            retryable=False,
        )

        self.assertEqual(pending.status, APPROVAL_STATUS_PENDING)
        self.assertFalse(pending.last_execution_retryable)
        with self.assertRaises(ValueError):
            self.queue.begin_execution(request.approval_id, resolved_by="manager-1")

        reset = self.queue.reset_execution_error(
            request.approval_id,
            reset_by="admin-1",
            reason_code="provider_config_fixed",
        )
        self.assertEqual(reset.status, APPROVAL_STATUS_PENDING)
        self.assertEqual(reset.last_execution_error, "provider_http_error")
        self.assertTrue(reset.last_execution_retryable)
        self.assertIsNotNone(reset.last_execution_reset_at)
        self.assertEqual(reset.last_execution_reset_by, "admin-1")
        self.assertEqual(reset.last_execution_reset_reason_code, "provider_config_fixed")

        retry = self.queue.begin_execution(request.approval_id, resolved_by="manager-1")
        self.assertEqual(retry.status, APPROVAL_STATUS_EXECUTING)
        self.assertEqual(retry.attempt_count, 2)

    def test_reset_execution_error_rejects_retryable_and_invalid_context_items(self) -> None:
        retryable = self.queue.create(
            request_id="req-retryable",
            requested_by="alice",
            reason="provider review",
            action="require_approval",
        )
        executing = self.queue.begin_execution(retryable.approval_id, resolved_by="manager-1")
        self.queue.fail_execution(
            retryable.approval_id,
            expected_execution_attempt_id=executing.execution_attempt_id,
            error_type="provider_timeout",
            retryable=True,
        )

        with self.assertRaises(ValueError):
            self.queue.reset_execution_error(
                retryable.approval_id,
                reset_by="admin-1",
                reason_code="provider_config_fixed",
            )

        invalid = self.queue.create(
            request_id="req-invalid-reset",
            requested_by="alice",
            reason="provider review",
            action="require_approval",
        )
        invalid_executing = self.queue.begin_execution(invalid.approval_id, resolved_by="manager-1")
        self.queue.fail_execution(
            invalid.approval_id,
            expected_execution_attempt_id=invalid_executing.execution_attempt_id,
            error_type="stored_approval_context_error",
            retryable=False,
            final_status=APPROVAL_STATUS_INVALID_CONTEXT,
        )

        with self.assertRaises(ValueError):
            self.queue.reset_execution_error(
                invalid.approval_id,
                reset_by="admin-1",
                reason_code="provider_config_fixed",
            )

    def test_reset_execution_error_allows_only_provider_execution_errors(self) -> None:
        for error_type in ("gateway_runtime_error", "approval_backend_error", "future_error"):
            request = self.queue.create(
                request_id=f"req-{error_type}",
                requested_by="alice",
                reason="provider review",
                action="require_approval",
            )
            executing = self.queue.begin_execution(request.approval_id, resolved_by="manager-1")
            self.queue.fail_execution(
                request.approval_id,
                expected_execution_attempt_id=executing.execution_attempt_id,
                error_type=error_type,
                retryable=False,
            )

            with self.assertRaises(ValueError):
                self.queue.reset_execution_error(
                    request.approval_id,
                    reset_by="admin-1",
                    reason_code="provider_config_fixed",
                )

    def test_non_retryable_context_failure_blocks_reexecution_but_can_be_rejected(self) -> None:
        request = self.queue.create(
            request_id="req-invalid-context",
            requested_by="alice",
            reason="provider review",
            action="require_approval",
        )
        executing = self.queue.begin_execution(request.approval_id, resolved_by="manager-1")

        invalid = self.queue.fail_execution(
            request.approval_id,
            expected_execution_attempt_id=executing.execution_attempt_id,
            error_type="stored_approval_context_error",
            retryable=False,
            final_status=APPROVAL_STATUS_INVALID_CONTEXT,
        )

        self.assertEqual(invalid.status, APPROVAL_STATUS_INVALID_CONTEXT)
        self.assertFalse(invalid.last_execution_retryable)
        self.assertEqual(len(self.queue.list_pending()), 1)
        self.assertEqual(self.queue.list_pending()[0].status, APPROVAL_STATUS_INVALID_CONTEXT)
        with self.assertRaises(ValueError):
            self.queue.begin_execution(request.approval_id, resolved_by="manager-2")

        rejected = self.queue.reject_pending(
            request.approval_id,
            resolved_by="manager-2",
            comment="operator closed invalid context",
        )
        self.assertEqual(rejected.status, APPROVAL_STATUS_REJECTED)
        self.assertEqual(len(self.queue.list_pending()), 0)

    def test_old_execution_attempt_cannot_finish_or_fail_new_attempt_after_recovery(self) -> None:
        request = self.queue.create(
            request_id="req-aba",
            requested_by="alice",
            reason="provider review",
            action="require_approval",
        )
        old_attempt = self.queue.begin_execution(request.approval_id, resolved_by="manager-1")
        now = datetime.now(UTC)
        stale_started_at = now - timedelta(seconds=600)
        self.queue._requests[request.approval_id] = replace(
            self.queue._requests[request.approval_id],
            execution_started_at=stale_started_at,
            last_execution_started_at=stale_started_at,
        )
        self.queue.recover_stale_executions(timeout_seconds=300, now=now)
        new_attempt = self.queue.begin_execution(request.approval_id, resolved_by="manager-2")

        with self.assertRaises(ValueError):
            self.queue.finish_execution_success(
                request.approval_id,
                expected_execution_attempt_id=old_attempt.execution_attempt_id,
                resolved_by="manager-1",
            )
        with self.assertRaises(ValueError):
            self.queue.fail_execution(
                request.approval_id,
                expected_execution_attempt_id=old_attempt.execution_attempt_id,
                error_type="provider_timeout",
            )

        current = self.queue.get(request.approval_id)
        self.assertIsNotNone(current)
        self.assertEqual(current.status, APPROVAL_STATUS_EXECUTING)
        self.assertEqual(current.execution_attempt_id, new_attempt.execution_attempt_id)
        approved = self.queue.finish_execution_success(
            request.approval_id,
            expected_execution_attempt_id=new_attempt.execution_attempt_id,
            resolved_by="manager-2",
        )
        self.assertEqual(approved.status, APPROVAL_STATUS_APPROVED)

    def test_recover_stale_executions_returns_old_executing_requests_to_pending(self) -> None:
        request = self.queue.create(
            request_id="req-stale",
            requested_by="alice",
            reason="provider review",
            action="require_approval",
        )
        executing = self.queue.begin_execution(request.approval_id, resolved_by="manager-1")
        now = datetime.now(UTC)
        stale_started_at = now - timedelta(seconds=600)
        self.queue._requests[request.approval_id] = replace(
            self.queue._requests[request.approval_id],
            execution_started_at=stale_started_at,
            last_execution_started_at=stale_started_at,
        )

        recovered = self.queue.recover_stale_executions(timeout_seconds=300, now=now)

        self.assertEqual(len(recovered), 1)
        self.assertEqual(recovered[0].approval_id, request.approval_id)
        self.assertEqual(recovered[0].status, APPROVAL_STATUS_PENDING)
        self.assertEqual(recovered[0].execution_attempt_id, executing.execution_attempt_id)
        self.assertEqual(recovered[0].last_execution_started_at, stale_started_at)
        self.assertIsNone(recovered[0].execution_started_at)
        self.assertEqual(recovered[0].last_execution_error, "execution_timeout")
        self.assertTrue(recovered[0].last_execution_retryable)
        self.assertEqual(len(self.queue.list_pending()), 1)

    def test_defensive_copy_on_returned_objects(self) -> None:
        request = self.queue.create(
            request_id="req-005",
            requested_by="alice",
            reason="immutability",
            action="route_external",
        )

        first_lookup = self.queue.get(request.approval_id)
        second_lookup = self.queue.get(request.approval_id)
        self.assertIsNot(first_lookup, second_lookup)

        with self.assertRaises(FrozenInstanceError):
            first_lookup.status = APPROVAL_STATUS_APPROVED

        self.assertEqual(self.queue.get(request.approval_id).status, APPROVAL_STATUS_PENDING)

        pending = self.queue.list_pending()
        self.assertEqual(len(pending), 1)
        self.assertEqual(pending[0].status, APPROVAL_STATUS_PENDING)


if __name__ == "__main__":
    unittest.main()

