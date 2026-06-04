import unittest

from dataclasses import FrozenInstanceError

from kai_security.approval.queue import (
    APPROVAL_STATUS_APPROVED,
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

    def test_list_pending_and_resolve(self) -> None:
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

        approved = self.queue.resolve(
            approval_id=first.approval_id,
            approved=True,
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
        rejected = self.queue.resolve(
            approval_id=request.approval_id,
            approved=False,
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
        self.queue.resolve(request.approval_id, approved=True, resolved_by="manager")

        with self.assertRaises(ValueError):
            self.queue.resolve(request.approval_id, approved=False, resolved_by="manager")

        current = self.queue.get(request.approval_id)
        self.assertIsNotNone(current)
        self.assertEqual(current.status, APPROVAL_STATUS_APPROVED)

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

