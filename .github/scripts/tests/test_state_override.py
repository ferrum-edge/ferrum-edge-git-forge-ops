import importlib.util
import sys
import unittest
from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "state_override.py"
SPEC = importlib.util.spec_from_file_location("state_override", SCRIPT)
assert SPEC and SPEC.loader
state_override = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = state_override
SPEC.loader.exec_module(state_override)


def event(event_id, action, actor, label="gitforgeops/state-override"):
    return {
        "id": event_id,
        "event": action,
        "created_at": f"2026-08-30T00:00:{event_id:02d}Z",
        "label": {"name": label},
        "actor": {"login": actor} if actor else None,
    }


class StateOverrideTests(unittest.TestCase):
    def test_write_maintain_and_admin_are_sufficient_but_triage_is_not(self):
        for permission in ("write", "maintain", "admin"):
            self.assertTrue(state_override.permission_is_sufficient(permission))
        for permission in ("triage", "read", "none", ""):
            self.assertFalse(state_override.permission_is_sufficient(permission))

    def test_remove_and_readd_uses_latest_actor(self):
        pages = [
            [
                event(1, "labeled", "first-writer"),
                event(2, "unlabeled", "remover"),
            ],
            [event(3, "labeled", "current-writer")],
        ]

        effective = state_override.resolve_effective_event(
            pages, "gitforgeops/state-override"
        )

        self.assertEqual(effective["actor"], "current-writer")
        self.assertEqual(effective["event_id"], 3)

    def test_removed_or_renamed_label_has_no_authority(self):
        cases = [
            [[event(1, "labeled", "writer"), event(2, "unlabeled", "writer")]],
            [[event(1, "labeled", "writer", label="state-override-lookalike")]],
        ]
        for pages in cases:
            with self.subTest(pages=pages), self.assertRaises(
                state_override.OverrideError
            ):
                state_override.resolve_effective_event(
                    pages, "gitforgeops/state-override"
                )

    def test_missing_actor_and_pagination_exhaustion_fail_closed(self):
        with self.assertRaisesRegex(state_override.OverrideError, "missing/deleted actor"):
            state_override.resolve_effective_event(
                [[event(1, "labeled", None)]], "gitforgeops/state-override"
            )

        oversized = [[]]
        oversized[0] = [
            {
                "id": index,
                "event": "commented",
                "created_at": "2026-08-30T00:00:00Z",
            }
            for index in range(state_override.MAX_EVENTS + 1)
        ]
        with self.assertRaisesRegex(state_override.OverrideError, "audit bound"):
            state_override.resolve_effective_event(
                oversized, "gitforgeops/state-override"
            )

    def test_malformed_actor_login_fails_closed(self):
        with self.assertRaisesRegex(state_override.OverrideError, "missing/deleted actor"):
            state_override.resolve_effective_event(
                [[event(1, "labeled", "owner/permission")]],
                "gitforgeops/state-override",
            )

    def test_malformed_paginated_response_fails_closed(self):
        with self.assertRaisesRegex(state_override.OverrideError, "array of pages"):
            state_override.resolve_effective_event(
                {"events": []}, "gitforgeops/state-override"
            )


if __name__ == "__main__":
    unittest.main()
