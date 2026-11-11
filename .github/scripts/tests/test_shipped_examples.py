"""The unit suite's copy of the shipped resource examples stays byte-equal.

Unit tests never read the customer-owned `resources/` tree, so the shipped
`resources/<namespace>/<kind>/_example.yaml` files are checked through copies
under `tests/fixtures/shipped-examples/`. Upstream ships both, and an edit to
one must reach the other or the unit suite tests an example nobody ships.
In a template copy `resources/` belongs to the operator, so the check runs
only in the upstream repository (and locally, where no repository is set).
"""

import os
import unittest
from pathlib import Path


ROOT = Path(__file__).parents[3]
SHIPPED = ROOT / "resources"
FIXTURES = ROOT / "tests" / "fixtures" / "shipped-examples"
# audit_settings.UPSTREAM_REPOSITORY
UPSTREAM_REPOSITORY = "ferrum-edge/ferrum-edge-git-forge-ops"


def _examples(root: Path) -> list[Path]:
    return sorted(path.relative_to(root) for path in root.glob("*/*/_example.yaml"))


class ShippedExampleFixtureTests(unittest.TestCase):
    def test_fixture_copies_equal_the_shipped_examples(self):
        repository = os.environ.get("GITHUB_REPOSITORY", UPSTREAM_REPOSITORY)
        if repository.casefold() != UPSTREAM_REPOSITORY:
            self.skipTest("resources/ is customer-owned in a template copy")
        shipped = _examples(SHIPPED)
        self.assertTrue(shipped, "upstream ships resource examples")
        self.assertEqual(shipped, _examples(FIXTURES))
        for relative in shipped:
            with self.subTest(example=str(relative)):
                self.assertEqual(
                    (SHIPPED / relative).read_bytes(),
                    (FIXTURES / relative).read_bytes(),
                    "copy the shipped example into tests/fixtures/shipped-examples/",
                )


if __name__ == "__main__":
    unittest.main()
