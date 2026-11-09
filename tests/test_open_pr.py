"""Tests for the parts that decide what reaches a repository.

The model's bucket is advisory. These rules are not: they pick the version,
refuse breaking moves, and report regressions. A silent failure here would
open a bad pull request, so this is the code worth testing.

    python3 -m unittest discover tests -v
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from open_pr import diff_findings, finding_key, rank, required_fix, verify_comment
from triage_cohere import build_groups, guardrail, is_breaking, package_name, version_key


def finding(package="lodash", version="4.17.12", advisory="SNYK-1", severity="high",
            fix="4.18.1", fix_available=True, paths=None):
    return {
        "id": advisory, "title": "t", "package": package, "current_version": version,
        "fix_version": fix, "severity": severity, "cvss": 7.5, "major_bump": False,
        "direct": False, "fix_available": fix_available, "dependency_paths": 1,
        "example_paths": paths if paths is not None else [f"app@1.0.0 > {package}@{version}"],
    }


class VersionRules(unittest.TestCase):
    def test_major_change_is_breaking(self):
        self.assertTrue(is_breaking("2.6.3", "3.0.1"))
        self.assertFalse(is_breaking("4.16.0", "4.22.3"))

    def test_below_one_a_minor_change_is_breaking(self):
        # 0.x has no stability promise, so the minor is the breaking number
        self.assertTrue(is_breaking("0.3.1", "0.7.2"))
        self.assertFalse(is_breaking("0.3.1", "0.3.9"))

    def test_crossing_into_one_is_breaking(self):
        self.assertTrue(is_breaking("0.9.0", "1.0.0"))

    def test_no_target_is_not_breaking(self):
        self.assertFalse(is_breaking("1.0.0", None))

    def test_versions_compare_numerically_not_as_strings(self):
        self.assertGreater(version_key("4.18.1"), version_key("4.9.0"))
        self.assertGreater(version_key("1.1.20"), version_key("1.1.3"))

    def test_prerelease_suffix_does_not_crash(self):
        self.assertEqual(version_key("1.2.3-beta"), (1, 2, 3))


class FixFloor(unittest.TestCase):
    def test_takes_the_highest_fix_for_the_named_package(self):
        group = {"findings": [
            finding(package="express", version="4.16.0", advisory="A", fix="4.19.2"),
            finding(package="express", version="4.16.0", advisory="B", fix="4.17.3"),
            finding(package="qs", version="6.5.1", advisory="C", fix="6.99.0"),
        ]}
        self.assertEqual(required_fix(group, "express"), "4.19.2")

    def test_none_when_the_package_itself_has_no_finding(self):
        group = {"findings": [finding(package="qs", fix="6.14.1")]}
        self.assertIsNone(required_fix(group, "express"))


class Guardrail(unittest.TestCase):
    def test_breaking_upgrade_blocks_act_now(self):
        group = {"findings": [finding(severity="critical", version="0.3.1", fix="0.7.2")]}
        final, note = guardrail(group, "act_now")
        self.assertEqual(final, "needs_human")
        self.assertIn("breaking", note)

    def test_missing_fix_blocks_act_now(self):
        group = {"findings": [finding(severity="critical", fix=None, fix_available=False)]}
        final, _ = guardrail(group, "act_now")
        self.assertEqual(final, "needs_human")

    def test_medium_only_group_is_downgraded(self):
        group = {"findings": [finding(severity="medium"), finding(severity="low")]}
        final, note = guardrail(group, "act_now")
        self.assertEqual(final, "batch_later")
        self.assertIn("medium or low", note)

    def test_clean_group_is_left_alone(self):
        group = {"findings": [finding(severity="high")]}
        self.assertEqual(guardrail(group, "act_now"), ("act_now", None))

    def test_guardrail_never_promotes(self):
        # it may only ever be more conservative than the model
        group = {"findings": [finding(severity="critical")]}
        for bucket in ("needs_human", "batch_later"):
            self.assertEqual(guardrail(group, bucket), (bucket, None))


class Grouping(unittest.TestCase):
    def test_groups_by_the_direct_dependency(self):
        findings = [
            finding(package="qs", paths=["app@1.0.0 > express@4.16.0 > qs@6.5.1"]),
            finding(package="cookie", paths=["app@1.0.0 > express@4.16.0 > cookie@0.3.1"]),
            finding(package="lodash", paths=["app@1.0.0 > lodash@4.17.12"]),
        ]
        groups = {g["key"]: g for g in build_groups(findings, {"express": "production"})}
        self.assertEqual(len(groups["express@4.16.0"]["findings"]), 2)
        self.assertEqual(groups["express@4.16.0"]["scope"], "production")
        self.assertEqual(groups["lodash@4.17.12"]["scope"], "unknown")

    def test_scoped_package_names_survive_the_split(self):
        self.assertEqual(package_name("@snyk/nodejs-runtime-agent@1.43.0"),
                         "@snyk/nodejs-runtime-agent")

    def test_worst_severity_ranks_first(self):
        critical = {"findings": [finding(severity="critical")]}
        high = {"findings": [finding(severity="high"), finding(severity="high")]}
        self.assertLess(rank(critical), rank(high))


class Diff(unittest.TestCase):
    def test_version_is_part_of_identity(self):
        # the same advisory against two installed versions is two findings
        base = [finding(version="4.17.12", advisory="X"), finding(version="4.17.15", advisory="X")]
        fixed, new, before, after = diff_findings(base, [])
        self.assertEqual((before, after), (2, 0))
        self.assertEqual(len(fixed), 2)

    def test_counts_fixed_and_new_separately(self):
        base = [finding(package="lodash"), finding(package="express")]
        after = [finding(package="express"), finding(package="qs")]
        fixed, new, _, _ = diff_findings(base, after)
        self.assertEqual([f["package"] for f in fixed], ["lodash"])
        self.assertEqual([f["package"] for f in new], ["qs"])

    def test_unchanged_set_reports_nothing(self):
        rows = [finding()]
        fixed, new, _, _ = diff_findings(rows, list(rows))
        self.assertEqual((fixed, new), ([], []))

    def test_key_uses_package_version_and_advisory(self):
        self.assertEqual(finding_key(finding()), ("lodash", "4.17.12", "SNYK-1"))


class VerifyComment(unittest.TestCase):
    def test_a_regression_is_stated_plainly(self):
        body = verify_comment([], [finding(package="qs", severity="high")], 10, 11)
        self.assertIn("**1 new finding introduced.**", body)
        self.assertIn("qs", body)
        self.assertNotIn("No new findings", body)

    def test_regressions_are_pluralized(self):
        body = verify_comment([], [finding(package="a"), finding(package="b")], 10, 12)
        self.assertIn("**2 new findings introduced.**", body)

    def test_a_clean_result_does_not_claim_the_app_works(self):
        body = verify_comment([finding()], [], 10, 9)
        self.assertIn("No new findings", body)
        self.assertIn("does not do one", body)

    def test_counts_appear_in_the_comment(self):
        body = verify_comment([finding(), finding()], [], 265, 263)
        self.assertIn("265 → 263", body)
        self.assertIn("2 fixed, 0 new", body)


if __name__ == "__main__":
    unittest.main()
