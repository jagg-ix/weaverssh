@sshx11 @ci @workbench
Feature: SSHX11 CI tiered gating
  As a release engineer
  I want tiered gates for fast and deep validation
  So that PR feedback stays fast while quality remains high

  Scenario: Execute required gate tier for a change
    Given gate tiers are defined for pull request and nightly runs
    And each tier has required artifacts and policies
    When the engineer runs the selected SSHX11 test gate
    Then all required checks for that tier pass
    And gate metadata is recorded in the run report
