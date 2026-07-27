@sshx11 @performance @workbench
Feature: SSHX11 performance regression workbench
  As a performance owner
  I want repeatable benchmark runs with threshold enforcement
  So that regressions are detected automatically

  Scenario: Compare current run against baseline
    Given benchmark baselines are versioned for the target environment
    And measurement tolerances are documented
    When the engineer runs "pytest -m 'sshx11 and performance' -q"
    Then benchmark execution completes successfully
    And regression thresholds are evaluated
    And comparison artifacts are published for review
