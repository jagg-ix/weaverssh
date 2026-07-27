@sshx11 @reporting @observability @workbench
Feature: SSHX11 workbench reporting and observability
  As an operator
  I want consistent summary evidence from all test scopes
  So that I can triage failures quickly and reproduce runs

  Scenario: Generate unified test workbench report
    Given junit, coverage, logs, and benchmark artifacts exist
    And metadata includes timestamps, seed, and environment identifiers
    When the engineer runs the report builder
    Then a unified summary is produced in JSON and Markdown
    And each failed case includes traceable artifact references
