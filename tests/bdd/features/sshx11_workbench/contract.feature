@sshx11 @contract @workbench
Feature: Cross-language SSHX11 contract parity
  As a platform engineer
  I want Go and Python SSHX11 outputs to remain contract-compatible
  So that clients see stable behavior across implementations

  Scenario: Validate normalized contract fixtures
    Given canonical contract fixtures are versioned
    And Go and Python adapters consume the same fixture set
    When the engineer runs "pytest -m 'sshx11 and contract' -q"
    Then parity checks pass for success and failure cases
    And a drift report is written to "artifacts/contracts/drift_report.json"
