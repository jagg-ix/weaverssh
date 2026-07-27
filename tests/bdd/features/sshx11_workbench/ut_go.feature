@sshx11 @unit @go @workbench
Feature: SSHX11 Go unit workbench
  As a platform engineer
  I want deterministic Go unit gates for SSH transport components
  So that protocol and concurrency regressions are caught early

  Scenario: Run Go unit scope with race checks
    Given Go SSH unit packages are enumerated
    And race detection is enabled for CI execution
    When the engineer runs "go test -race ./..."
    Then the command exits with status code 0
    And race findings are empty
    And unit logs are stored as CI artifacts
