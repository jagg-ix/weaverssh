@sshx11 @security @resilience @workbench
Feature: SSHX11 resilience and security behavior
  As a security-conscious operator
  I want fail-closed security and deterministic recovery behavior
  So that the platform remains safe and reliable under faults

  Scenario: Enforce strict host-key policy and recover from transport faults
    Given strict host-key validation is enabled
    And controlled network fault injection is configured
    When the engineer runs "pytest -m 'sshx11 and (security or resilience)' -q"
    Then host-key tamper scenarios fail closed
    And transient transport failures recover per policy
    And secret values remain redacted in logs
