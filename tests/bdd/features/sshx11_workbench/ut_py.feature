@sshx11 @unit @python @workbench
Feature: SSHX11 Python unit workbench
  As a platform engineer
  I want deterministic Python unit gates for SSHX11 modules
  So that regressions are detected before integration tests

  Scenario: Run Python unit scope with artifact output
    Given the SSHX11 Python module inventory is defined
    And deterministic unit fixtures are available
    When the engineer runs "pytest -m 'sshx11 and unit' -q"
    Then the command exits with status code 0
    And junit output is written to "artifacts/junit/ut_py.xml"
    And coverage evidence is generated for targeted modules
