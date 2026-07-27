@sshx11 @system @workbench
Feature: SSHX11 system end-to-end topology
  As a platform engineer
  I want environment-faithful end-to-end SSHX11 tests
  So that routing, forwarding, and SOCKS and backhaul flows are validated together

  Scenario: Execute system suite on ephemeral topology
    Given the SSHX11 system topology is up and healthy
    And X11 probe and transfer targets are reachable
    When the engineer runs "pytest -m 'sshx11 and system' -q"
    Then all mandatory end-to-end scenarios pass
    And evidence artifacts are captured for each route type
