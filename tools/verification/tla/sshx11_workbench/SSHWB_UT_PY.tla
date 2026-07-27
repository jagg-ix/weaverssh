----------------------------- MODULE SSHWB_UT_PY -----------------------------
EXTENDS Naturals

VARIABLES phase, junitReady, coverageReady, passed

Init ==
  /\ phase = "init"
  /\ junitReady = FALSE
  /\ coverageReady = FALSE
  /\ passed = FALSE

Next ==
  \/ /\ phase = "init"
     /\ phase' = "running"
     /\ UNCHANGED <<junitReady, coverageReady, passed>>
  \/ /\ phase = "running"
     /\ phase' = "reporting"
     /\ junitReady' = TRUE
     /\ coverageReady' = TRUE
     /\ UNCHANGED passed
  \/ /\ phase = "reporting"
     /\ phase' = "done"
     /\ passed' = junitReady /\ coverageReady
     /\ UNCHANGED <<junitReady, coverageReady>>
  \/ /\ phase = "done"
     /\ UNCHANGED <<phase, junitReady, coverageReady, passed>>

Spec == Init /\ [][Next]_<<phase, junitReady, coverageReady, passed>>

NoFalsePass == passed => (junitReady /\ coverageReady)
TerminalDone == phase = "done" => passed

=============================================================================
