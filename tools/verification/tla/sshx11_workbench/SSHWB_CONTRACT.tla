---------------------------- MODULE SSHWB_CONTRACT ---------------------------
EXTENDS Naturals

VARIABLES phase, fixtureParity, errorCodeParity, passed

Init ==
  /\ phase = "init"
  /\ fixtureParity = FALSE
  /\ errorCodeParity = FALSE
  /\ passed = FALSE

Next ==
  \/ /\ phase = "init"
     /\ phase' = "comparing"
     /\ UNCHANGED <<fixtureParity, errorCodeParity, passed>>
  \/ /\ phase = "comparing"
     /\ phase' = "reporting"
     /\ fixtureParity' = TRUE
     /\ errorCodeParity' = TRUE
     /\ UNCHANGED passed
  \/ /\ phase = "reporting"
     /\ phase' = "done"
     /\ passed' = fixtureParity /\ errorCodeParity
     /\ UNCHANGED <<fixtureParity, errorCodeParity>>
  \/ /\ phase = "done"
     /\ UNCHANGED <<phase, fixtureParity, errorCodeParity, passed>>

Spec == Init /\ [][Next]_<<phase, fixtureParity, errorCodeParity, passed>>

ParityBeforePass == passed => (fixtureParity /\ errorCodeParity)
TerminalDone == phase = "done" => passed

=============================================================================
