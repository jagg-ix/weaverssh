----------------------------- MODULE SSHWB_UT_GO -----------------------------
EXTENDS Naturals

VARIABLES phase, raceClean, fuzzSeeded, passed

Init ==
  /\ phase = "init"
  /\ raceClean = FALSE
  /\ fuzzSeeded = FALSE
  /\ passed = FALSE

Next ==
  \/ /\ phase = "init"
     /\ phase' = "running"
     /\ UNCHANGED <<raceClean, fuzzSeeded, passed>>
  \/ /\ phase = "running"
     /\ phase' = "analyzing"
     /\ raceClean' = TRUE
     /\ fuzzSeeded' = TRUE
     /\ UNCHANGED passed
  \/ /\ phase = "analyzing"
     /\ phase' = "done"
     /\ passed' = raceClean /\ fuzzSeeded
     /\ UNCHANGED <<raceClean, fuzzSeeded>>
  \/ /\ phase = "done"
     /\ UNCHANGED <<phase, raceClean, fuzzSeeded, passed>>

Spec == Init /\ [][Next]_<<phase, raceClean, fuzzSeeded, passed>>

NoFalsePass == passed => (raceClean /\ fuzzSeeded)
TerminalDone == phase = "done" => passed

=============================================================================
