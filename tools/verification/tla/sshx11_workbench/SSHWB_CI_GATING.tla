--------------------------- MODULE SSHWB_CI_GATING ---------------------------
EXTENDS Naturals

VARIABLES phase, tierSelected, requiredChecksPassed, artifactsPublished, passed

Init ==
  /\ phase = "init"
  /\ tierSelected = FALSE
  /\ requiredChecksPassed = FALSE
  /\ artifactsPublished = FALSE
  /\ passed = FALSE

Next ==
  \/ /\ phase = "init"
     /\ phase' = "dispatch"
     /\ tierSelected' = TRUE
     /\ UNCHANGED <<requiredChecksPassed, artifactsPublished, passed>>
  \/ /\ phase = "dispatch"
     /\ phase' = "evaluating"
     /\ requiredChecksPassed' = TRUE
     /\ artifactsPublished' = TRUE
     /\ UNCHANGED <<tierSelected, passed>>
  \/ /\ phase = "evaluating"
     /\ phase' = "done"
     /\ passed' = tierSelected /\ requiredChecksPassed /\ artifactsPublished
     /\ UNCHANGED <<tierSelected, requiredChecksPassed, artifactsPublished>>
  \/ /\ phase = "done"
     /\ UNCHANGED <<phase, tierSelected, requiredChecksPassed, artifactsPublished, passed>>

Spec == Init /\ [][Next]_<<phase, tierSelected, requiredChecksPassed, artifactsPublished, passed>>

NoPassWithoutTier == passed => tierSelected
NoPassWithoutChecks == passed => requiredChecksPassed

=============================================================================
