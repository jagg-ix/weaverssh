---------------------- MODULE SSHWB_RESILIENCE_SECURITY ----------------------
EXTENDS Naturals

VARIABLES phase, failClosed, recovered, secretsRedacted, passed

Init ==
  /\ phase = "init"
  /\ failClosed = FALSE
  /\ recovered = FALSE
  /\ secretsRedacted = FALSE
  /\ passed = FALSE

Next ==
  \/ /\ phase = "init"
     /\ phase' = "injecting_faults"
     /\ UNCHANGED <<failClosed, recovered, secretsRedacted, passed>>
  \/ /\ phase = "injecting_faults"
     /\ phase' = "validating"
     /\ failClosed' = TRUE
     /\ recovered' = TRUE
     /\ secretsRedacted' = TRUE
     /\ UNCHANGED passed
  \/ /\ phase = "validating"
     /\ phase' = "done"
     /\ passed' = failClosed /\ recovered /\ secretsRedacted
     /\ UNCHANGED <<failClosed, recovered, secretsRedacted>>
  \/ /\ phase = "done"
     /\ UNCHANGED <<phase, failClosed, recovered, secretsRedacted, passed>>

Spec == Init /\ [][Next]_<<phase, failClosed, recovered, secretsRedacted, passed>>

NoUnsafePass == passed => (failClosed /\ secretsRedacted)
RecoveryRequired == passed => recovered

=============================================================================
