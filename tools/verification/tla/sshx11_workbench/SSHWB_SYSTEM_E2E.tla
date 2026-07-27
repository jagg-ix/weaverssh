--------------------------- MODULE SSHWB_SYSTEM_E2E --------------------------
EXTENDS Naturals

VARIABLES phase, topologyUp, routesValidated, passed

Init ==
  /\ phase = "init"
  /\ topologyUp = FALSE
  /\ routesValidated = FALSE
  /\ passed = FALSE

Next ==
  \/ /\ phase = "init"
     /\ phase' = "booting"
     /\ UNCHANGED <<topologyUp, routesValidated, passed>>
  \/ /\ phase = "booting"
     /\ phase' = "testing"
     /\ topologyUp' = TRUE
     /\ UNCHANGED <<routesValidated, passed>>
  \/ /\ phase = "testing"
     /\ phase' = "reporting"
     /\ routesValidated' = TRUE
     /\ UNCHANGED <<topologyUp, passed>>
  \/ /\ phase = "reporting"
     /\ phase' = "done"
     /\ passed' = topologyUp /\ routesValidated
     /\ UNCHANGED <<topologyUp, routesValidated>>
  \/ /\ phase = "done"
     /\ UNCHANGED <<phase, topologyUp, routesValidated, passed>>

Spec == Init /\ [][Next]_<<phase, topologyUp, routesValidated, passed>>

NoPassWithoutTopology == passed => topologyUp
NoPassWithoutRoutes == passed => routesValidated

=============================================================================
