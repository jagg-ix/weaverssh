-------------------- MODULE SSHWB_OBSERVABILITY_REPORTING --------------------
EXTENDS Naturals

VARIABLES phase, metadataComplete, traceableArtifacts, summaryBuilt, passed

Init ==
  /\ phase = "init"
  /\ metadataComplete = FALSE
  /\ traceableArtifacts = FALSE
  /\ summaryBuilt = FALSE
  /\ passed = FALSE

Next ==
  \/ /\ phase = "init"
     /\ phase' = "collecting"
     /\ UNCHANGED <<metadataComplete, traceableArtifacts, summaryBuilt, passed>>
  \/ /\ phase = "collecting"
     /\ phase' = "building"
     /\ metadataComplete' = TRUE
     /\ traceableArtifacts' = TRUE
     /\ UNCHANGED <<summaryBuilt, passed>>
  \/ /\ phase = "building"
     /\ phase' = "done"
     /\ summaryBuilt' = TRUE
     /\ passed' = metadataComplete /\ traceableArtifacts /\ summaryBuilt
     /\ UNCHANGED <<metadataComplete, traceableArtifacts>>
  \/ /\ phase = "done"
     /\ UNCHANGED <<phase, metadataComplete, traceableArtifacts, summaryBuilt, passed>>

Spec == Init /\ [][Next]_<<phase, metadataComplete, traceableArtifacts, summaryBuilt, passed>>

NoPassWithoutMetadata == passed => metadataComplete
NoPassWithoutTraceability == passed => traceableArtifacts

=============================================================================
