-------------------------- MODULE SSHWB_PERFORMANCE --------------------------
EXTENDS Naturals

VARIABLES phase, baselineLoaded, thresholdsChecked, regressionFree, passed

Init ==
  /\ phase = "init"
  /\ baselineLoaded = FALSE
  /\ thresholdsChecked = FALSE
  /\ regressionFree = FALSE
  /\ passed = FALSE

Next ==
  \/ /\ phase = "init"
     /\ phase' = "benchmarking"
     /\ baselineLoaded' = TRUE
     /\ UNCHANGED <<thresholdsChecked, regressionFree, passed>>
  \/ /\ phase = "benchmarking"
     /\ phase' = "comparing"
     /\ thresholdsChecked' = TRUE
     /\ regressionFree' = TRUE
     /\ UNCHANGED <<baselineLoaded, passed>>
  \/ /\ phase = "comparing"
     /\ phase' = "done"
     /\ passed' = baselineLoaded /\ thresholdsChecked /\ regressionFree
     /\ UNCHANGED <<baselineLoaded, thresholdsChecked, regressionFree>>
  \/ /\ phase = "done"
     /\ UNCHANGED <<phase, baselineLoaded, thresholdsChecked, regressionFree, passed>>

Spec == Init /\ [][Next]_<<phase, baselineLoaded, thresholdsChecked, regressionFree, passed>>

NoPassWithoutBaseline == passed => baselineLoaded
NoPassWithoutThresholdCheck == passed => thresholdsChecked

=============================================================================
