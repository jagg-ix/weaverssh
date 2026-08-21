-------------------------- MODULE TerminalSession --------------------------
EXTENDS Naturals

CONSTANT MaxGeneration

States == {"PROVISIONING", "ACTIVE", "DETACHING", "DETACHED",
           "RECOVERING", "TERMINATED"}

VARIABLES state, generation, attachment, ttlArmed, everTerminated,
          writes, staleMutation

vars == <<state, generation, attachment, ttlArmed, everTerminated,
          writes, staleMutation>>

Init ==
    /\ state = "PROVISIONING"
    /\ generation = 0
    /\ attachment = 0
    /\ ttlArmed = FALSE
    /\ everTerminated = FALSE
    /\ writes = 0
    /\ staleMutation = FALSE

ProvisionOK ==
    /\ state = "PROVISIONING"
    /\ state' = "ACTIVE"
    /\ generation' = 1
    /\ attachment' = 1
    /\ ttlArmed' = FALSE
    /\ UNCHANGED <<everTerminated, writes, staleMutation>>

ProvisionFail ==
    /\ state = "PROVISIONING"
    /\ state' = "TERMINATED"
    /\ attachment' = 0
    /\ ttlArmed' = FALSE
    /\ everTerminated' = TRUE
    /\ UNCHANGED <<generation, writes, staleMutation>>

NetworkDrop ==
    /\ state = "ACTIVE"
    /\ state' = "DETACHING"
    /\ attachment' = 0
    /\ UNCHANGED <<generation, ttlArmed, everTerminated, writes, staleMutation>>

FinishDetach ==
    /\ state = "DETACHING"
    /\ state' = "DETACHED"
    /\ ttlArmed' = TRUE
    /\ UNCHANGED <<generation, attachment, everTerminated, writes, staleMutation>>

\* Reattach is deliberately enabled from ACTIVE: it preempts a ghost transport
\* by installing a strictly newer attachment generation.
Reattach ==
    /\ state \in {"ACTIVE", "DETACHED"}
    /\ generation < MaxGeneration
    /\ state' = "RECOVERING"
    /\ generation' = generation + 1
    /\ attachment' = generation + 1
    /\ ttlArmed' = FALSE
    /\ UNCHANGED <<everTerminated, writes, staleMutation>>

RecoverOK ==
    /\ state = "RECOVERING"
    /\ state' = "ACTIVE"
    /\ UNCHANGED <<generation, attachment, ttlArmed, everTerminated,
                   writes, staleMutation>>

RecoverFail ==
    /\ state = "RECOVERING"
    /\ state' = "DETACHED"
    /\ attachment' = 0
    /\ ttlArmed' = TRUE
    /\ UNCHANGED <<generation, everTerminated, writes, staleMutation>>

TTLExpire ==
    /\ state = "DETACHED"
    /\ ttlArmed
    /\ state' = "TERMINATED"
    /\ attachment' = 0
    /\ ttlArmed' = FALSE
    /\ everTerminated' = TRUE
    /\ UNCHANGED <<generation, writes, staleMutation>>

Terminate ==
    /\ state # "TERMINATED"
    /\ state' = "TERMINATED"
    /\ attachment' = 0
    /\ ttlArmed' = FALSE
    /\ everTerminated' = TRUE
    /\ UNCHANGED <<generation, writes, staleMutation>>

ClientWrite(g) ==
    /\ state = "ACTIVE"
    /\ writes' = IF g = generation /\ attachment = g
                  THEN (writes + 1) % 2 ELSE writes
    /\ staleMutation' = staleMutation \/
          (g # generation /\ writes' # writes)
    /\ UNCHANGED <<state, generation, attachment, ttlArmed,
                   everTerminated>>

Next ==
    \/ ProvisionOK
    \/ ProvisionFail
    \/ NetworkDrop
    \/ FinishDetach
    \/ Reattach
    \/ RecoverOK
    \/ RecoverFail
    \/ TTLExpire
    \/ Terminate
    \/ \E g \in 1..MaxGeneration: ClientWrite(g)

Spec == Init /\ [][Next]_vars

TypeOK ==
    /\ state \in States
    /\ generation \in 0..MaxGeneration
    /\ attachment \in 0..MaxGeneration
    /\ ttlArmed \in BOOLEAN
    /\ everTerminated \in BOOLEAN
    /\ writes \in 0..1
    /\ staleMutation \in BOOLEAN

TerminalIsFinal == everTerminated => state = "TERMINATED"

AttachmentGeneration ==
    /\ (state \in {"ACTIVE", "RECOVERING"} =>
          attachment = generation /\ generation > 0)
    /\ (state \in {"PROVISIONING", "DETACHING", "DETACHED", "TERMINATED"} =>
          attachment = 0)

TTLOnlyDetached == ttlArmed => state = "DETACHED"

StaleWriterCannotMutate == ~staleMutation

=============================================================================
