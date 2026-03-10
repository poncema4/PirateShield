#lang fsm

#|
ROLE-CONTEXT-RULES CREATION
States represent the current numerical score
Language represent the set of all possible restricted actions
Invariants represent the result of the calculations done for each action

rv = Role Violation (+40 points)
bd = Bulk Download (+30 points)
oh = Off-Hours Sensitive Access (+20 points) 
rf = Repeated Failed Access Attempts (+25 points)

Sensitivity Adjustment
LOW = BAR * 0.8
MED = BAR
HIGH = BAR * 1.2

rs = risk score
REJECT_SCORE = an arbitrary numerical value (For this example, let's say 75)
s = Sensitvity Adjustment

L = {rs * s | rs <= REJECT_SCORE}
Σ = {rv bd oh rf}

; (check-reject? ROLE-CONTEXT-RULES '() '(rv bd oh LOW) '(b a b b a a) '(a b b b b) '(b a b b a a b))
; (check-accept? ROLE-CONTEXT-RULES

|#