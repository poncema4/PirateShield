#lang fsm

#|

A dfa-based (deterministic finite automata) program can be used to classify Access Risk Scores, as a dfa
can be used to accept/reject certain risk scores that are above a certain threshold. 

(make-dfa S Σ F δ ['no-dead])

Where:
S = the set of all thresholds for risk scores 
Σ = the set of all restricted actions in a policy-based rule system during a given event
F = the accepting state, where no action is needed (threshold < 40)
δ = the set of all transition functions for every state such that state ∈ S

ROLE-CONTEXT-RULES CREATION

Σ: '(rv bd oh rf low med high)

Restricted actions: 
rv = Role Violation (+40 points)
bd = Bulk Download (+30 points)
oh = Off-Hours Sensitive Access (+20 points) 
rf = Repeated Failed Access Attempts (+25 points)

Sensitivity factors: 
low = 0.8
med = 1
high = 1.2

ROLE-CONTEXT-RULES = {w | (w ∈ Σ⁺ ^ u⁺ ∈ Σ such that w = us) ^ (BAR * s < 40)}

Where:
w = an access event
u⁺ = 1 or more restricted actions
s = sensitivity factor

; UNIT TESTS

(check-reject? ROLE-CONTEXT-RULES '() '(rv bd oh low) '(rv med) '(rf bd high) '(bd oh low))
(check-accept? ROLE-CONTEXT-RULES '(bd med) '(rv low) '(oh rf low))

; States
S: The starting state (BAR = 0)
SAFE-20: An intermediate, safe state (BAR = 20)
SAFE-25: An intermediate, safe state (BAR = 25)
SAFE-30: An intermediate, safe state (BAR = 30)
WARNING-40: From an intermediate, unsafe state (BAR = 40)
WARNING-45: From an intermediate, unsafe state (BAR = 45)
WARNING-50: From an intermediate, unsafe state (BAR = 50)
WARNING-55: From an intermediate, unsafe state (BAR = 55)
R: The rejecting state, where no sensitivity factor can bring the score below 40. (BAR >= 60) and or the structure of w is invalid.
A: The accepting state (FAR < 40)

;; Transition rules
(state action next-state)

(S rv WARNING-40)
(S bd SAFE-30)
(S oh SAFE-20)
(S rf SAFE-25)

(SAFE-20 rv R)
(SAFE-20 bd WARNING-50)
(SAFE-20 oh SAFE-40)
(SAFE-20 rf WARNING-45)

(SAFE-25 rv R)
(SAFE-25 bd WARNING-55)
(SAFE-25 oh WARNING-45)
(SAFE-25 rf WARNING-50)

(SAFE-30 rv R)
(SAFE-30 bd R)
(SAFE-30 oh WARNING-50)
(SAFE-30 rf WARNING-55)

(WARNING-40 rv R)
(WARNING-40 bd R)
(WARNING-40 oh R)
(WARNING-40 rf R)

(WARNING-45 rv R)
(WARNING-45 bd R)
(WARNING-45 oh R)
(WARNING-45 rf R)

(WARNING-50 rv R)
(WARNING-50 bd R)
(WARNING-50 oh R)
(WARNING-50 rf R)

(WARNING-55 rv R)
(WARNING-55 bd R)
(WARNING-55 oh R)
(WARNING-55 rf R)

(SAFE-20  low  A)
(SAFE-20  med  A)
(SAFE-20  high A)
(SAFE-25  low  A)
(SAFE-25  med  A)
(SAFE-25  high A)
(SAFE-30  low  A)
(SAFE-30  med  A)
(SAFE-30  high R)
(WARNING-40 low  A)
(WARNING-40 med  R)
(WARNING-40 high R)
(WARNING-45 low  A)
(WARNING-45 med  R)
(WARNING-45 high R)
(WARNING-50 low  R)
(WARNING-50 med  R)
(WARNING-50 high R)
(WARNING-55 low  R)
(WARNING-55 med  R)
(WARNING-55 high R)
(R  low  R)
(R  med  R)
(R  high R)


WIP: Make invariants represent the numerical result of the calculations done for each action

|#

;; Implementation 
(define ROLE-CONTEXT-RULES (make-dfa `(S B C D E F G H A R)
                             '(rv bd oh rf low med high)
                             'S
                             '(A)
                             `((S rv E)
                               (S bd D)
                               (S oh B)
                               (S rf C)
                               (B rv R)
                               (B bd G)
                               (B oh E)
                               (B rf H)
                               (C rv R)
                               (C bd H)
                               (C oh F)
                               (C rf G)

(SAFE-30 rv R)
(SAFE-30 bd R)
(SAFE-30 oh WARNING-50)
(SAFE-30 rf WARNING-55)

(WARNING-40 rv R)
(WARNING-40 bd R)
(WARNING-40 oh R)
(WARNING-40 rf R)

(WARNING-45 rv R)
(WARNING-45 bd R)
(WARNING-45 oh R)
(WARNING-45 rf R)

(WARNING-50 rv R)
(WARNING-50 bd R)
(WARNING-50 oh R)
(WARNING-50 rf R)

(WARNING-55 rv R)
(WARNING-55 bd R)
(WARNING-55 oh R)
(WARNING-55 rf R)

(SAFE-20  low  A)
(SAFE-20  med  A)
(SAFE-20  high A)
(SAFE-25  low  A)
(SAFE-25  med  A)
(SAFE-25  high A)
(SAFE-30  low  A)
(SAFE-30  med  A)
(SAFE-30  high R)
(WARNING-40 low  A)
(WARNING-40 med  R)
(WARNING-40 high R)
(WARNING-45 low  A)
(WARNING-45 med  R)
(WARNING-45 high R)
(WARNING-50 low  R)
(WARNING-50 med  R)
(WARNING-50 high R)
(WARNING-55 low  R)
(WARNING-55 med  R)
(WARNING-55 high R)
(R  low  R)
(R  med  R)
(R  high R))
                                'no-dead))