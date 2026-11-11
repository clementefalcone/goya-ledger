namespace HotStuff

inductive Phase where
  | prepare
  | precommit
  | commit
  deriving DecidableEq

structure Certificate (Block : Type) where
  round : Nat
  block : Block

structure Ancestry (Block : Type) where
  isAncestor : Block → Block → Prop
  refl : ∀ b, isAncestor b b
  trans : ∀ a b c, isAncestor a b → isAncestor b c → isAncestor a c

def count {n : Nat} (members : Fin n → Bool) : Nat :=
  (List.finRange n).countP members

def Certified {n : Nat} {Block : Type} (voted : Phase → Fin n → Nat → Block → Prop) (f : Nat)
    (phase : Phase) (round : Nat) (block : Block) : Prop :=
  ∃ voters : Fin n → Bool, 2 * f + 1 ≤ count voters ∧ ∀ v, voters v = true → voted phase v round block

def safeToVote {Block : Type} (ancestry : Ancestry Block) (lock : Option (Certificate Block))
    (round : Nat) (block : Block) (justify : Option (Certificate Block)) : Prop :=
  match lock with
  | none => True
  | some l =>
      ancestry.isAncestor l.block block ∨
        ∃ j, justify = some j ∧ l.round < j.round ∧ j.round < round ∧
          ancestry.isAncestor j.block block

structure Execution (n f : Nat) (Block : Type) where
  ancestry : Ancestry Block
  faulty : Fin n → Bool
  voted : Phase → Fin n → Nat → Block → Prop
  lockAt : Fin n → Nat → Option (Certificate Block)
  justifyAt : Fin n → Nat → Option (Certificate Block)
  size : n = 3 * f + 1
  faultyBound : count faulty ≤ f
  precommitOnce : ∀ v r b b', faulty v = false →
    voted .precommit v r b → voted .precommit v r b' → b = b'
  commitOnce : ∀ v r b b', faulty v = false →
    voted .commit v r b → voted .commit v r b' → b = b'
  precommitNeedsPrepareQc : ∀ v r b, faulty v = false →
    voted .precommit v r b → Certified voted f .prepare r b
  commitNeedsPrecommitQc : ∀ v r b, faulty v = false →
    voted .commit v r b → Certified voted f .precommit r b
  prepareIsSafe : ∀ v r b, faulty v = false →
    voted .prepare v r b → safeToVote ancestry (lockAt v r) r b (justifyAt v r)
  lockIsPrecommitQc : ∀ v r l, faulty v = false → lockAt v r = some l →
    Certified voted f .precommit l.round l.block ∧ l.round < r
  justifyIsQc : ∀ v r j, faulty v = false → justifyAt v r = some j →
    ∃ phase, Certified voted f phase j.round j.block
  lockCoversCommit : ∀ v r₁ b₁ r b, faulty v = false →
    voted .commit v r₁ b₁ → voted .prepare v r b → r₁ < r →
    ∃ l, lockAt v r = some l ∧ r₁ ≤ l.round

theorem countP_or_add_and {α : Type} (l : List α) (p q : α → Bool) :
    l.countP (fun a => p a || q a) + l.countP (fun a => p a && q a) =
      l.countP p + l.countP q := by
  induction l with
  | nil => simp
  | cons a t ih =>
    simp only [List.countP_cons]
    cases p a <;> cases q a <;> simp <;> omega

theorem countP_and_le {α : Type} (l : List α) (p q : α → Bool) :
    l.countP (fun a => p a && q a) ≤ l.countP q := by
  induction l with
  | nil => simp
  | cons a t ih =>
    simp only [List.countP_cons]
    cases p a <;> cases q a <;> simp <;> omega

theorem countP_split {α : Type} (l : List α) (p q : α → Bool) :
    l.countP p = l.countP (fun a => p a && !q a) + l.countP (fun a => p a && q a) := by
  induction l with
  | nil => simp
  | cons a t ih =>
    simp only [List.countP_cons]
    cases p a <;> cases q a <;> simp <;> omega

theorem count_le {n : Nat} (members : Fin n → Bool) : count members ≤ n := by
  have h := List.countP_le_length (p := members) (l := List.finRange n)
  simpa [count, List.length_finRange] using h

theorem exists_of_count_pos {n : Nat} (members : Fin n → Bool) (h : 0 < count members) :
    ∃ v, members v = true := by
  obtain ⟨v, _, hv⟩ := List.countP_pos_iff.mp h
  exact ⟨v, hv⟩

theorem honest_member {n f : Nat} (faulty members : Fin n → Bool)
    (hFaulty : count faulty ≤ f) (hMembers : f + 1 ≤ count members) :
    ∃ v, members v = true ∧ faulty v = false := by
  have hSplit := countP_split (List.finRange n) members faulty
  have hBad := countP_and_le (List.finRange n) members faulty
  have hPos : 0 < count (fun v => members v && !faulty v) := by
    simp only [count] at *
    omega
  obtain ⟨v, hv⟩ := exists_of_count_pos _ hPos
  refine ⟨v, ?_, ?_⟩ <;> cases hm : members v <;> cases hf : faulty v <;> simp_all

theorem quorums_share_honest {n f : Nat} (faulty q₁ q₂ : Fin n → Bool)
    (hSize : n = 3 * f + 1) (hFaulty : count faulty ≤ f)
    (h₁ : 2 * f + 1 ≤ count q₁) (h₂ : 2 * f + 1 ≤ count q₂) :
    ∃ v, q₁ v = true ∧ q₂ v = true ∧ faulty v = false := by
  have hSum := countP_or_add_and (List.finRange n) q₁ q₂
  have hUnion := count_le (fun v => q₁ v || q₂ v)
  have hBoth : f + 1 ≤ count (fun v => q₁ v && q₂ v) := by
    simp only [count] at *
    omega
  obtain ⟨v, hv, hHonest⟩ := honest_member faulty _ hFaulty hBoth
  refine ⟨v, ?_, ?_, hHonest⟩ <;> cases h1 : q₁ v <;> cases h2 : q₂ v <;> simp_all

namespace Execution

variable {n f : Nat} {Block : Type} (E : Execution n f Block)

theorem honest_voter {p r b} (h : Certified E.voted f p r b) :
    ∃ v, E.faulty v = false ∧ E.voted p v r b := by
  obtain ⟨q, hq, hVoted⟩ := h
  obtain ⟨v, hv, hHonest⟩ := honest_member E.faulty q E.faultyBound (by omega)
  exact ⟨v, hHonest, hVoted v hv⟩

theorem shared_honest_voter {p₁ r₁ b₁ p₂ r₂ b₂}
    (h₁ : Certified E.voted f p₁ r₁ b₁) (h₂ : Certified E.voted f p₂ r₂ b₂) :
    ∃ v, E.faulty v = false ∧ E.voted p₁ v r₁ b₁ ∧ E.voted p₂ v r₂ b₂ := by
  obtain ⟨q₁, hq₁, hv₁⟩ := h₁
  obtain ⟨q₂, hq₂, hv₂⟩ := h₂
  obtain ⟨v, hm₁, hm₂, hHonest⟩ :=
    quorums_share_honest E.faulty q₁ q₂ E.size E.faultyBound hq₁ hq₂
  exact ⟨v, hHonest, hv₁ v hm₁, hv₂ v hm₂⟩

theorem precommit_qc_unique {r b b'}
    (h : Certified E.voted f .precommit r b) (h' : Certified E.voted f .precommit r b') :
    b = b' := by
  obtain ⟨v, hHonest, hv, hv'⟩ := E.shared_honest_voter h h'
  exact E.precommitOnce v r b b' hHonest hv hv'

theorem commit_qc_unique {r b b'}
    (h : Certified E.voted f .commit r b) (h' : Certified E.voted f .commit r b') :
    b = b' := by
  obtain ⟨v, hHonest, hv, hv'⟩ := E.shared_honest_voter h h'
  exact E.commitOnce v r b b' hHonest hv hv'

theorem prepare_qc_of_certified {p r b} (h : Certified E.voted f p r b) :
    Certified E.voted f .prepare r b := by
  cases p with
  | prepare => exact h
  | precommit =>
    obtain ⟨v, hHonest, hv⟩ := E.honest_voter h
    exact E.precommitNeedsPrepareQc v r b hHonest hv
  | commit =>
    obtain ⟨v, hHonest, hv⟩ := E.honest_voter h
    obtain ⟨w, hwHonest, hw⟩ := E.honest_voter (E.commitNeedsPrecommitQc v r b hHonest hv)
    exact E.precommitNeedsPrepareQc w r b hwHonest hw

theorem prepare_qc_extends_commit {r₁ b₁} (hCommit : Certified E.voted f .commit r₁ b₁) :
    ∀ r b, r₁ < r → Certified E.voted f .prepare r b → E.ancestry.isAncestor b₁ b := by
  intro r
  induction r using Nat.strongRecOn with
  | ind r ih =>
  intro b hLater hPrepare
  obtain ⟨v, hHonest, hCommitVote, hPrepareVote⟩ := E.shared_honest_voter hCommit hPrepare
  obtain ⟨l, hLock, hLockRound⟩ := E.lockCoversCommit v r₁ b₁ r b hHonest hCommitVote hPrepareVote hLater
  obtain ⟨hLockQc, hLockBefore⟩ := E.lockIsPrecommitQc v r l hHonest hLock
  have hLockExtends : E.ancestry.isAncestor b₁ l.block := by
    rcases Nat.lt_or_eq_of_le hLockRound with hAfter | hSame
    · exact ih l.round hLockBefore l.block hAfter (E.prepare_qc_of_certified hLockQc)
    · obtain ⟨w, hwHonest, hw⟩ := E.honest_voter hCommit
      have hCommitQc := E.commitNeedsPrecommitQc w r₁ b₁ hwHonest hw
      rw [← hSame] at hLockQc
      rw [E.precommit_qc_unique hCommitQc hLockQc]
      exact E.ancestry.refl _
  have hSafe := E.prepareIsSafe v r b hHonest hPrepareVote
  rw [hLock] at hSafe
  rcases hSafe with hFromLock | ⟨j, hJustify, hAboveLock, hBefore, hFromJustify⟩
  · exact E.ancestry.trans _ _ _ hLockExtends hFromLock
  · obtain ⟨phase, hJustifyQc⟩ := E.justifyIsQc v r j hHonest hJustify
    have hJustifyExtends :=
      ih j.round hBefore j.block (by omega) (E.prepare_qc_of_certified hJustifyQc)
    exact E.ancestry.trans _ _ _ hJustifyExtends hFromJustify

theorem no_fork {r₁ b₁ r₂ b₂}
    (h₁ : Certified E.voted f .commit r₁ b₁) (h₂ : Certified E.voted f .commit r₂ b₂) :
    E.ancestry.isAncestor b₁ b₂ ∨ E.ancestry.isAncestor b₂ b₁ := by
  rcases Nat.lt_trichotomy r₁ r₂ with hLt | hEq | hGt
  · exact Or.inl (E.prepare_qc_extends_commit h₁ r₂ b₂ hLt (E.prepare_qc_of_certified h₂))
  · subst hEq
    rw [E.commit_qc_unique h₁ h₂]
    exact Or.inl (E.ancestry.refl _)
  · exact Or.inr (E.prepare_qc_extends_commit h₂ r₁ b₁ hGt (E.prepare_qc_of_certified h₁))

end Execution

def fourNodesDecideOneBlock : Execution 4 1 Nat where
  ancestry := ⟨(· ≤ ·), Nat.le_refl, fun _ _ _ => Nat.le_trans⟩
  faulty := fun _ => false
  voted := fun _ _ r b => r = 0 ∧ b = 1
  lockAt := fun _ _ => none
  justifyAt := fun _ _ => none
  size := rfl
  faultyBound := by decide
  precommitOnce := fun _ _ _ _ _ h h' => by omega
  commitOnce := fun _ _ _ _ _ h h' => by omega
  precommitNeedsPrepareQc := fun _ _ _ _ h => ⟨fun _ => true, by decide, fun _ _ => h⟩
  commitNeedsPrecommitQc := fun _ _ _ _ h => ⟨fun _ => true, by decide, fun _ _ => h⟩
  prepareIsSafe := fun _ _ _ _ _ => trivial
  lockIsPrecommitQc := fun _ _ _ _ h => nomatch h
  justifyIsQc := fun _ _ _ _ h => nomatch h
  lockCoversCommit := fun _ _ _ _ _ _ h h' hLater => by omega

theorem fourNodesDecideOneBlock_commits :
    Certified fourNodesDecideOneBlock.voted 1 .commit 0 1 :=
  ⟨fun _ => true, by decide, fun _ _ => ⟨rfl, rfl⟩⟩

end HotStuff
