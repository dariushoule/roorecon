---
name: retro
description: Post-engagement retrospective that turns one run's operator↔agent interactions into durable improvements to this repo's skills, runbooks, and tooling. Use at the end of an engagement (after the work, ideally before teardown wipes scratch) to refine skills, extract runbooks, prune box-specific dead weight, propose new skills/tools, and fix the rough edges where the agent tripped. Proposal-first — produces a reviewed changeset the operator approves before anything is written. Triggers on "retro", "retrospective", "debrief", "post-mortem", "what did we learn", "improve the skills", "update the playbooks", "capture lessons", "tune the skills from this engagement".
---

Base directory for this skill: `.claude/skills/retro`

# Retro — turn an engagement into a better toolkit

The learning loop. Every engagement exposes where the skills carried the agent
and where they let it walk into a wall. This skill reads the run back, distils the
durable lessons, and proposes concrete edits to the repo's skills, runbooks, and
`roo` CLI — so the next run starts smarter. It is the knowledge counterpart to
**teardown** (which shuts down infra): run *this* first, while the transcript and
artifacts are warm, then tear down.

This skill **edits the source of truth** every future engagement depends on, so a
bad edit is expensive. Two rules govern everything below:

- **Proposal-first, operator-approved.** Produce a reviewed changeset; the operator
  approves which edits land. Apply approved changes on a branch, never silently to
  `main`. (Same ethos as the rest of the repo: enumerate and plan, the operator
  approves the acting.)
- **Generic over specific — this is the whole game.** A skill captures what is true
  on the *next* box, not what was true on this one. Box facts (which CVE, which ACE,
  the actual password) live in `recon-results/`, never in a skill. The failure mode
  of every retro is over-fitting: enshrining one box's specifics, or one run's fluke,
  as permanent doctrine. Default to *distil the generic lesson or discard it*.

## Scope guardrail

This skill modifies the repo, not a target — no network, no scanning. It runs after
the engagement is otherwise done. It needs nothing in scope beyond the conversation
and the artifacts already on disk.

## What counts as evidence

Read from all four, and trust them in this order when they disagree:

1. **Operator corrections and redirections** — ground truth. Every time the operator
   said "no, use X", "you already tried that", "wrong path", "why didn't you just …"
   is a defect in the agent's defaults or the skills. These are the highest-signal
   items in the whole run; mine them first.
2. **On-disk artifacts** — `recon-results/`, `.roo/`, `./hosts`, loot, and the git
   history of the engagement. These survive context compaction, so when the
   conversation was summarized mid-run they are your most reliable record of what
   actually happened.
3. **The in-context transcript** — the agent's own actions: retries of a failing
   command, long detours that paid nothing, tools invoked that don't exist, footguns
   hit, questions asked that a skill should have answered.
4. **Wins worth codifying** — a path or trick that *worked*. Generalise it the same
   way you generalise a failure.

> Be adversarial about your own transcript. You wrote it, so you will be tempted to
> rationalise the dead-ends as reasonable. Treat operator corrections as fact and
> assume each trip-up was preventable until you've shown it wasn't.

## Workflow

### 1. Did last time's fixes hold? (regression check — do this first)

Before harvesting new lessons, check the old ones stuck. Read `docs/retro-log.md`
(deferred + recurring items from prior retros) and `git log --oneline -15
.claude/skills`. Did this engagement re-hit anything a previous retro claimed to
fix? A regression is the highest-value finding there is: it means a past edit was
wrong, mis-placed, or surfaced too late to help. Flag these separately — they get
priority and they teach you not to repeat the same weak fix.

### 2. Build the friction inventory

Walk the run and list every signal, with a one-line evidence pointer for each
(quote the correction, name the artifact, cite the retry). Group as:

- **Corrections** — where the operator redirected the agent.
- **Dead-ends** — rabbit-holes, repeated failures, retries of the same wrong thing.
- **Gaps** — the agent asked for, or hand-rolled, something a skill/tool should have
  provided.
- **Footguns** — a documented one hit anyway (surfaced too late?) vs a *novel* one
  (nothing warned about it).
- **Wins** — what worked and is worth making repeatable.

Don't fix anything yet. The inventory is the raw material; one pass over the run
feeds all five change types, so collect once.

### 3. Classify each signal

Two axes per item. **Kind:**

- **durable + generic** → candidate skill/runbook edit.
- **box-specific** → belongs in `recon-results/`, *not* a skill. Drop it from the loop.
- **model-only blip** → the agent erred on a run the docs already covered correctly;
  not doc-fixable. Note it, don't edit (thrashing a good skill to chase a one-off
  makes it worse).
- **capability gap** → candidate new tool / skill / `roo` subcommand.

…and **confidence:** *recurring* (seen this engagement and in `retro-log.md`/before)
vs *N=1* (one incident, this run only). **N=1 is a lead, not a verdict.** Unless the
lesson is self-evidently general (a flag that is just objectively correct), prefer
logging an N=1 item to `retro-log.md` over editing a skill — let it earn a change by
recurring. This is what stops the loop from over-fitting to the last box.

### 4. Draft the changeset (the five change types)

Route the durable items into concrete proposals. Each proposal carries: the evidence
pointer, the exact target file + location, a diff sketch, the generic justification,
and an impact×confidence rating. The five types and the discipline each demands:

- **Refine a skill.** Highest leverage, smallest words. Aim at the parts that steer
  behavior: the `description` (it controls *activation* — wrong wording means the
  skill doesn't fire when it should; high blast radius, change carefully), the footgun
  cheat-sheets, and the tool/auth-selection tables. Usually the fix is *tightening or
  correcting* guidance the agent followed into a wall, or surfacing a known footgun
  *earlier*, not adding a paragraph.
- **Extract a runbook.** When a technique's detail is deep *and* cherry-picked, move
  it to `<skill>/runbooks/<technique>.md` and leave a one-line dispatch pointer.
  Cross-cutting judgment stays inline. Follow CLAUDE.md → "Keep SKILL.md lean"; the
  `ad` skill's `runbooks/badsuccessor.md` is the reference example.
- **Prune dead weight.** The conservative, reversible pass — and the one your bias
  fights, because "improving" feels like adding. Cut box-specific material that leaked
  into a skill, and genuinely unused guidance. **Higher evidence bar than adding:**
  before cutting, prove it isn't a load-bearing *generic example*. (We keep
  cross-cutting examples inline on purpose — don't mistake one for single-target
  noise.) When unsure, generalise rather than delete.
- **Propose a new skill or tool.** Only for a capability gap that actually recurred
  (the agent hand-rolled the same workaround, or hit "there's no tool for this"). Bar
  for a *new skill*: it must be independently triggerable — the agent should route to
  it without already being in a parent skill's flow (the bar `hashcat`/`memforensics`
  cleared). Below that bar it's a runbook or a `roo` subcommand, not a skill. New
  reusable automation → a `scripts/roo.py` subcommand (stdlib, cross-platform), per
  CLAUDE.md → "Adding a skill".
- **Polish rough edges.** For each trip-up: was it doc-fixable? If yes, find the
  *smallest* change that prevents a repeat (often: move a warning earlier, fix a wrong
  flag, add a decision pointer at the fork where the agent guessed wrong). If no
  (model blip), log it and move on.

### 5. Present, approve, apply

1. Show the operator the changeset, grouped by skill and ranked by impact×confidence,
   regressions first. Keep each item to: evidence → proposed change → why it's generic.
2. The operator approves a subset. Apply only those, on a branch (`retro/<date>` or
   similar), as reviewable diffs. Don't auto-commit to `main`.
3. Write the per-engagement record to `recon-results/<target>/retro.md` (git-ignored —
   it may name specifics): what happened, the inventory, what was applied, what was
   deferred.
4. Update `docs/retro-log.md` (git-ignored / private to the checkout; keep it generic
   anyway): append the N=1 / deferred items so a future retro can confirm a pattern,
   and tick off anything this run resolved. This file is the loop's memory — step 1
   reads it back.

## Where each kind of lesson goes (routing)

- **Technique / methodology / footgun** → the skill or a runbook (the work above).
- **A box's specific facts** → `recon-results/`. Never a skill.
- **How *this operator* likes to work** (cadence, verbosity, what to ask vs assume,
  tooling preferences) → your file-based **memory** as a `feedback` entry, not a
  skill. Skills are the repo's shared doctrine; working-style is per-operator. If a
  preference looks universal, propose it as a skill edit *and* note it in memory.

## Anti-patterns (read before you edit)

- **Over-fitting to N=1.** One engagement is a single data point. Don't promote a
  fluke to doctrine — make it earn a change by recurring (that's what `retro-log.md`
  is for).
- **Enshrining box specifics.** "On this box the path was ESC1" is not a lesson; "force
  `-ldap-scheme ldap` because the default LDAPS resets on hardened DCs" is.
- **Bloat by accretion.** Not every lesson is a new paragraph. Prefer tightening
  existing text, fixing a flag, or extracting a runbook over growing the always-loaded
  skill. A skill that doubles in size each retro gets *worse*.
- **Editing the `description` carelessly.** It gates activation across every future
  run. Change it only with a clear reason and re-read it for trigger coverage.
- **Pruning a load-bearing example.** Generic illustrations that look box-specific are
  the easiest thing to delete by mistake. Generalise before you cut.
- **Self-justifying.** Don't defend the transcript's dead-ends. The operator's
  correction is the verdict.
- **Silent edits.** No write to a skill without the operator seeing the diff.
