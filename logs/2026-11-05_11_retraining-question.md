# Log 11: Question: what does retraining look like, and how do old and new models relate?

- **Date:** 2026-11-05
- **Query:** "brief question: in the future, what would re-training with newly found malware information look like? what would be the correlation between the new and the current model?"
- **Files changed:** none (a conceptual answer; an optional experiment is proposed in §4)

---

## 1. What "newly found malware information" really is

1. **Label delay.** EMBER labels come from AV consensus (`detection_ratio`), and AV engines catch up over days or weeks. A file first seen as "0/74, benign" can become "40/74, malicious" a month later. So retraining is mostly about **late-arriving and corrected labels**, not just new files. Corrected labels (benign → malicious) on files already in the training set matter as much as new rows.
2. **Not everything needs a retrain.** A specific newly confirmed hash goes onto a **hash blocklist** (O(1) lookup, effective immediately), or into a YARA rule (Day-2 stretch). Retraining is for **generalizing to the next variants** of a family the model hasn't seen, which a hash can't do.

## 2. Three ways to retrain a LightGBM model

### 2.1 Full retrain on a moving window (the default)
Vectorize the new weeks (`axi/dataset.py` is per-week and idempotent, so only new weeks cost time), then run the same pipeline:
- train = an expanding window (weeks 1..N) or a sliding one (the last K weeks), optionally with **time-decay sample weights** so recent weeks count more;
- val = the newest weeks, used for early stopping **and** new thresholds;
- a fixed **regression suite**: known goodware (System32, common installers) that must stay benign, plus known malware that must stay detected.

Costs and caveats:
- `train.lgb.bin` must be **rebuilt**. Bin boundaries are quantiles of the training data, so a new window gives new bins (134 s here).
- **Thresholds must be re-derived.** The score scale is model-specific: our T_high = 0.999917 means nothing for the next model. This is exactly why `axi_lgbm.json` binds thresholds to the model's sha256.
- Keep some old malware. Families resurface, and a sliding window that drops them can make the model forget. EMBER's "challenge" set contains evasive samples for that reason.

### 2.2 Warm start / continued boosting (`lgb.train(..., init_model=old)`)
LightGBM computes the old model's raw score as the starting point and fits **new trees to the residuals on the new data**:

  f_new(x) = f_old(x) + Σ new trees(x)    (in log-odds space)

- **Pros:** cheap (only the new trees), and naturally close to the old model.
- **Cons:** old trees are frozen, so wrong or outdated structure is never removed, only patched on top. The model grows every cycle (prediction latency grows linearly with tree count). After a few rounds you still need a full retrain.

### 2.3 Refit (`booster.refit(new_X, new_y)`)
Keep every tree's **split structure** and re-estimate only the **leaf values** on new data, blended by a `decay_rate`.
- This targets exactly the **calibration / threshold drift** we measured in log 10 §2 (the 0.1% threshold moved from 0.999917 to 0.999992) without changing which features the model looks at.
- It can't learn new patterns: a new packer that needs a new split isn't representable.

| | Full retrain | Warm start | Refit |
|---|---|---|---|
| Fixes ranking drift | yes | partially | no |
| Fixes calibration drift | yes | yes | yes |
| Cost | full | small | smallest |
| Similarity to old model | lowest | high (old model is a prefix) | highest (same partitions) |

Real pipelines usually combine them: frequent cheap updates (refit / warm start, threshold re-derivation), plus periodic full retrains.

## 3. How correlated are old and new models?

### 3.1 Where they agree, and where they don't
- **On the bulk, extremely correlated.** Both models learn the same dominant signals (packing entropy, import profiles, signatures). Easy malware and easy benign files get near-identical extreme scores either way. Even two full retrains on the **same** data with different seeds agree on most files, because the signal is strong.
- **At the tail, much less.** GBDT training is a sequence of greedy, discrete decisions (which split, which bagged rows, which 50% of features in `feature_fraction`). A small change in data or seed changes early splits, and everything downstream changes. Files near the decision boundary, the only ones whose verdict can change, are exactly where models disagree. (CP analogy: the argmax of a greedy algorithm is unstable under small perturbations of near-tied inputs.)

### 3.2 Why "correlation" is the wrong metric, and what to measure instead
A Spearman correlation of ~0.99+ over 120k files is dominated by the easy 99%, the same flaw as ROC-AUC in log 10 §2. What operations care about is **prediction churn** at the operating thresholds:
- **verdict agreement:** the fraction of files whose zone (pass / sandbox / quarantine) changes;
- **FP churn:** of the new model's false positives, how many are **new** (benign files the old model passed). The new model may have the *same* FPR as the old one but on *different* files. To a user that looks like "software that worked yesterday is quarantined today", the most visible failure an EDR has.
- **fixed vs. new misses:** malware the new model catches that the old one missed, and the reverse ("regressions").

### 3.3 Reducing churn
- Warm start or refit: the new model contains the old one by construction.
- Same seed, same hyperparameters, and an expanding (not sliding) window, so most training data is shared.
- **Anchoring / distillation:** add a training term that keeps new scores close to old scores on benign files. A "stable" model trades a little accuracy for less churn.
- **Shadow mode:** run the new model beside the old one on live traffic, log both verdicts, and promote only if the churn and regression-suite numbers are acceptable. Our event DB should store `model_sha256` with each verdict (Day 2), so past dashboard entries stay explainable after a model swap.

## 4. Optional experiment (not run; ~45 min CPU)
We can **measure** this instead of arguing it, without touching test:
1. Train model A on weeks 1–6 and model B on weeks 1–8, same params, both early-stopped on val.
2. On val, compare Spearman correlation, zone agreement, FP overlap (|FP_A ∩ FP_B| / |FP_B|), and TPR gained/lost.
3. Bonus: warm-start A on weeks 7–8 (`init_model`) and compare its churn with B's.

That simulates "two weeks of new data arrived" and gives real numbers for §3.
