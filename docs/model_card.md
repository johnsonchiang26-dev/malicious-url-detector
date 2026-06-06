# Model Card — Malicious URL Classifier

## Overview

| | |
|---|---|
| **Task** | Multi-class URL classification: `benign / phishing / malware / defacement` |
| **Input** | A raw URL string (no DNS lookup, no page fetch) |
| **Model** | TF-IDF (word 1–2gram + character 3–5gram) + 21 numeric features → `LinearSVC` (`class_weight="balanced"`, C=1.0) |
| **Feature space** | ~350,000 dimensions |
| **Training data** | Public Malicious URLs dataset (ISCX-URL-2016 + PhishTank + PhishStorm + malware-domain blacklists), 651,191 URLs |
| **Split** | 80 / 20 stratified, `random_state=42` |
| **Compute** | CPU only; full pipeline featurization ≈ 4 min, model training ≈ 2.5 min |
| **Artifact** | `models/url_classifier.joblib` (clf + both vectorizers + scaler + feature schema) |

## Intended use

Real-time, inline URL triage at the point a message/URL is received — e.g. flag URLs inside SMS/email before
any network call. Suited to high-throughput filtering where a fast, interpretable first-pass classifier is
needed. **Not** a standalone verdict engine: pair with reputation feeds / sandboxing for confirmed blocking.

## Features

**Text (TF-IDF):** word 1–2grams and character 3–5grams over `token_str` — the role-tagged token stream from
the pipeline, which **excludes the URL scheme** (see Limitations → scheme leak).

**Numeric (21):**
- *9 base* — Shannon entropy, anomaly-field count, `has_cjk`, `has_ip_host`, digit count, special-char count,
  token count, encoded flag, URL length.
- *12 engineered phishing clues (`extra_features()`)* — `host_len`, `host_dots`, `host_digits`,
  `host_hyphens`, `has_at`, `path_depth`, `sus_tld`, `lure_hits` (login/secure/paypal/bank/verify… on the
  **decoded** URL), `n_params`, `is_ip_host`, `url_len2`, `special_ratio`.

## Evaluation

Two protocols are reported because they answer different questions.

### A. Held-out test set — 130,239 URLs, real (imbalanced) distribution

| Class | Precision | Recall | F1 |
|---|:---:|:---:|:---:|
| benign | 0.968 | 0.958 | 0.963 |
| defacement | 0.995 | 0.999 | 0.997 |
| malware | 0.988 | 0.967 | 0.977 |
| phishing | 0.815 | 0.857 | 0.835 |

**Accuracy 0.950 · Macro-F1 0.943 · Weighted-F1 0.951.**
Engineered features lifted phishing-F1 from 0.816 → 0.835; dominant residual error is benign↔phishing.

### B. Head-to-head vs URLBERT — balanced 8,000-URL sample (identical rows for both)

| Model | Accuracy | Macro-F1 | Phishing-F1 |
|---|:---:|:---:|:---:|
| This model (honest held-out) | 0.943 | 0.943 | 0.889 |
| `CrabInHoney/urlbert-tiny-v4-malicious-url-classifier` | 0.974 | 0.974 | 0.951 |

> Per-class F1 (phishing) is higher on the balanced sample (0.889) than on the imbalanced full set (0.835)
> because precision rises when benign is no longer the majority — a reminder that the metric depends on the
> evaluation distribution.

## Limitations & ethical considerations

- **URLBERT comparison is not apples-to-apples.** The pretrained model predicts these exact 4 classes and was
  almost certainly trained on this same public dataset, including rows in our test split → **data leakage**
  inflates its score. Our model is trained only on the 80% split and is honestly held out.
- **Source/collection bias.** `defacement` reaches ~0.997 F1, which likely reflects how that subset was
  collected (single source, near-identical structure) rather than genuine separability. Real-world
  generalization is best estimated by the **phishing** number, the hardest and most operationally important class.
- **String-only.** No DNS, WHOIS, page content, or reputation history; truncation/obfuscation an adversary
  controls can degrade it. Best used as a fast first stage, not a sole gate.
- **Translation quality.** `opus-mt-mul-en` translations are approximate and used as features, not ground truth.
- **Dataset age.** ISCX-2016-era URLs; phishing TLD/keyword fashions drift, so periodic retraining is expected.

## Reproduce

Run `tagging.ipynb` top to bottom (§⑨b full evaluation, §⑨c engineered-feature model, §⑩ URLBERT comparison),
or load `models/url_classifier.joblib`.
