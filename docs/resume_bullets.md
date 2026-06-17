# Resume & Portfolio Material — Malicious URL Detection

All numbers below are the **honest held-out** results from this repo. Use them as-is.

> Quick fact-check before you paste anything:
> - **0.950 accuracy / 0.943 macro-F1** → full imbalanced test set (130,239 URLs).
> - **Phishing-F1 = 0.835** on that full test set; **= 0.889** only on the balanced 8K head-to-head sample.
> - **URLBERT 0.974** is *not* a fair win — likely trained on this dataset (leakage). Always present it with that caveat.

---

## 1. Résumé bullet points

### English (pick 2–3)

- Built a **real-time, multi-class malicious-URL classifier** (benign / phishing / malware / defacement) on
  **651K URLs** using **pure string analysis** — no DNS lookup or page fetch — combining TF-IDF (word + character
  n-grams) with 21 numeric features into a `LinearSVC`; achieved **0.95 accuracy / 0.94 macro-F1** on a 130K
  held-out set, CPU-only.
- **Engineered 12 phishing-specific features** (suspicious/free TLDs, brand-lure keywords on *decoded* URLs,
  host structure & entropy, `@`-obfuscation, IP-as-host), raising the hardest class — **phishing F1 from 0.816
  to 0.835**.
- Benchmarked against a pretrained **URLBERT** transformer and **diagnosed its higher score (0.974) as
  data-leakage-inflated** (trained on the same public corpus, including our test rows); reported honest hold-out
  metrics instead — demonstrating evaluation rigor over headline numbers.
- Designed a **robust multilingual ingestion pipeline** — multi-encoding percent-decoding (UTF-8 / GBK / Big5 /
  Shift-JIS) + Punycode, hash/Base64 anomaly filtering, and many-language→English translation — and surfaced
  that decoded CJK content concentrates in **malware (12.7% vs ~0% in other classes)**.

### 中文（擇 2–3 條）

- 以**純字串分析**（免 DNS、免抓網頁）建構**即時惡意 URL 多分類器**（benign / phishing / malware / defacement），
  資料 **65 萬筆**；結合 TF-IDF（詞＋字元 n-gram）與 21 個數值特徵訓練 `LinearSVC`，於 13 萬筆 held-out 測試集達
  **0.95 準確率 / 0.94 macro-F1**，純 CPU 即可。
- **自行設計 12 個釣魚專屬特徵**（可疑/免費 TLD、解碼後 URL 的品牌誘餌字、主機結構與熵、`@` 混淆、IP 當主機），
  將最難的 **phishing F1 由 0.816 提升至 0.835**。
- 與預訓練 **URLBERT** 對照，**判讀其較高分數（0.974）實為資料洩漏所致**（以同一公開資料含測試列訓練），改採誠實
  held-out 評估——展現對評估嚴謹度的重視，而非追逐帳面數字。
- 設計**健壯的多語言前處理 pipeline**：多編碼百分號解碼（UTF-8 / GBK / Big5 / Shift-JIS）＋Punycode、雜湊/Base64
  亂碼過濾、多語言→英文翻譯；並發現解碼後中文內容高度集中於 **malware（12.7% vs 其他類別約 0%）**。

### One-line "pipeline" bullet (links both projects)

> Built an end-to-end **messaging-threat pipeline**: a BERT SMS spam filter (`sms-spam-detector`) feeding a
> real-time URL threat classifier (`malicious-url-detector`) — mirroring mobile-security + web-reputation
> product surfaces.

---

## 2. Portfolio description (中文，約 200 字)

> **Malicious URL Detection — 即時惡意網址分類器**
>
> 這個專案從「網址字串本身」判斷其威脅類型（正常 / 釣魚 / 惡意軟體 / 網頁竄改），不需 DNS 查詢或抓取網頁，因此能在
> 訊息抵達的瞬間即時過濾。我設計了一條完整 pipeline：先做多編碼解碼（UTF-8 / GBK / Big5，能還原被編碼隱藏的中文）、
> 結構解析與公共後綴清單取出 TLD、過濾隨機雜湊雜訊，再對主機與路徑斷詞、把非英文字段翻成英文。在 65 萬筆資料上，以
> TF-IDF 加上我自己設計的 12 個釣魚線索特徵訓練 LinearSVC，於 13 萬筆未見過的測試集達 0.95 準確率、0.94 macro-F1，
> 並把最難的釣魚類別 F1 從 0.816 推到 0.835。我也跟預訓練的 URLBERT 對照，指出它看似更高的 0.974 其實受資料洩漏影響——
> 比起追求帳面數字，能判斷「哪個分數可信」才是這個專案真正的收穫。

---

## 3. Interview talking points (5 Q&A)

**Q1. Why classic ML (TF-IDF + LinearSVC) instead of a deep model from the start?**
A URL has no sentence grammar, so a word-level language model is a poor fit; character/structural patterns
carry the signal. A sparse linear model over char + word n-grams is fast (CPU, real-time), interpretable
(I can read the weights), and turned out to be only ~3 points behind a transformer — most of which is leakage.
For an inline filter, that trade-off is the right call; the deep model is the next stage, not the baseline.

**Q2. How did you conclude URLBERT's higher score was data leakage, not genuine superiority?**
It predicts the exact same 4 labels as this public dataset, and its model card points back to the same family
of sources — so its training set almost certainly overlaps our test rows. I evaluated both models on the
*same* held-out sample for fairness, but flagged that only my model is truly held out. The honest move is to
report my 0.943 and treat URLBERT's 0.974 as an upper bound contaminated by leakage — not to claim the higher
number.

**Q3. Phishing is your weakest class — why, and what did you do about it?**
Phishing URLs are *designed* to look benign, so they sit closest to the benign cluster (the confusion matrix
confirms benign↔phishing is the main error). I engineered 12 features around how phishing actually disguises
itself — suspicious/free TLDs, hyphen/digit-stuffed hosts, brand-lure keywords on the **decoded** string,
`@`-obfuscation, IP-as-host — which lifted phishing-F1 from 0.816 to 0.835. Next levers: per-class threshold
tuning, oversampling, and a phishing-focused second-stage model.

**Q4. How do the two projects fit together, and why does it matter operationally?**
`SMS → BERT spam filter → extract URL → URL threat classifier`. In my day job I run the ETL/alerting behind
94M+ SMS records, where phishing texts carry malicious links. The SMS model catches the *message*; the URL
model classifies the *payload* — two complementary detectors. This is exactly the split between a
mobile/SMS-security product and a web-reputation/URL-filtering product.

**Q5. What would it take to ship this into a product like Trend Micro's Web Reputation Service?**
(1) Latency/throughput: it's already CPU-fast, but I'd cache vectorizers, batch, and benchmark p99.
(2) Drift: phishing TLD/keyword fashions change, so I'd add monitoring on feature distributions and
prediction mix, with scheduled retraining. (3) Fairness of eval: build a *temporally* held-out test set
(train on older, test on newer) to estimate true generalization, avoiding the leakage I flagged with URLBERT.
(4) Defense-in-depth: feed scores into a reputation/sandbox ensemble rather than blocking on the string model
alone. (5) Feedback loop: capture analyst verdicts to grow labeled data over time.

---

## 4. Skills demonstrated (for the skills section)

`Python` · `scikit-learn` · `feature engineering` · `NLP / tokenization` · `HuggingFace Transformers` ·
`model evaluation & error analysis` · `data-leakage detection` · `multilingual text processing` ·
`security / threat classification`
