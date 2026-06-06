# Data

CSV files in this folder are **git-ignored** (too large to version, and the raw set is a redistributed
public dataset). Obtain / regenerate them as follows.

## 1. Raw dataset — `malicious_phish.csv`

Public **Malicious URLs dataset** (built from ISCX-URL-2016, PhishTank, PhishStorm, and malware-domain
blacklists). 651,191 rows, two columns: `url`, `type`.

| `type` | count |
|---|---:|
| benign | 428,103 |
| defacement | 96,457 |
| phishing | 94,111 |
| malware | 32,520 |

Download from Kaggle (search "Malicious URLs dataset") and place it here as `data/malicious_phish.csv`.

## 2. Feature table — `url_features.csv`

Generated from the raw set by the pipeline (≈4 minutes, CPU):

```python
import pandas as pd, url_features as uf
df = pd.read_csv("data/malicious_phish.csv")
feats = uf.featurize_dataframe(df, extra=True)   # adds tokens + numeric + 12 phishing features
feats.to_csv("data/url_features.csv", index=False)
```
