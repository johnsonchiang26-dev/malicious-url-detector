# -*- coding: utf-8 -*-
"""在真實資料分層抽樣上驗證管線：速度、詞彙表大小、各類異常率。"""
import pandas as pd, collections, time
from url_tokenizer import split_structural, subword_segment, clean_and_tag, url_labels, to_text

df = pd.read_csv("./data/malicious_phish.csv")
df['url'] = df['url'].astype(str)
parts = [g.sample(min(len(g), 5000), random_state=7) for _, g in df.groupby('type')]
sub = pd.concat(parts).reset_index(drop=True)

t0 = time.time()
vocab1, vocab2, vocab3 = set(), set(), set()
anom_by_type = collections.defaultdict(collections.Counter)
n_urls_with_anom = collections.Counter()
suffix_by_type = collections.defaultdict(collections.Counter)
ext_by_type = collections.defaultdict(collections.Counter)

for url, typ in zip(sub['url'], sub['type']):
    s1 = split_structural(url)
    s2 = subword_segment(s1)
    s3, anom = clean_and_tag(s1)
    vocab1.update(t for t, _ in s1)
    vocab2.update(t for t, _ in s2)
    vocab3.update(t for t, _ in s3)
    lab = url_labels(url)
    if lab['suffix']: suffix_by_type[typ][lab['suffix']] += 1
    if lab['file_ext']: ext_by_type[typ][lab['file_ext'].lower()] += 1
    if anom:
        n_urls_with_anom[typ] += 1
        for k, v in anom.items():
            anom_by_type[typ][k] += v

dt = time.time() - t0
n = len(sub)
print(f"處理 {n} 筆，耗時 {dt:.1f}s  ({n/dt:,.0f} URL/秒)  → 全量 65 萬約 {651191/(n/dt):.0f}s")
print()
print(f"詞彙表大小 (unique token)：")
print(f"  Step1 原始符號切詞 : {len(vocab1):,}")
print(f"  Step2 +子詞切分     : {len(vocab2):,}   ({'+' if len(vocab2)>len(vocab1) else ''}{len(vocab2)-len(vocab1):,} vs step1)")
print(f"  Step3 異常標籤化後  : {len(vocab3):,}   ({len(vocab3)-len(vocab1):,} vs step1，雜訊大幅收斂)")
print()
print("含異常字段的 URL 比例（每類 5000 筆）：")
for t in ['benign','phishing','malware','defacement']:
    print(f"  {t:11s}: {n_urls_with_anom[t]/5000:6.1%}   異常類型 {dict(anom_by_type[t].most_common())}")
print()
print("TLD 後綴 Top5（驗證 PSL 多段後綴）：")
for t in ['benign','phishing','malware','defacement']:
    print(f"  {t:11s}: {dict(suffix_by_type[t].most_common(5))}")
print()
print("副檔名 Top5：")
for t in ['benign','phishing','malware','defacement']:
    print(f"  {t:11s}: {dict(ext_by_type[t].most_common(5))}")
print()
print("to_text() 範例（可直接丟 TF-IDF / HashingVectorizer）：")
for url in sub['url'].head(3):
    print(f"  {url[:60]:60s} -> {to_text(url, step=3)[:80]}")
