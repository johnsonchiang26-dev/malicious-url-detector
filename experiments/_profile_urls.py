# -*- coding: utf-8 -*-
"""一次性剖析 URL 結構，輸出 JSON 供後續決策。不依賴外部 NLP 套件。"""
import pandas as pd, numpy as np, re, math, json, collections
from urllib.parse import urlsplit

df = pd.read_csv("./data/malicious_phish.csv")
df['url'] = df['url'].astype(str)

class _P:  # urlsplit 失敗時的退化容器
    def __init__(s, u):
        s.scheme=''; s.hostname=u.split('/')[0]; s.path='/'+'/'.join(u.split('/')[1:])
        s.query=''; s.fragment=''; s.port=None

def split_url(u):
    # 補上 scheme 讓 urlsplit 能正確切 host/path
    has_scheme = bool(re.match(r'^[a-zA-Z][a-zA-Z0-9+.-]*://', u))
    try:
        parsed = urlsplit(u if has_scheme else 'http://' + u)
        _ = parsed.hostname, parsed.port  # 觸發 IPv6 解析錯誤
    except ValueError:
        parsed = _P(re.sub(r'^[a-zA-Z][a-zA-Z0-9+.-]*://', '', u))
    return has_scheme, parsed

def shannon_entropy(s):
    if not s: return 0.0
    cnt = collections.Counter(s)
    n = len(s)
    return -sum((c/n)*math.log2(c/n) for c in cnt.values())

DELIMS = re.compile(r'[^a-zA-Z0-9]')
report = {}

# 1. 每類抽樣
samples = {}
for t in df['type'].unique():
    samples[t] = df[df['type']==t]['url'].head(6).tolist()
report['samples'] = samples

# 為了速度，對大資料抽樣統計（分層）
N = 60000
parts = []
for t, g in df.groupby('type'):
    parts.append(g.sample(min(len(g), N//4), random_state=1))
sub = pd.concat(parts).reset_index(drop=True)

rows = []
for u, t in zip(sub['url'], sub['type']):
    has_scheme, p = split_url(u)
    host = p.hostname or ''
    path = p.path or ''
    query = p.query or ''
    frag = p.fragment or ''
    port = p.port
    labels = host.split('.') if host else []
    tld = labels[-1] if labels else ''
    is_ip = bool(re.match(r'^\d{1,3}(\.\d{1,3}){3}$', host))
    toks = [x for x in DELIMS.split(u) if x]
    alpha_toks = [x for x in toks if x.isalpha()]
    rows.append(dict(
        type=t, has_scheme=has_scheme, scheme=p.scheme,
        url_len=len(u), n_dots=u.count('.'), n_slash=u.count('/'),
        n_hyphen=u.count('-'), n_under=u.count('_'), n_qmark=u.count('?'),
        n_eq=u.count('='), n_amp=u.count('&'), n_pct=u.count('%'),
        n_at=u.count('@'), n_tilde=u.count('~'),
        has_path=len(path.strip('/'))>0, has_query=len(query)>0, has_frag=len(frag)>0,
        is_ip=is_ip, has_port=port is not None,
        n_subdomain_labels=len(labels), tld=tld.lower(),
        n_tokens=len(toks),
        max_tok_len=max((len(x) for x in toks), default=0),
        mean_tok_len=float(np.mean([len(x) for x in toks])) if toks else 0,
        n_alpha_tokens=len(alpha_toks),
        url_entropy=shannon_entropy(u.lower()),
        host_entropy=shannon_entropy(host.lower()),
        has_hex_long=bool(re.search(r'[0-9a-f]{16,}', u.lower())),
        has_pct_encoding=bool(re.search(r'%[0-9a-fA-F]{2}', u)),
        digit_ratio=sum(c.isdigit() for c in u)/max(len(u),1),
    ))
prof = pd.DataFrame(rows)

def by_type(col, agg='mean'):
    g = prof.groupby('type')[col]
    return {k: round(float(v),3) for k,v in getattr(g, agg)().items()}

report['scheme_rate'] = by_type('has_scheme')
report['scheme_values'] = {k:int(v) for k,v in prof['scheme'].value_counts().head(8).items()}
report['has_path_rate'] = by_type('has_path')
report['has_query_rate'] = by_type('has_query')
report['has_frag_rate'] = by_type('has_frag')
report['is_ip_rate'] = by_type('is_ip')
report['has_port_rate'] = by_type('has_port')
report['has_pct_encoding_rate'] = by_type('has_pct_encoding')
report['has_hex_long_rate'] = by_type('has_hex_long')
report['url_len_mean'] = by_type('url_len')
report['url_len_p95'] = {k: round(float(prof[prof.type==k]['url_len'].quantile(0.95)),1) for k in prof.type.unique()}
report['n_tokens_mean'] = by_type('n_tokens')
report['max_tok_len_mean'] = by_type('max_tok_len')
report['max_tok_len_p95'] = {k: round(float(prof[prof.type==k]['max_tok_len'].quantile(0.95)),1) for k in prof.type.unique()}
report['host_entropy_mean'] = by_type('host_entropy')
report['url_entropy_mean'] = by_type('url_entropy')
report['digit_ratio_mean'] = by_type('digit_ratio')
report['n_subdomain_labels_mean'] = by_type('n_subdomain_labels')

# 分隔符總頻率（每 URL 平均）
report['delim_per_url'] = {c: round(float(prof[f'n_{c}'].mean()),3) for c in
    ['dots','slash','hyphen','under','qmark','eq','amp','pct','at','tilde']}

# TLD 分佈（整體 + 各類前幾名）
report['top_tld_overall'] = {k:int(v) for k,v in prof['tld'].value_counts().head(20).items()}
report['top_tld_by_type'] = {}
for t in prof['type'].unique():
    report['top_tld_by_type'][t] = {k:int(v) for k,v in prof[prof.type==t]['tld'].value_counts().head(8).items()}

# 需要 subword 切分的「黏在一起」長 token 範例
glued = []
for u in sub['url'].sample(min(4000,len(sub)), random_state=2):
    for tok in DELIMS.split(u):
        if tok.isalpha() and len(tok) >= 16:
            glued.append(tok)
report['glued_token_examples'] = list(dict.fromkeys(glued))[:25]

# 高 entropy / 疑似亂碼 token 範例（每類）
report['high_entropy_token_examples'] = {}
for t in prof['type'].unique():
    ex = []
    for u in sub[sub.type==t]['url'].sample(min(3000,(sub.type==t).sum()), random_state=3):
        for tok in DELIMS.split(u):
            if len(tok) >= 12 and shannon_entropy(tok) >= 3.5 and any(c.isdigit() for c in tok) and any(c.isalpha() for c in tok):
                ex.append(tok)
    report['high_entropy_token_examples'][t] = list(dict.fromkeys(ex))[:12]

print(json.dumps(report, ensure_ascii=False, indent=1))
