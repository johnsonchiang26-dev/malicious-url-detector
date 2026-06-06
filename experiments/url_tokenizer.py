# -*- coding: utf-8 -*-
"""
URL 三步驟斷詞 + 標籤管線 (for Malicious URL Detection)
=====================================================
設計理念：URL 不是自然語言，所以不用中文/英文的「語意斷詞模型」當主力，
而是「結構解析 → 子詞切分 → 異常字段標籤化」三層處理。

Step 1  依符號斷詞 + 結構解析   split_structural()
Step 2  拿掉符號後做子詞切分     subword_segment()   (wordninja)
Step 3  排除/標籤化異常字段後再切 clean_and_tag()
標籤     TLD後綴 / 元件角色 / 副檔名 / 異常類型

依賴：tldextract  wordninja  (純 Python，輕量)
    pip install tldextract wordninja
"""
import re, math, base64, collections
from urllib.parse import urlsplit, parse_qsl
import tldextract
import wordninja

# tldextract 預設會連網更新 Public Suffix List；用內建快照避免每次連網
_EXTRACT = tldextract.TLDExtract(suffix_list_urls=())  # 用套件內建的 PSL 快照

# ---------------------------------------------------------------- 工具函式
def shannon_entropy(s: str) -> float:
    """字元層級的 Shannon 熵：亂碼/隨機字串會偏高，真詞偏低。"""
    if not s:
        return 0.0
    n = len(s)
    cnt = collections.Counter(s)
    return -sum((c / n) * math.log2(c / n) for c in cnt.values())

HEX_RE      = re.compile(r'^[0-9a-fA-F]+$')
B64_RE      = re.compile(r'^[A-Za-z0-9+/_-]+={0,2}$')
_OCTET      = r'(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)'   # 0-255，避免把 999.999.. 當 IP
IPV4_RE     = re.compile(rf'^{_OCTET}(\.{_OCTET}){{3}}$')
PCT_RE      = re.compile(r'%[0-9a-fA-F]{2}')
DELIMS_RE   = re.compile(r'[^A-Za-z0-9]+')          # Step1 斷詞用：任何非英數字元
DIGIT_RUN   = re.compile(r'\d{5,}')

def is_hex_hash(tok: str) -> bool:
    """32=MD5, 40=SHA1, 64=SHA256；或夠長的純 hex。"""
    return bool(HEX_RE.match(tok)) and (len(tok) in (32, 40, 64) or len(tok) >= 24)

def is_base64ish(tok: str) -> bool:
    """偵測 base64 編碼字串（資料裡常見：把整段 http://... 用 base64 藏在 link= 參數）。"""
    if len(tok) < 16 or not B64_RE.match(tok):
        return False
    if tok.lower().startswith(('ahr0c', 'ahr0', 'ahr')):   # base64("http") = aHR0c...
        return True
    has_u, has_l, has_d = any(c.isupper() for c in tok), any(c.islower() for c in tok), any(c.isdigit() for c in tok)
    if not (has_u and has_l):
        return False
    try:  # 能解碼成大多可列印 ASCII → 視為 base64
        dec = base64.b64decode(tok + '=' * (-len(tok) % 4), validate=False)
        printable = sum(32 <= b < 127 for b in dec)
        return len(dec) > 0 and printable / len(dec) > 0.85
    except Exception:
        return False

def is_random(tok: str) -> bool:
    """高熵、英數混雜、又不是字典詞 → 疑似隨機 token / DGA / session id。"""
    if len(tok) < 10:
        return False
    has_d, has_a = any(c.isdigit() for c in tok), any(c.isalpha() for c in tok)
    if not (has_d and has_a):
        return False
    if shannon_entropy(tok) < 3.3:
        return False
    # wordninja 若能把它切成都是短碎片，代表不是真詞 → 更像隨機
    parts = wordninja.split(tok)
    long_parts = [p for p in parts if len(p) >= 4]
    return len(long_parts) <= 1

_VOWELS = set('aeiou')
def is_random_alpha(tok: str) -> bool:
    """純字母但母音比例異常低 + 高熵 + 切不出長詞 → 疑似 DGA/亂碼子網域。可調。"""
    if not tok.isalpha() or len(tok) < 12:
        return False
    if sum(c in _VOWELS for c in tok.lower()) / len(tok) >= 0.26:
        return False
    if shannon_entropy(tok) < 3.2:
        return False
    return max((len(p) for p in wordninja.split(tok)), default=0) <= 4

def classify_anomaly(tok: str):
    """回傳異常標籤或 None。順序：IP→HASH→B64→NUM→RANDOM。"""
    if IPV4_RE.match(tok):
        return '<IP>'
    if is_hex_hash(tok):
        return '<HASH>'
    if is_base64ish(tok):
        return '<B64>'
    if DIGIT_RUN.search(tok) and not tok.isalpha():
        return '<NUM>'
    if is_random(tok) or is_random_alpha(tok):
        return '<RAND>'
    return None

_HEXPAIR_RE = re.compile(r'^[0-9A-Fa-f]{1,2}$')
def _collapse_pct(tokens):
    """把 %XX 百分比編碼被符號切碎後留下的連續 hex pair (>=3 個) 收斂成單一 <PCT>。"""
    out, i, n = [], 0, len(tokens)
    while i < n:
        j = i
        while j < n and tokens[j][1] == tokens[i][1] and _HEXPAIR_RE.match(tokens[j][0]):
            j += 1
        if j - i >= 3:                       # 連續 3+ 個 hex pair → 視為 %編碼殘骸
            out.append(('<PCT>', tokens[i][1]))
            i = j
        else:
            out.append(tokens[i]); i += 1
    return out

# ---------------------------------------------------------------- 解析
def _safe_split(url: str):
    has_scheme = bool(re.match(r'^[a-zA-Z][a-zA-Z0-9+.-]*://', url))
    work = url if has_scheme else 'http://' + url
    try:
        p = urlsplit(work)
        _ = p.hostname, p.port
        return has_scheme, p
    except ValueError:                         # 例如壞掉的 IPv6
        rest = re.sub(r'^[a-zA-Z][a-zA-Z0-9+.-]*://', '', url)
        host = rest.split('/')[0]
        class _P: pass
        p = _P(); p.scheme=''; p.hostname=host; p.port=None
        p.path='/'+'/'.join(rest.split('/')[1:]); p.query=''; p.fragment=''
        return has_scheme, p

# ================================================================ STEP 1
def split_structural(url: str):
    """
    Step 1：依符號斷詞，但「保留結構角色」。
    回傳 [(token, role), ...]，role ∈
      SCHEME SUBDOMAIN DOMAIN SUFFIX PORT PATH FILE_EXT QUERY_KEY QUERY_VAL FRAGMENT
    """
    has_scheme, p = _safe_split(url)
    out = []
    if has_scheme and p.scheme:
        out.append((p.scheme, 'SCHEME'))

    host = p.hostname or ''
    if IPV4_RE.match(host):
        out.append((host, 'DOMAIN'))           # IP 當作 domain，另由標籤標 has_ip
    else:
        ext = _EXTRACT(host)
        for s in filter(None, ext.subdomain.split('.')):
            out.append((s, 'SUBDOMAIN'))
        for s in filter(None, ext.domain.split('.')):
            out.append((s, 'DOMAIN'))
        for s in filter(None, ext.suffix.split('.')):
            out.append((s, 'SUFFIX'))           # 後綴：co, uk / com, br 會逐段拆
    if p.port:
        out.append((str(p.port), 'PORT'))

    segs = [s for s in (p.path or '').split('/') if s]
    for i, seg in enumerate(segs):
        toks = [t for t in DELIMS_RE.split(seg) if t]
        # 最後一段若有副檔名，最後一個 token 標 FILE_EXT
        if i == len(segs) - 1 and '.' in seg:
            for t in toks[:-1]:
                out.append((t, 'PATH'))
            if toks:
                out.append((toks[-1], 'FILE_EXT'))
        else:
            for t in toks:
                out.append((t, 'PATH'))

    for k, v in parse_qsl(p.query or '', keep_blank_values=True):
        for t in (x for x in DELIMS_RE.split(k) if x):
            out.append((t, 'QUERY_KEY'))
        for t in (x for x in DELIMS_RE.split(v) if x):
            out.append((t, 'QUERY_VAL'))

    for t in (x for x in DELIMS_RE.split(p.fragment or '') if x):
        out.append((t, 'FRAGMENT'))
    return out

# ================================================================ STEP 2
def subword_segment(tokens):
    """
    Step 2：拿掉符號後，把黏在一起的英文/字母 token 用 wordninja 切成子詞。
    e.g. 'thefreedictionary' -> ['the','free','dictionary']
    數字 / 過短 token 原樣保留。
    """
    out = []
    for tok, role in tokens:
        if tok.isalpha() and len(tok) >= 8:
            parts = wordninja.split(tok)
            out.extend((p, role) for p in parts) if parts else out.append((tok, role))
        else:
            out.append((tok, role))
    return out

# ================================================================ STEP 3
def clean_and_tag(tokens):
    """
    Step 3：先把異常字段換成佔位標籤 (<IP> <HASH> <B64> <NUM> <RAND>)，
    其餘「乾淨」token 再做子詞切分。回傳 (tokens, anomaly_counter)。
    """
    out, anom = [], collections.Counter()
    tokens = _collapse_pct(tokens)
    for tok, role in tokens:
        if tok == '<PCT>':
            out.append((tok, role)); anom['<PCT>'] += 1; continue
        tag = classify_anomaly(tok)
        if tag:
            out.append((tag, role))
            anom[tag] += 1
        elif tok.isalpha() and len(tok) >= 8:
            for p in (wordninja.split(tok) or [tok]):
                out.append((p, role))
        else:
            out.append((tok, role))
    return out, anom

# ================================================================ 標籤
def url_labels(url: str) -> dict:
    """產生 URL 層級的標籤（含 TLD 後綴、副檔名、結構特徵），可直接當分類特徵。"""
    has_scheme, p = _safe_split(url)
    host = p.hostname or ''
    is_ip = bool(IPV4_RE.match(host))
    ext = _EXTRACT(host) if not is_ip else None
    s1 = split_structural(url)
    _, anom = clean_and_tag(s1)
    file_ext = next((t for t, r in s1 if r == 'FILE_EXT'), None)
    return {
        'scheme': p.scheme if has_scheme else None,
        'subdomain': (ext.subdomain or None) if ext else None,
        'domain': (ext.domain or None) if ext else host,
        'suffix': (ext.suffix or None) if ext else None,     # ← 你要的「網址最後後綴」(PSL 正確處理 .com.br/.co.za)
        'file_ext': file_ext,
        'has_ip': is_ip,
        'has_port': p.port is not None,
        'has_pct_encoding': bool(PCT_RE.search(url)),
        'n_path_seg': len([s for s in (p.path or '').split('/') if s]),
        'n_query': len(parse_qsl(p.query or '')),
        'url_len': len(url),
        'url_entropy': round(shannon_entropy(url.lower()), 3),
        'anomalies': dict(anom),                              # {'<HASH>':1, ...}
    }

def analyze(url: str) -> dict:
    """一次跑完三步驟 + 標籤，方便檢視/比較。"""
    s1 = split_structural(url)
    s2 = subword_segment(s1)
    s3, _ = clean_and_tag(s1)
    return {
        'url': url,
        'step1_symbol_split': s1,
        'step2_subword': s2,
        'step3_clean_tagged': s3,
        'labels': url_labels(url),
    }

# 給下游模型 (TF-IDF / HashingVectorizer / HF tokenizer) 的「文字化」輸出
def to_text(url: str, step: int = 3) -> str:
    s1 = split_structural(url)
    toks = {1: s1, 2: subword_segment(s1), 3: clean_and_tag(s1)[0]}[step]
    return ' '.join(t for t, _ in toks)


if __name__ == '__main__':
    import json
    demo = [
        "br-icloud.com.br",                                                   # phishing, 多段後綴
        "signin.eby.de.zukruygxctzmmqi.civpro.co.za",                         # phishing, .co.za + 亂碼子網域
        "http://www.thefreedictionary.com/disenpene",                        # 黏字
        "http://adventure-nicaragua.net/index.php?option=com_mailto&link=aHR0cDovL2FkdmVudHVyZS1uaWNhcmFndWE",  # base64
        "http://www.824555.com/app/member/SportOption.php?uid=guest&langx=gb",
        "http://9779.info/%E5%84%BF%E7%AB%A5%E7%AB%8B%E4%BD%93/",             # %編碼 CJK
        "http://192.168.1.10:8080/login/acc1c7d702392887b8e93f7c95f3671c.php", # IP+port+MD5
    ]
    for u in demo:
        print('=' * 90)
        a = analyze(u)
        print('URL  :', u)
        print('STEP1:', a['step1_symbol_split'])
        print('STEP2:', [t for t, _ in a['step2_subword']])
        print('STEP3:', [t for t, _ in a['step3_clean_tagged']])
        print('LABEL:', json.dumps(a['labels'], ensure_ascii=False))
