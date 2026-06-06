"""
URL 斷詞 / 標籤 示範 pipeline（純標準庫版，可直接跑）
對應你描述的三個步驟 + 後綴(TLD/副檔名)擷取。

進階版（步驟2英文斷字、步驟3中文）需要：
    pip install tldextract wordninja wordsegment jieba
程式碼裡用 try/except 自動偵測，有裝就用更好的版本。
"""
import re
import math
from urllib.parse import urlparse, unquote
from collections import Counter

# ---- 可選套件：有裝就升級，沒裝就用 fallback ----
try:
    import tldextract           # 正確的公共後綴清單(PSL)，能處理 .com.br / .co.uk
    _HAS_TLDEXTRACT = True
except ImportError:
    _HAS_TLDEXTRACT = False

try:
    import wordninja            # 把 "marketingbyinternet" 切成 marketing/by/internet
    _HAS_WORDNINJA = True
except ImportError:
    _HAS_WORDNINJA = False


# ========== 工具函式 ==========
def shannon_entropy(s: str) -> float:
    """字串的夏農熵；隨機 hash/base64 會很高(>3.5)，正常英文詞偏低。"""
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


HEX_RE = re.compile(r'^[0-9a-f]{8,}$', re.I)              # 純16進位長字串 = hash
B64_RE = re.compile(r'^[A-Za-z0-9+/=_-]{20,}$')          # 長 base64 blob
HAS_CJK = re.compile(r'[一-鿿]')


def is_anomalous(tok: str) -> bool:
    """步驟3用：判斷一個 token 是不是『異常字段』(隨機hash/base64/超長亂碼)。"""
    if len(tok) >= 8 and HEX_RE.match(tok):
        return True
    if len(tok) >= 24 and B64_RE.match(tok):
        return True
    if len(tok) >= 12 and shannon_entropy(tok) > 3.5:   # 高熵 = 看起來隨機
        return True
    digit_ratio = sum(c.isdigit() for c in tok) / max(len(tok), 1)
    if len(tok) >= 10 and digit_ratio > 0.6:            # 一長串數字
        return True
    return False


# ========== 後綴擷取 ==========
_FALLBACK_MULTI_SUFFIX = {  # 沒裝 tldextract 時的小型 fallback（不完整！）
    'com.br', 'co.za', 'co.uk', 'com.au', 'co.jp', 'com.cn', 'gov.cn', 'org.uk',
}

def extract_suffix(url: str):
    host = urlparse(url if '://' in url else 'http://' + url).hostname or ''
    if _HAS_TLDEXTRACT:
        ext = tldextract.extract(url)
        return {'subdomain': ext.subdomain, 'domain': ext.domain,
                'suffix(TLD)': ext.suffix, 'registered': ext.registered_domain}
    # fallback：先比對已知雙段後綴，再退回最後一段
    parts = host.split('.')
    suffix = ''
    if len(parts) >= 3 and '.'.join(parts[-2:]) in _FALLBACK_MULTI_SUFFIX:
        suffix = '.'.join(parts[-2:]); dom = parts[-3]; sub = '.'.join(parts[:-3])
    elif len(parts) >= 2:
        suffix = parts[-1]; dom = parts[-2]; sub = '.'.join(parts[:-2])
    else:
        dom = host; sub = ''
    return {'subdomain': sub, 'domain': dom, 'suffix(TLD)': suffix,
            'registered': f'{dom}.{suffix}' if suffix else dom,
            '_note': '(fallback，建議裝 tldextract)'}


def file_ext(url: str):
    path = urlparse(url if '://' in url else 'http://' + url).path
    m = re.search(r'\.([a-zA-Z0-9]{1,5})$', path)
    return m.group(1).lower() if m else None


# ========== 三個斷詞步驟 ==========
def step1_split_symbols(url: str):
    """步驟1：用斜線/任何符號切。保留所有片段(含 http, www, 副檔名)。"""
    return [t for t in re.split(r'[\W_]+', url) if t]


def step2_wordseg(url: str):
    """步驟2：拿掉結構符號後，把黏在一起的字串做英文斷字。"""
    raw = step1_split_symbols(url)
    # 丟掉純結構雜訊
    drop = {'http', 'https', 'www', 'com', 'org', 'net', 'php', 'html', 'htm', 'asp'}
    words = []
    for tok in raw:
        if tok.lower() in drop or tok.isdigit():
            continue
        if _HAS_WORDNINJA and tok.isalpha() and len(tok) > 6:
            words.extend(wordninja.split(tok))   # marketingbyinternet -> [marketing, by, internet]
        else:
            words.append(tok)
    return words


def step3_clean_segment(url: str):
    """步驟3：先 URL-decode、排除異常字段(hash/base64/亂碼)，再對乾淨字串斷字。"""
    decoded = unquote(url)                        # %E5%84%BF... -> 中文
    raw = [t for t in re.split(r'[\W_]+', decoded) if t]
    kept, dropped, cjk = [], [], []
    drop = {'http', 'https', 'www'}
    for tok in raw:
        if tok.lower() in drop:
            continue
        if is_anomalous(tok):
            dropped.append(tok); continue
        if HAS_CJK.search(tok):
            cjk.append(tok); continue           # 中文 -> 交給 jieba(此處先標記)
        if _HAS_WORDNINJA and tok.isalpha() and len(tok) > 6:
            kept.extend(wordninja.split(tok))
        else:
            kept.append(tok)
    return {'clean_tokens': kept, 'dropped_anomalies': dropped, 'cjk(需jieba)': cjk}


# ========== 示範 ==========
SAMPLES = [
    ('phishing', 'br-icloud.com.br'),
    ('phishing', 'signin.eby.de.zukruygxctzmmqi.civpro.co.za'),
    ('phishing', 'http://www.marketingbyinternet.com/mo/e56508df639f6ce7d55c81ee3fcd5ba8/'),
    ('defacement', 'http://www.garage-pirenne.be/index.php?option=com_content&view=article&id=70'),
    ('malware', 'http://9779.info/%E5%84%BF%E7%AB%A5%E7%AB%8B%E4%BD%93%E7%BA%B8%E8%B4%B4%E7%94%BB/'),
    ('benign', 'allmusic.com/album/crazy-from-the-heat-r16990'),
]

if __name__ == '__main__':
    print(f'tldextract={_HAS_TLDEXTRACT}  wordninja={_HAS_WORDNINJA}\n' + '=' * 70)
    for label, url in SAMPLES:
        print(f'\n[{label}] {url}')
        print('  後綴 :', extract_suffix(url), '| 副檔名:', file_ext(url))
        print('  步驟1(符號切):', step1_split_symbols(url))
        print('  步驟2(英文斷字):', step2_wordseg(url))
        s3 = step3_clean_segment(url)
        print('  步驟3(清洗+斷字):', s3['clean_tokens'])
        if s3['dropped_anomalies']:
            print('        ↳ 丟掉的異常字段:', s3['dropped_anomalies'])
        if s3['cjk(需jieba)']:
            print('        ↳ 中文(需jieba):', s3['cjk(需jieba)'])
