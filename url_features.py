"""
url_features.py  ──  惡意 URL 斷詞 / 解碼 / 標籤 特徵工程模組

設計目標：把一條 URL 變成「乾淨、有標籤、看得懂」的 token，當作 ML 特徵。

整條 pipeline（實務正確順序）：
    原始 URL
      │
   ① 智慧解碼  smart_decode()      ← %E5%84%BF → 兒  (UTF-8/GBK/Big5)、xn-- Punycode → 中文域名
      │
   ② 結構解析  parse_structure()   ← scheme/子網域/網域/後綴(TLD)/路徑/參數/副檔名
      │
   ③ 異常過濾  is_anomalous()      ← 丟掉 hash / UUID / base64 / 高熵亂碼  (你的步驟3，要先做)
      │
   ④ 斷字      segment_token()     ← 英文用 wordsegment、中文用 jieba  (你的步驟2)
      │
   ⑤ 上標籤    tokenize_url()      ← 每個 token 標角色：tld/domain/cjk/word/digit/anomaly...

依賴： pip install tldextract wordsegment jieba   （都離線可跑，資料內建）
"""
import re
import math
import unicodedata
from urllib.parse import urlsplit, unquote_to_bytes, unquote

import tldextract
import wordsegment
import jieba

# wordsegment 第一次要載入字頻表（333k unigram + 250k bigram）
wordsegment.load()
# tldextract：用內建的 Public Suffix List 快照，不連網（避免每次抓清單）
_TLD = tldextract.TLDExtract(suffix_list_urls=())   # () = 只用套件內建快照
jieba.setLogLevel(20)  # 關掉 jieba 的 build dict 訊息


# ════════════════════════════════════════════════════════════════════
# ① 智慧解碼：把 %XX / Punycode 還原成原本的文字（中文或其他語言）
# ════════════════════════════════════════════════════════════════════
_DECODE_TRY = ("utf-8", "gbk", "big5", "shift_jis", "euc-kr")

def smart_decode(s: str):
    """
    還原 URL 編碼的文字。回傳 (解碼後字串, 用到的編碼 or None)。
    - %E5%84%BF...  → 先取出原始 bytes，再依序試 UTF-8→GBK→Big5→日韓編碼
    - 純 ASCII / 無 % 的字串原樣回傳
    為什麼要試多種編碼：大多數網站用 UTF-8，但中國舊站常用 GBK、台灣舊站用 Big5，
    日韓站可能是 Shift-JIS / EUC-KR。只用 UTF-8 解會得到亂碼。
    """
    if "%" not in s:
        return s, None
    raw = unquote_to_bytes(s)            # 只把 %XX 變回 bytes，ASCII 部分不變
    for enc in _DECODE_TRY:
        try:
            decoded = raw.decode(enc)
            # 解出來如果幾乎沒有可印字元就當失敗，繼續試下一種編碼
            if decoded and sum(c.isprintable() for c in decoded) / len(decoded) > 0.7:
                return decoded, enc
        except (UnicodeDecodeError, LookupError):
            continue
    return unquote(s, errors="replace"), "utf-8?"   # 都失敗：盡力而為


def decode_idna(host: str) -> str:
    """xn--fiqs8s  →  中  （國際化域名 Punycode 還原）。失敗就原樣回傳。"""
    if "xn--" not in host:
        return host
    out = []
    for label in host.split("."):
        if label.startswith("xn--"):
            try:
                out.append(label.encode("ascii").decode("idna"))
                continue
            except Exception:
                pass
        out.append(label)
    return ".".join(out)


# ════════════════════════════════════════════════════════════════════
# 文字種類偵測：決定一個 token 要交給 jieba(中文) 還是 wordsegment(英文)
# ════════════════════════════════════════════════════════════════════
_HAN = re.compile(r"[一-鿿㐀-䶿]")        # 中日漢字
_KANA = re.compile(r"[぀-ヿ]")                     # 日文假名
_HANGUL = re.compile(r"[가-힣]")                   # 韓文
_CYRILLIC = re.compile(r"[Ѐ-ӿ]")                 # 西里爾(常見於釣魚仿冒)

def script_of(tok: str) -> str:
    if _HAN.search(tok):
        return "han"          # 中文/漢字 → jieba
    if _KANA.search(tok):
        return "kana"         # 日文
    if _HANGUL.search(tok):
        return "hangul"       # 韓文
    if _CYRILLIC.search(tok):
        return "cyrillic"
    if tok.isdigit():
        return "digit"
    if re.fullmatch(r"[a-zA-Z]+", tok):
        return "latin"        # 純英文 → wordsegment
    return "mixed"


# ════════════════════════════════════════════════════════════════════
# ③ 異常字段偵測（你的步驟3）：hash / UUID / base64 / 高熵亂碼
# ════════════════════════════════════════════════════════════════════
def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    return -sum((c / n) * math.log2(c / n) for c in freq.values())

_HEX = re.compile(r"^[0-9a-f]+$", re.I)
_UUID = re.compile(r"^[0-9a-f]{8}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{12}$", re.I)
_B64 = re.compile(r"^[A-Za-z0-9+/_-]+={0,2}$")

def _looks_like_word(tok: str) -> bool:
    """真實英文(含黏在一起的多字)母音比例約 0.26~0.62；隨機字串通常落在這之外。
    用來避免把 'summaryauthpolicyagreement' 這種長黏字誤判成亂碼（前次實測教訓）。"""
    if not tok.isalpha():
        return False
    v = sum(c.lower() in "aeiou" for c in tok) / len(tok)
    return 0.26 <= v <= 0.62

def is_anomalous(tok: str, entropy_thr: float = 3.5) -> bool:
    """判斷是不是『不該斷詞、應排除』的隨機字段。門檻 entropy_thr 建議用你的資料校準。
    注意：hash/uuid/base64/長數字 由明確規則攔下；高熵規則只套在『不像真實單字』的 token，
    避免誤殺長英文黏字（純靠熵會誤判，見 memory）。"""
    if _UUID.match(tok):
        return True
    if len(tok) >= 24 and _HEX.match(tok):                    # MD5(32)/SHA(40,64) 類
        return True
    if len(tok) >= 16 and _B64.match(tok) and not tok.isalpha():
        return True
    digit_ratio = sum(c.isdigit() for c in tok) / max(len(tok), 1)
    if len(tok) >= 10 and digit_ratio > 0.6:                   # 一長串數字 ID
        return True
    if len(tok) >= 12 and not _looks_like_word(tok) and shannon_entropy(tok) > entropy_thr:
        return True                                            # 看起來隨機(且不像真實單字)
    return False


# ════════════════════════════════════════════════════════════════════
# ② 結構解析（含後綴/TLD/副檔名）
# ════════════════════════════════════════════════════════════════════
_STRUCT_NOISE = {"http", "https", "www"}

def _safe_urlsplit(u: str):
    """urlsplit 對畸形字串(不成對中括號/壞 port/怪位元組)會丟 ValueError。
    這裡容錯：先原樣試，失敗就清掉中括號重試，再失敗回 None。"""
    try:
        sp = urlsplit(u)
        _ = sp.hostname          # 觸發 netloc 解析(壞 IPv6 會在這丟錯)
        return sp
    except ValueError:
        try:
            sp = urlsplit(u.replace("[", "").replace("]", ""))
            _ = sp.hostname
            return sp
        except ValueError:
            return None

def parse_structure(url: str) -> dict:
    u = url if "://" in url else "http://" + url
    sp = _safe_urlsplit(u)
    if sp is None:                                   # 完全無法解析的畸形資料
        return {"scheme": "", "host": "", "subdomain": "", "domain": "",
                "suffix": "", "registered_domain": "", "port": None,
                "path": url, "query": "", "fragment": "", "file_ext": None,
                "has_ip_host": False, "malformed": True}
    host = decode_idna(sp.hostname or "")
    ext = _TLD.extract_str(host)
    path = sp.path
    m = re.search(r"\.([a-zA-Z0-9]{1,6})$", path)
    file_ext = m.group(1).lower() if m else None
    # 新版 tldextract 用 top_domain_under_public_suffix，舊版用 registered_domain
    reg = getattr(ext, "top_domain_under_public_suffix", None) or ext.registered_domain
    try:
        port = sp.port                              # 壞 port 也會丟 ValueError
    except ValueError:
        port = None
    return {
        "scheme": sp.scheme,
        "host": host,
        "subdomain": ext.subdomain,
        "domain": ext.domain,
        "suffix": ext.suffix,                       # ← 你要的「後綴/TLD」：co.uk / com.br 也正確
        "registered_domain": reg,                   # bbc.co.uk
        "port": port,
        "path": path,
        "query": sp.query,
        "fragment": sp.fragment,
        "file_ext": file_ext,                       # ← 路徑副檔名 php/html/asp
        "has_ip_host": bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host)),
        "malformed": False,
    }


# ════════════════════════════════════════════════════════════════════
# 釣魚線索數值特徵：給分類器「加料」用（釣魚網址的典型特徵）
#   實測：把這 12 個特徵加進 TF-IDF 模型，phishing F1 0.816 → 0.835
# ════════════════════════════════════════════════════════════════════
_SUS_TLD = {"tk", "ml", "ga", "cf", "gq", "xyz", "top", "club", "work", "click",
            "link", "icu", "online", "site", "live", "cn", "ru", "info"}
_LURE = ["login", "signin", "secure", "account", "update", "verify", "confirm",
         "bank", "paypal", "apple", "icloud", "microsoft", "amazon", "ebay",
         "wallet", "password", "webscr", "free", "bonus", "support"]

def extra_features(url: str) -> dict:
    """釣魚常見線索 → 12 個數值特徵。鍵名即欄位名，可直接餵分類器。"""
    sp = _safe_urlsplit(url if "://" in url else "http://" + url)
    host = (sp.hostname or "") if sp else ""
    path = (sp.path or "") if sp else url
    query = (sp.query or "") if sp else ""
    dec = smart_decode(url)[0].lower()                       # 解碼後再找誘餌字
    last_label = host.rsplit(".", 1)[-1] if "." in host else ""
    return {
        "host_len": len(host),                               # 主機名長度
        "host_dots": host.count("."),                        # 點數(子網域多寡)
        "host_digits": sum(c.isdigit() for c in host),       # 主機名數字數
        "host_hyphens": host.count("-"),                     # 連字號數
        "has_at": int("@" in url),                           # 有沒有 @ (釣魚常見)
        "path_depth": path.count("/"),                       # 路徑深度
        "sus_tld": int(last_label in _SUS_TLD),              # 可疑/免費 TLD
        "lure_hits": sum(k in dec for k in _LURE),           # 誘餌字命中數
        "n_params": query.count("="),                        # 參數數量
        "is_ip_host": int(bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host))),  # IP 當主機
        "url_len2": len(url),                                # 整體長度
        "special_ratio": round(sum(not c.isalnum() for c in url) / max(len(url), 1), 4),  # 特殊字比例
    }


# ════════════════════════════════════════════════════════════════════
# 斷字：英文 wordsegment、中文 jieba
# ════════════════════════════════════════════════════════════════════
def segment_token(tok: str):
    """把單一 token 斷成更小的詞。回傳 (子詞 list, 方法標籤)。"""
    sc = script_of(tok)
    if sc == "han":
        return [w for w in jieba.cut(tok) if w.strip()], "jieba"
    if sc == "latin" and len(tok) > 6:
        seg = wordsegment.segment(tok)
        return (seg if seg else [tok]), "wordsegment"
    return [tok], "asis"


# ════════════════════════════════════════════════════════════════════
# 多語言翻譯：任何語言 → 英文（解碼後的非英文字段翻成英文再斷詞、當標籤）
#   單一模型 Helsinki-NLP/opus-mt-mul-en 涵蓋數十種來源語言 → 英文
#   懶載入(第一次用才載模型) + 全域快取(651k 大量重複，只翻不重複的)
# ════════════════════════════════════════════════════════════════════
_MUL_EN_MODEL = "Helsinki-NLP/opus-mt-mul-en"
_TR = {"tok": None, "model": None}
_TRANS_CACHE = {}
# 非拉丁文字（中日韓、西里爾、阿拉伯、泰文等）→ 一定要翻
_NONLATIN_SPAN = re.compile(
    r"[㐀-鿿぀-ヿ가-힯Ѐ-ӿ؀-ۿ฀-๿]+"
)

def _load_translator():
    if _TR["model"] is None:
        from transformers import MarianMTModel, MarianTokenizer
        _TR["tok"] = MarianTokenizer.from_pretrained(_MUL_EN_MODEL)
        _TR["model"] = MarianMTModel.from_pretrained(_MUL_EN_MODEL)
        _TR["model"].eval()
    return _TR["tok"], _TR["model"]

_LANGID = None
# 拉丁語系翻譯時要忽略的結構/檔案/英文常見雜訊字（避免污染語言偵測）
_LATIN_STOP = {
    "index", "php", "html", "htm", "asp", "aspx", "jsp", "cgi", "page", "pages",
    "home", "default", "content", "view", "article", "articles", "category",
    "id", "item", "node", "main", "site", "web", "www", "http", "https",
    "com", "org", "net", "de", "nl", "ru", "fr", "es", "it", "info", "html5",
}

def _detect_lang_prob(text: str):
    """回傳 (語言碼, 機率0~1)。用正規化機率，方便設信心門檻。"""
    global _LANGID
    if _LANGID is None:
        from langid.langid import LanguageIdentifier, model
        _LANGID = LanguageIdentifier.from_modelstring(model, norm_probs=True)
    return _LANGID.classify(text)

def detect_lang(text: str) -> str:
    """偵測語言代碼(en/zh/de/ja...)。失敗回 'en'。"""
    try:
        return _detect_lang_prob(text)[0]
    except Exception:
        return "en"

def translate_many(texts, batch_size: int = 32, max_length: int = 80):
    """一批文字 → 英文。自動去重+快取。回傳與輸入等長的英文 list。"""
    import torch
    need = [t for t in dict.fromkeys(texts) if t and t.strip() and t not in _TRANS_CACHE]
    if need:
        tok, model = _load_translator()
        for i in range(0, len(need), batch_size):
            chunk = need[i:i + batch_size]
            enc = tok(chunk, return_tensors="pt", padding=True, truncation=True)
            with torch.no_grad():
                gen = model.generate(**enc, max_length=max_length, num_beams=2)
            for src, g in zip(chunk, gen):
                _TRANS_CACHE[src] = tok.decode(g, skip_special_tokens=True).strip()
    return [_TRANS_CACHE.get(t, t) for t in texts]

def translate_to_en(text: str) -> str:
    """單句翻成英文（內部走 translate_many 快取）。"""
    return translate_many([text])[0]


# ════════════════════════════════════════════════════════════════════
# 三個步驟的對外函式
# ════════════════════════════════════════════════════════════════════
def step1_symbol_split(url: str):
    """步驟1：先解碼，再用斜線/任何符號切。保留所有片段。"""
    decoded, _ = smart_decode(url)
    return [t for t in re.split(r"[\W_]+", decoded, flags=re.UNICODE) if t]


def step2_wordseg(url: str):
    """步驟2：拿掉結構雜訊後，對黏在一起的字串斷字（英文+中文）。"""
    toks = step1_symbol_split(url)
    out = []
    for t in toks:
        if t.lower() in _STRUCT_NOISE or t.isdigit():
            continue
        out.extend(segment_token(t)[0])
    return out


def step3_clean_segment(url: str, entropy_thr: float = 3.5):
    """步驟3：解碼 → 排除異常字段 → 對乾淨字串斷字。回傳分類好的 dict。"""
    toks = step1_symbol_split(url)
    kept, dropped = [], []
    for t in toks:
        if t.lower() in _STRUCT_NOISE:
            continue
        if is_anomalous(t, entropy_thr):
            dropped.append(t)
            continue
        kept.extend(segment_token(t)[0])
    return {"clean_tokens": kept, "dropped_anomalies": dropped}


# ════════════════════════════════════════════════════════════════════
# ⑤ 主函式：產生「帶標籤的 token」+ 一整排特徵
# ════════════════════════════════════════════════════════════════════
def tokenize_url(url: str, entropy_thr: float = 3.5, translate: bool = False) -> dict:
    """
    一條 URL → 完整特徵 dict：
      - 結構欄位（domain/suffix/file_ext...）
      - tagged_tokens：每個 token 標角色 [(token, tag), ...]
      - tokens：最終乾淨 token list（給 BoW / TF-IDF / 詞袋用）
      - 統計特徵（長度、熵、異常數、是否含中文/IP/編碼...）
    translate=True：把非拉丁語系(中日韓/西里爾/阿拉伯/泰…)字段整段翻成英文，
                    再斷詞、標成 label_en；原文 token 仍保留(cjk)。
    tag 可能值：scheme/host/subdomain/tld/domain/file_ext/cjk/word/digit/anomaly/label_en
    """
    st = parse_structure(url)
    decoded_full, enc = smart_decode(url)

    tagged = []
    n_anom = 0
    # 結構性標籤（直接來自解析，最可靠）
    if st["scheme"]:
        tagged.append((st["scheme"], "scheme"))
    if st["subdomain"]:
        for p in st["subdomain"].split("."):
            if p.lower() in _STRUCT_NOISE:          # www 等雜訊不進詞袋
                continue
            if is_anomalous(p, entropy_thr):         # 隨機子網域本身就是釣魚訊號 → 標記
                tagged.append((p, "anomaly"))
                n_anom += 1
            else:
                tagged.append((p, "subdomain"))
    if st["domain"]:
        # 網域名本身可能是黏在一起的字 → 再斷一次（marketingbyinternet）
        for w in segment_token(st["domain"])[0]:
            tagged.append((w, "domain"))
    if st["suffix"]:
        tagged.append((st["suffix"], "tld"))         # ← 後綴標籤
    if st["file_ext"]:
        tagged.append((st["file_ext"], "file_ext"))  # ← 副檔名標籤

    # 路徑 + 參數的 token（走完整步驟3：過濾異常 → 斷字 → 上標籤）
    path_q = (st["path"] + " " + st["query"] + " " + st["fragment"]).strip()
    decoded_pq, _ = smart_decode(path_q)
    for t in re.split(r"[\W_]+", decoded_pq, flags=re.UNICODE):
        if not t or t.lower() in _STRUCT_NOISE:
            continue
        if is_anomalous(t, entropy_thr):
            tagged.append((t, "anomaly"))
            n_anom += 1
            continue
        sub, method = segment_token(t)
        for w in sub:
            sc = script_of(w)
            tag = "cjk" if sc in ("han", "kana", "hangul") else (
                  "digit" if sc == "digit" else "word")
            tagged.append((w, tag))

    # 翻譯層：把非英文字段整段翻成英文 → 斷詞 → 標 label_en
    translations = []
    if translate:
        # (a) 非拉丁語系(中日韓/西里爾/阿拉伯/泰…)：一定翻，整段(phrase)品質才好
        spans = [s for s in dict.fromkeys(_NONLATIN_SPAN.findall(decoded_full)) if s]
        # (b) 拉丁語系但非英文(德/西/法/印尼…)：偵測語言，高信心才翻
        latin_words = [w for w, tag in tagged
                       if tag in ("word", "domain", "subdomain")
                       and w.isascii() and w.replace("-", "").isalpha()
                       and len(w) >= 4 and w.lower() not in _LATIN_STOP]
        if len(latin_words) >= 1:
            phrase = " ".join(latin_words)
            lang, prob = _detect_lang_prob(phrase)
            if lang != "en" and prob >= 0.90 and len(phrase) >= 8:
                spans.append(phrase)
        if spans:
            en_list = translate_many(spans)
            for src, en in zip(spans, en_list):
                translations.append((src, en))
                for w in re.split(r"[\W_]+", en.lower()):       # 翻完的英文再斷詞當標籤
                    if w and not w.isdigit() and w not in _LATIN_STOP:
                        tagged.append((w, "label_en"))

    tokens = [w for w, tag in tagged if tag not in ("anomaly", "scheme")]
    return {
        **st,
        "decoded_url": decoded_full,
        "decode_encoding": enc,                 # 用到哪種編碼（None=不需解碼）
        "was_encoded": enc is not None,
        "translations": translations,           # [(原文, 英文), ...]
        "tagged_tokens": tagged,
        "tokens": tokens,
        "token_str": " ".join(tokens),          # 直接餵 TfidfVectorizer 的字串
        "n_tokens": len(tokens),
        "n_anomaly": n_anom,
        "url_len": len(url),
        "url_entropy": round(shannon_entropy(url), 3),
        "has_cjk": bool(_HAN.search(decoded_full)),
        "n_digits": sum(c.isdigit() for c in url),
        "n_special": sum(not c.isalnum() for c in url),
    }


# ════════════════════════════════════════════════════════════════════
# 批次處理整個 DataFrame
# ════════════════════════════════════════════════════════════════════
def featurize_dataframe(df, url_col="url", entropy_thr=3.5, translate=False, extra=False, keep_cols=None):
    """對整個 df 跑 tokenize_url，回傳加好特徵欄位的新 df。
    translate=True 會對含非拉丁字段的列做翻譯（有快取，但仍會明顯變慢）。
    extra=True 會額外加上 12 個釣魚線索特徵（extra_features，很快）。"""
    import pandas as pd
    keep = keep_cols or [
        "domain", "suffix", "file_ext", "decode_encoding", "was_encoded",
        "token_str", "n_tokens", "n_anomaly", "url_len", "url_entropy",
        "has_cjk", "has_ip_host", "n_digits", "n_special", "malformed",
    ]
    recs, n_fail = [], 0
    for u in df[url_col].astype(str):
        try:
            f = tokenize_url(u, entropy_thr, translate=translate)
        except Exception:                          # 任何單筆意外都不該中斷整批
            n_fail += 1
            f = {"token_str": "", "url_len": len(u), "malformed": True}
        rec = {k: f.get(k) for k in keep}
        if translate:
            rec["translations"] = "; ".join(f"{s}->{e}" for s, e in f.get("translations", []))
        if extra:
            rec.update(extra_features(u))          # 12 個釣魚線索特徵
        recs.append(rec)
    if n_fail:
        print(f"⚠️ {n_fail} 筆畸形資料無法解析，已標記 malformed=True 並跳過")
    feat = pd.DataFrame(recs, index=df.index)
    return pd.concat([df, feat], axis=1)


if __name__ == "__main__":
    SAMPLES = [
        ("phishing",  "br-icloud.com.br"),
        ("phishing",  "signin.eby.de.zukruygxctzmmqi.civpro.co.za"),
        ("phishing",  "http://www.marketingbyinternet.com/mo/e56508df639f6ce7d55c81ee3fcd5ba8/"),
        ("defacement","http://www.garage-pirenne.be/index.php?option=com_content&view=article&id=70"),
        ("malware",   "http://9779.info/%E5%84%BF%E7%AB%A5%E7%AB%8B%E4%BD%93%E7%BA%B8%E8%B4%B4%E7%94%BB/"),
        ("benign",    "allmusic.com/album/crazy-from-the-heat-r16990"),
    ]
    for label, url in SAMPLES:
        f = tokenize_url(url)
        print(f"\n[{label}] {url}")
        print(f"   解碼: enc={f['decode_encoding']}  →  {f['decoded_url']}")
        print(f"   後綴(TLD)={f['suffix']!r}  網域={f['domain']!r}  副檔名={f['file_ext']!r}")
        print(f"   tokens: {f['tokens']}")
        anomalies = [t for t, tag in f['tagged_tokens'] if tag == 'anomaly']
        if anomalies:
            print(f"   丟掉的異常字段: {anomalies}")
