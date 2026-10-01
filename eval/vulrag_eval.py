"""
eval/vulrag_eval.py
Retrieval-only accuracy evaluation using CVEs from Vul-RAG benchmark.
NO Gemini/LLM calls. Reuses retrieval.py CveStore schema (read-only).
Runnable: python eval/vulrag_eval.py --repo "D:\Downloads\KnowledgeRAG4LLMVulD"
"""
import argparse
import json
import random
import re
from collections import Counter, defaultdict
from pathlib import Path
import sys

# Allow import of src/retrieval.py without modifying it
ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

try:
    from retrieval import CveStore
    RETRIEVAL_AVAILABLE = True
except Exception as e:
    RETRIEVAL_AVAILABLE = False
    CveStore = None
    print(f"Warning: could not import CveStore: {e}", file=sys.stderr)

def inspect_dataset(repo: Path):
    """STEP 1a: inspect Linux_kernel_clean_data_top10_CWEs.json and one benchmark file."""
    dataset = repo / "dataset" / "Linux_kernel_clean_data_top10_CWEs.json"
    print("=== STEP 1a INSPECT: Linux_kernel_clean_data_top10_CWEs.json ===")
    if not dataset.exists():
        print(f"NOT FOUND: {dataset}", file=sys.stderr)
        return
    with open(dataset, "r", encoding="utf-8") as f:
        data = json.load(f)
    print(f"File: {dataset} | type={type(data).__name__} | len={len(data) if isinstance(data, list) else 'dict'}")
    if isinstance(data, list) and data:
        e = data[0]
        print(f"Keys of one entry: {list(e.keys())}")
        for k in list(e.keys()):
            v = e[k]
            if k in ("code_before_change", "code_after_change", "patch"):
                print(f"  {k}: <code field skipped, len={len(str(v))}>")
            elif isinstance(v, str):
                print(f"  {k}: {repr(v[:200])}")
            elif isinstance(v, list):
                print(f"  {k}: list len={len(v)} sample={str(v[:2])[:300]}")
            elif isinstance(v, dict):
                print(f"  {k}: dict keys={list(v.keys())} preview={str(v)[:400]}")
            else:
                print(f"  {k}: {type(v).__name__} = {str(v)[:300]}")
        print("\nIdentified fields:")
        print("  CVE ID -> 'cve_id' (e.g.,", repr(e.get("cve_id")), ")")
        print("  CWE ID -> 'cwe' (list, e.g.,", e.get("cwe"), ")")
        print("  CVE description -> 'cve_description' (e.g.,", repr(str(e.get("cve_description"))[:150]), ")")
        print("  IGNORED code fields: code_before_change, code_after_change, patch, function_modified_lines")
    bench_dir = repo / "benchmark"
    sample = None
    for p in bench_dir.rglob("*.json"):
        sample = p
        break
    if sample:
        print(f"\n=== Sample benchmark file: {sample} ===")
        with open(sample, "r", encoding="utf-8") as f:
            bdata = json.load(f)
        print(f"type={type(bdata).__name__} len={len(bdata) if isinstance(bdata, list) else '?'}")
        if isinstance(bdata, list) and bdata:
            e2 = bdata[0]
            print(f"Keys: {list(e2.keys())}")
            for k in list(e2.keys())[:5]:
                v = e2[k]
                if isinstance(v, str):
                    print(f"  {k}: {repr(v[:200])}")
                else:
                    print(f"  {k}: {type(v).__name__} {str(v)[:300]}")

def inspect_knowledge(repo: Path):
    print("\n=== STEP 1b INSPECT: vulnerability knowledge ===")
    vk = repo / "vulnerability knowledge"
    if not vk.exists():
        print(f"NOT FOUND: {vk}")
        return {}
    files = [p for p in vk.glob("*.json") if p.name != "README.md"]
    print(f"Found {len(files)} knowledge files in {vk}")
    total = 0
    all_entries = []
    for fp in files[:2]:
        with open(fp, "r", encoding="utf-8") as f:
            data = json.load(f)
        print(f"  {fp.name}: {len(data)} entries | sample keys: {list(data[0].keys()) if data else []}")
        if data:
            print(f"    CVE_id sample: {data[0].get('CVE_id') or data[0].get('cve_id')}")
        total += len(data)
        all_entries.extend(data[:1])
    cve_ids = set()
    for fp in vk.glob("*.json"):
        if fp.name == "README.md":
            continue
        try:
            data = json.loads(fp.read_text(encoding="utf-8"))
            if isinstance(data, list):
                for e in data:
                    cid = e.get("CVE_id") or e.get("cve_id")
                    if cid:
                        cve_ids.add(cid)
        except:
            pass
    print(f"Total knowledge entries (all files): counted from 2 files ~ extrapolated, unique CVE_id across all: {len(cve_ids)}")
    dataset = repo / "dataset" / "Linux_kernel_clean_data_top10_CWEs.json"
    if dataset.exists():
        with open(dataset, "r", encoding="utf-8") as f:
            d = json.load(f)
        ds_cves = set(x["cve_id"] for x in d)
        print(f"Dataset unique CVE: {len(ds_cves)} | Knowledge unique: {len(cve_ids)} | Overlap: {len(ds_cves & cve_ids)} | Dataset not in KB: {len(ds_cves - cve_ids)}")
        print(f"Joinable by CVE ID: CVE_id (knowledge) == cve_id (dataset) -> YES")
    return

def inspect_retrieval():
    print("\n=== STEP 1c INSPECT: retrieval.py ===")
    rp = ROOT / "src" / "retrieval.py"
    print(f"Reading {rp}")
    text = rp.read_text(encoding="utf-8")
    print("\nCveStore:")
    print("  Construction: CveStore(cve_kb: dict) where cve_kb is dict keyed by CVE ID, value is CVE record dict (schema: id, text, cvss_v3_score, cwe_ids, etc. as in data/knowledge_base/synthetic_cve_kb.json)")
    print("  Query: lookup(cve_id: str) -> dict|None ; lookup_many(cve_ids: list) -> list[dict] (exact key lookup, not semantic)")
    print("  Returns: direct record dict or {'id': cve_id, 'not_found': True, 'text': None} for misses; NO score field, NO top-k support, NO vectorization")
    print("  Threshold/abstention: NONE - CveStore never abstains, always returns exact lookup or explicit not_found marker; no similarity threshold")
    print("\nCisIndex (for contrast):")
    print("  Construction: CisIndex(cis_kb: list[dict]) -> fits TfidfVectorizer(stop_words='english') on each control's 'text' field; stores matrix")
    print("  Query: search(query_text: str, service_tags: list[str], top_k=3) -> filters controls by applies_to overlap before ranking, then cosine_similarity between query_vec and candidate_matrix, returns top_k sorted by similarity_score (rounded to 3 decimals)")
    print("  Returns: list[dict] each with added 'similarity_score' field (float 0-1)")
    print("  Threshold/abstention: implicit - returns [] if vectorizer is None, query empty, or no candidate tags match; NO explicit similarity threshold (always returns top_k of filtered set, even if score ~0)")
    print("\nImplication for this task: CveStore is NOT suitable for truncated/knowledge text retrieval (requires exact CVE ID). We must build a NEW semantic index over CVE descriptions using the SAME TF-IDF+cosine approach as CisIndex, but over the temp Vul-RAG KB file (eval/results/tmp_vulrag_kb.json) in the same dict schema CveStore expects. This reuses the schema without modifying retrieval.py.")

def load_dataset(repo: Path):
    dataset_path = repo / "dataset" / "Linux_kernel_clean_data_top10_CWEs.json"
    with open(dataset_path, "r", encoding="utf-8") as f:
        raw = json.load(f)
    cve_map = {}
    for e in raw:
        cid = e.get("cve_id")
        if not cid:
            continue
        if cid not in cve_map:
            cwe_list = e.get("cwe") or []
            primary_cwe = None
            for c in cwe_list:
                if c.startswith("CWE-"):
                    primary_cwe = c
                    break
            if not primary_cwe and cwe_list:
                primary_cwe = cwe_list[0]
            if not primary_cwe:
                primary_cwe = "UNKNOWN"
            cve_map[cid] = {
                "cve_id": cid,
                "cwe": primary_cwe,
                "cwe_list": cwe_list,
                "description": e.get("cve_description") or "",
                "raw": e,
            }
        else:
            pass
    return cve_map

def load_knowledge(repo: Path):
    vk = repo / "vulnerability knowledge"
    kb = {}
    for fp in vk.glob("*.json"):
        if fp.name.lower() == "readme.md":
            continue
        try:
            data = json.loads(fp.read_text(encoding="utf-8"))
        except:
            continue
        if not isinstance(data, list):
            continue
        for e in data:
            cid = e.get("CVE_id") or e.get("cve_id")
            if not cid:
                continue
            if cid in kb:
                continue
            parts = []
            for field in ["purpose", "function", "analysis", "solution"]:
                v = e.get(field)
                if isinstance(v, str) and v.strip():
                    parts.append(v.strip())
            vb = e.get("vulnerability_behavior") or {}
            if isinstance(vb, dict):
                for k in ["vulnerability_cause_description", "trigger_condition", "specific_code_behavior_causing_vulnerability"]:
                    v = vb.get(k)
                    if isinstance(v, str) and v.strip():
                        parts.append(v.strip())
            for k in ["vulnerability_cause_description", "trigger_condition", "specific_code_behavior_causing_vulnerability"]:
                v = e.get(k)
                if isinstance(v, str) and v.strip() and v.strip() not in parts:
                    parts.append(v.strip())
            text = " ".join(parts)
            if not text:
                text = e.get("analysis") or e.get("purpose") or ""
            kb[cid] = text
    return kb

def stratified_split(cve_map, seed=42):
    random.seed(seed)
    groups = defaultdict(list)
    for cid, rec in cve_map.items():
        groups[rec["cwe"]].append(cid)
    indexed = []
    unseen = []
    for cwe in sorted(groups.keys()):
        lst = groups[cwe][:]
        random.shuffle(lst)
        n = len(lst)
        n_unseen = int(round(n * 0.2))
        if n >= 5 and n_unseen == 0:
            n_unseen = 1
        if n_unseen > n:
            n_unseen = n
        unseen.extend(lst[:n_unseen])
        indexed.extend(lst[n_unseen:])
    random.shuffle(indexed)
    random.shuffle(unseen)
    return indexed, unseen

def build_temp_kb(indexed_cids, cve_map, out_path: Path):
    kb = {}
    for cid in indexed_cids:
        rec = cve_map[cid]
        kb[cid] = {
            "id": cid,
            "text": rec["description"],
            "cvss_v3_score": None,
            "cvss_v3_vector": None,
            "cvss_severity": None,
            "cwe_ids": [rec["cwe"]] if rec["cwe"] != "UNKNOWN" else [],
            "published_date": None,
            "last_modified_date": None,
            "references": [],
            "kev_listed": None,
            "kev_date_added": None,
        }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(kb, f, indent=2, ensure_ascii=False)
    if RETRIEVAL_AVAILABLE:
        _store = CveStore(kb)
        assert _store.lookup(indexed_cids[0]) is not None
    return kb

def build_tfidf_index(kb: dict):
    ids = list(kb.keys())
    texts = [kb[cid].get("text") or "" for cid in ids]
    vectorizer = TfidfVectorizer(stop_words="english")
    matrix = vectorizer.fit_transform(texts)
    if matrix.shape[1] == 0:
        return ids, vectorizer, None
    return ids, vectorizer, matrix

def retrieve(query_text: str, kb_ids, vectorizer, matrix, top_k=5):
    if not query_text or not query_text.strip():
        return [], []
    if matrix is None:
        return [], []
    q_vec = vectorizer.transform([query_text])
    sims = cosine_similarity(q_vec, matrix)[0]
    ranked = sorted(zip(kb_ids, sims), key=lambda x: x[1], reverse=True)
    return ranked[:top_k], ranked

def truncated_query(description: str, ratio=0.5):
    words = description.split()
    if not words:
        return ""
    n = max(1, int(len(words) * ratio))
    return " ".join(words[:n])

def evaluate():
    parser = argparse.ArgumentParser(description="Retrieval-only Vul-RAG CVE accuracy")
    parser.add_argument("--repo", required=True, help="Path to cloned KnowledgeRAG4LLMVulD repo")
    args = parser.parse_args()
    repo = Path(args.repo)
    if not repo.exists():
        print(f"Repo not found: {repo}", file=sys.stderr)
        sys.exit(1)

    inspect_dataset(repo)
    inspect_knowledge(repo)
    inspect_retrieval()

    print("\n=== STEP 2 BUILD DATASET ===")
    random.seed(42)
    cve_map = load_dataset(repo)
    print(f"Loaded dataset: {len(cve_map)} unique CVE records (deduped)")
    cwe_counts = Counter(rec["cwe"] for rec in cve_map.values())
    print(f"CWE distribution (deduped): {dict(sorted(cwe_counts.items()))}")
    kb_knowledge = load_knowledge(repo)
    print(f"Loaded knowledge: {len(kb_knowledge)} unique CVE knowledge entries")
    overlap = set(cve_map.keys()) & set(kb_knowledge.keys())
    print(f"Joinable (CVE ID overlap): {len(overlap)} / {len(cve_map)} dataset CVEs have knowledge")
    if len(overlap) < len(cve_map) * 0.5:
        print("WARNING: <50% knowledge coverage, knowledge mode may be sparse")

    indexed, unseen = stratified_split(cve_map, seed=42)
    print(f"Split seed=42: indexed (80%) {len(indexed)} , unseen (20%) {len(unseen)}")
    for cwe in sorted(set(cve_map[c]["cwe"] for c in indexed + unseen))[:10]:
        idx_c = sum(1 for c in indexed if cve_map[c]["cwe"] == cwe)
        uns_c = sum(1 for c in unseen if cve_map[c]["cwe"] == cwe)
        print(f"  {cwe}: indexed {idx_c} unseen {uns_c} total {idx_c+uns_c}")

    tmp_kb_path = ROOT / "eval" / "results" / "tmp_vulrag_kb.json"
    kb = build_temp_kb(indexed, cve_map, tmp_kb_path)
    print(f"Wrote temp KB to {tmp_kb_path} with {len(kb)} entries (schema same as CveStore expects)")
    kb_ids, vectorizer, matrix = build_tfidf_index(kb)
    print(f"TF-IDF index built: vocab size {matrix.shape[1] if matrix is not None else 0}, docs {len(kb_ids)}")

    print("\n=== STEP 3 EVALUATION ===")

    # Precompute per-query retrieval details for both in-KB modes and unseen
    # In-KB truncated
    in_truncated_details = []
    for cid in indexed:
        rec = cve_map[cid]
        q = truncated_query(rec["description"], 0.5)
        if not q.strip():
            in_truncated_details.append({"cve_id": cid, "query": q, "top1_cid": None, "top1_score": 0.0, "rank": None, "correct": False, "cwe_match": False})
            continue
        top, full = retrieve(q, kb_ids, vectorizer, matrix, top_k=5)
        top1_cid, top1_score = top[0] if top else (None, 0.0)
        rank = None
        for idx, (rcid, sc) in enumerate(full):
            if rcid == cid:
                rank = idx + 1
                break
        correct = (top1_cid == cid)
        cwe_match = False
        if not correct and top1_cid:
            top1_cwe = cve_map.get(top1_cid, {}).get("cwe") or kb.get(top1_cid, {}).get("cwe_ids", [None])[0]
            if top1_cwe == rec["cwe"]:
                cwe_match = True
        in_truncated_details.append({"cve_id": cid, "query": q, "top1_cid": top1_cid, "top1_score": top1_score, "rank": rank, "correct": correct, "cwe_match": cwe_match})

    # In-KB knowledge (only joinable)
    in_knowledge_details = []
    joinable_cids = [cid for cid in indexed if kb_knowledge.get(cid, "").strip()]
    for cid in joinable_cids:
        q = kb_knowledge.get(cid, "")
        top, full = retrieve(q, kb_ids, vectorizer, matrix, top_k=5)
        top1_cid, top1_score = top[0] if top else (None, 0.0)
        rank = None
        for idx, (rcid, sc) in enumerate(full):
            if rcid == cid:
                rank = idx + 1
                break
        correct = (top1_cid == cid)
        rec = cve_map[cid]
        cwe_match = False
        if not correct and top1_cid:
            top1_cwe = cve_map.get(top1_cid, {}).get("cwe") or kb.get(top1_cid, {}).get("cwe_ids", [None])[0]
            if top1_cwe == rec["cwe"]:
                cwe_match = True
        in_knowledge_details.append({"cve_id": cid, "query": q, "top1_cid": top1_cid, "top1_score": top1_score, "rank": rank, "correct": correct, "cwe_match": cwe_match})

    # Unseen details
    unseen_details = []
    for cid in unseen:
        rec = cve_map[cid]
        q = truncated_query(rec["description"], 0.5)
        top, full = retrieve(q, kb_ids, vectorizer, matrix, top_k=5)
        top1_cid, top1_score = top[0] if top else (None, 0.0)
        unseen_details.append({"cve_id": cid, "query": q, "top1_cid": top1_cid, "top1_score": top1_score})

    # Base metrics at threshold 0 (original)
    def base_metrics(details):
        n = len(details)
        if n == 0:
            return {"n": 0, "top1_acc": None, "top5_acc": None, "mrr": None, "cwe_match": 0, "sibling": 0}
        top1 = sum(1 for d in details if d["correct"])
        # top5 needs rank
        top5 = sum(1 for d in details if d["rank"] is not None and d["rank"] <= 5)
        mrr = sum(1.0/d["rank"] if d["rank"] else 0.0 for d in details) / n
        cwe = sum(1 for d in details if d["cwe_match"])
        return {"n": n, "top1": top1, "top5": top5, "top1_acc": top1/n, "top5_acc": top5/n, "mrr": mrr, "cwe_match": cwe, "cwe_rate": cwe/n}

    in_truncated_base = base_metrics(in_truncated_details)
    in_knowledge_base = base_metrics(in_knowledge_details) if in_knowledge_details else {"n": 0, "top1": 0, "top5": 0, "top1_acc": None, "top5_acc": None, "mrr": None, "cwe_match": 0, "cwe_rate": None}
    print(f"In-KB truncated: n={in_truncated_base['n']} top1={in_truncated_base['top1_acc']:.3f} top5={in_truncated_base['top5_acc']:.3f} MRR={in_truncated_base['mrr']:.3f} CWE-match={in_truncated_base['cwe_match']} ({in_truncated_base['cwe_rate']:.3f})")
    if in_knowledge_details:
        print(f"In-KB knowledge: n={in_knowledge_base['n']} top1={in_knowledge_base['top1_acc']:.3f} top5={in_knowledge_base['top5_acc']:.3f} MRR={in_knowledge_base['mrr']:.3f} CWE-match={in_knowledge_base['cwe_match']}")
    else:
        print("In-KB knowledge: SKIPPED")

    # Threshold sweep for both modes + unseen
    thresholds = [0.0, 0.1, 0.2, 0.3, 0.4, 0.5]
    # For threshold metrics we need per-threshold coverage etc.
    in_truncated_thr = {}
    in_knowledge_thr = {}
    unseen_thr = {}

    # Correct at 0 for lost calculation
    correct_at_0_trunc = in_truncated_base["top1"]
    correct_at_0_know = in_knowledge_base["top1"] if in_knowledge_base["n"] else 0

    for thr in thresholds:
        # In-KB truncated
        answered = [d for d in in_truncated_details if d["top1_score"] >= thr]
        n = len(in_truncated_details)
        cov = len(answered) / n if n else 0
        correct_answered = sum(1 for d in answered if d["correct"])
        prec = correct_answered / len(answered) if answered else 0.0
        # correct retained = correct_answered, correct lost = correct_at_0 - correct_answered
        correct_lost_cnt = correct_at_0_trunc - correct_answered
        correct_lost_pct = (correct_lost_cnt / correct_at_0_trunc * 100) if correct_at_0_trunc else 0.0
        retained = correct_answered
        in_truncated_thr[str(thr)] = {
            "threshold": thr,
            "coverage": cov,
            "answered": len(answered),
            "n": n,
            "precision_at_coverage": prec,
            "correct_answered": correct_answered,
            "correct_at_0": correct_at_0_trunc,
            "correct_lost": correct_lost_cnt,
            "correct_lost_pct": correct_lost_cnt / correct_at_0_trunc if correct_at_0_trunc else 0.0,
            "correct_retained": retained,
        }
        # In-KB knowledge
        if in_knowledge_details:
            answered_k = [d for d in in_knowledge_details if d["top1_score"] >= thr]
            n_k = len(in_knowledge_details)
            cov_k = len(answered_k) / n_k if n_k else 0
            correct_answered_k = sum(1 for d in answered_k if d["correct"])
            prec_k = correct_answered_k / len(answered_k) if answered_k else 0.0
            correct_lost_cnt_k = correct_at_0_know - correct_answered_k
            in_knowledge_thr[str(thr)] = {
                "threshold": thr,
                "coverage": cov_k,
                "answered": len(answered_k),
                "n": n_k,
                "precision_at_coverage": prec_k,
                "correct_answered": correct_answered_k,
                "correct_at_0": correct_at_0_know,
                "correct_lost": correct_lost_cnt_k,
                "correct_lost_pct": correct_lost_cnt_k / correct_at_0_know if correct_at_0_know else 0.0,
                "correct_retained": correct_answered_k,
            }
        else:
            in_knowledge_thr[str(thr)] = {"threshold": thr, "coverage": 0, "precision_at_coverage": 0, "correct_lost": 0, "correct_lost_pct": 0, "n": 0}

        # Unseen
        correct_abstain = sum(1 for d in unseen_details if d["top1_score"] < thr)
        false_cite = len(unseen_details) - correct_abstain
        n_unseen = len(unseen_details)
        unseen_thr[str(thr)] = {
            "threshold": thr,
            "correct_abstention_rate": correct_abstain / n_unseen if n_unseen else 0,
            "false_citation_rate": false_cite / n_unseen if n_unseen else 0,
            "correct_abstain": correct_abstain,
            "false_cite": false_cite,
            "n": n_unseen,
        }

    print("\nUnseen (20% held out, truncated) - abstention test")
    for thr in thresholds:
        r = unseen_thr[str(thr)]
        print(f"  thr={thr:.1f}: correct_abstain {r['correct_abstain']}/{r['n']} ({r['correct_abstention_rate']:.3f}) false_cite {r['false_cite']}/{r['n']} ({r['false_citation_rate']:.3f})")

    print("\nIn-KB truncated - threshold sweep")
    for thr in thresholds:
        r = in_truncated_thr[str(thr)]
        print(f"  thr={thr:.1f}: coverage {r['answered']}/{r['n']} ({r['coverage']:.3f}) prec {r['precision_at_coverage']:.3f} lost {r['correct_lost']}/{r['correct_at_0']} ({r['correct_lost_pct']:.3f})")

    if in_knowledge_details:
        print("\nIn-KB knowledge - threshold sweep")
        for thr in thresholds:
            r = in_knowledge_thr[str(thr)]
            print(f"  thr={thr:.1f}: coverage {r['answered']}/{r['n']} ({r['coverage']:.3f}) prec {r['precision_at_coverage']:.3f} lost {r['correct_lost']}/{r['correct_at_0']} ({r['correct_lost_pct']:.3f})")

    # Combined tables and suggestion
    # Maximize (in-KB correct retained + unseen abstention)
    # Use truncated mode as primary for suggestion (task says one combined table per threshold with in-KB coverage/precision/correct-lost + unseen abstention/false-citation)
    # We'll compute score per threshold for both modes, report best
    best_thr = None
    best_score = -1
    best_mode = "truncated"
    for thr in thresholds:
        retained = in_truncated_thr[str(thr)]["correct_retained"]
        abstain = unseen_thr[str(thr)]["correct_abstain"]
        score = retained + abstain
        if score > best_score:
            best_score = score
            best_thr = thr
    # Also check knowledge mode
    best_thr_k = None
    best_score_k = -1
    if in_knowledge_details:
        for thr in thresholds:
            retained = in_knowledge_thr[str(thr)]["correct_retained"]
            abstain = unseen_thr[str(thr)]["correct_abstain"]
            score = retained + abstain
            if score > best_score_k:
                best_score_k = score
                best_thr_k = thr

    print(f"\nSuggestion (truncated mode) threshold maximizing (retained + abstention): {best_thr} with score {best_score} (retained {in_truncated_thr[str(best_thr)]['correct_retained']} + abstain {unseen_thr[str(best_thr)]['correct_abstain']})")
    if best_thr_k is not None:
        print(f"Suggestion (knowledge mode) threshold: {best_thr_k} with score {best_score_k}")

    # STEP 4 OUTPUTS
    config = {
        "seed": 42,
        "repo": str(repo),
        "dataset_file": "dataset/Linux_kernel_clean_data_top10_CWEs.json",
        "dedupe": "one record per CVE ID {cve_id, cwe, description}",
        "cwe_field": "cwe[0] primary",
        "description_field": "cve_description",
        "knowledge_join": "CVE_id == cve_id",
        "split": {"indexed": len(indexed), "unseen": len(unseen), "stratified_by_cwe": True, "seed": 42, "total_unique_cve": len(cve_map)},
        "temp_kb": str(tmp_kb_path),
        "retrieval": {
            "store": "CveStore (direct lookup) for storage + TF-IDF/Cosine (TfidfVectorizer(stop_words='english') + cosine_similarity) mirroring CisIndex.search (no service_tags filtering, no explicit threshold in retrieval.py)",
            "existing_threshold": "NONE in retrieval.py (CveStore never abstains; CisIndex only returns [] when no tags/empty vocab). For this eval, default threshold considered 0.0 (never abstain). CveStore is exact-ID lookup with no threshold; this evaluates a TF-IDF retriever mirroring CisIndex.",
            "sweep_thresholds": thresholds,
        },
        "query_modes": {"truncated": "first ~50% words of description", "knowledge": "concatenated purpose+function+analysis+solution+vulnerability_behavior text from vulnerability knowledge files"},
        "assumptions": {
            "knowledge_text": "concatenated all textual knowledge fields per CVE_id",
            "truncated_ratio": 0.5,
            "top_k": 5,
            "cwe_match_definition": "top-1 wrong but shares same primary CWE",
            "abstention_logic": "max cosine similarity < threshold => abstain",
            "suggestion_metric": "maximize (in-KB correct retained + unseen correct abstention) - reported as suggestion only",
        }
    }

    metrics = {
        "in_kb_truncated": {"base": in_truncated_base, "per_threshold": in_truncated_thr},
        "in_kb_knowledge": {"base": in_knowledge_base, "per_threshold": in_knowledge_thr, "skipped": len(in_knowledge_details)==0},
        "unseen_truncated": unseen_thr,
        "combined_truncated": {str(thr): {
            "threshold": thr,
            "in_kb_coverage": in_truncated_thr[str(thr)]["coverage"],
            "in_kb_precision": in_truncated_thr[str(thr)]["precision_at_coverage"],
            "in_kb_correct_lost": in_truncated_thr[str(thr)]["correct_lost"],
            "in_kb_correct_lost_pct": in_truncated_thr[str(thr)]["correct_lost_pct"],
            "in_kb_correct_retained": in_truncated_thr[str(thr)]["correct_retained"],
            "unseen_correct_abstention": unseen_thr[str(thr)]["correct_abstention_rate"],
            "unseen_false_citation": unseen_thr[str(thr)]["false_citation_rate"],
            "score_retained_plus_abstain": in_truncated_thr[str(thr)]["correct_retained"] + unseen_thr[str(thr)]["correct_abstain"],
        } for thr in thresholds},
        "combined_knowledge": {str(thr): {
            "threshold": thr,
            "in_kb_coverage": in_knowledge_thr[str(thr)]["coverage"],
            "in_kb_precision": in_knowledge_thr[str(thr)]["precision_at_coverage"],
            "in_kb_correct_lost": in_knowledge_thr[str(thr)]["correct_lost"],
            "in_kb_correct_lost_pct": in_knowledge_thr[str(thr)]["correct_lost_pct"],
            "in_kb_correct_retained": in_knowledge_thr[str(thr)]["correct_retained"],
            "unseen_correct_abstention": unseen_thr[str(thr)]["correct_abstention_rate"],
            "unseen_false_citation": unseen_thr[str(thr)]["false_citation_rate"],
            "score_retained_plus_abstain": (in_knowledge_thr[str(thr)]["correct_retained"] + unseen_thr[str(thr)]["correct_abstain"]) if in_knowledge_details else None,
        } for thr in thresholds},
        "suggestion": {
            "truncated_mode": {"threshold": best_thr, "score": best_score, "retained": in_truncated_thr[str(best_thr)]["correct_retained"] if best_thr is not None else None, "abstain": unseen_thr[str(best_thr)]["correct_abstain"] if best_thr is not None else None},
            "knowledge_mode": {"threshold": best_thr_k, "score": best_score_k, "retained": in_knowledge_thr[str(best_thr_k)]["correct_retained"] if best_thr_k is not None else None, "abstain": unseen_thr[str(best_thr_k)]["correct_abstain"] if best_thr_k is not None else None} if in_knowledge_details else None,
            "note": "Suggestion only - maximizes retained correct + abstention, not a tuned threshold",
        },
        "sibling_confusions": {
            "truncated_mode_count": in_truncated_base["cwe_match"],
            "knowledge_mode_count": in_knowledge_base.get("cwe_match", 0) if in_knowledge_base else 0,
            "description": "in-KB queries where top-1 was wrong but shares same CWE"
        },
        "counts": {
            "total_unique_cve": len(cve_map),
            "indexed": len(indexed),
            "unseen": len(unseen),
            "knowledge_total": len(kb_knowledge),
            "knowledge_joinable_indexed": len(joinable_cids),
            "temp_kb_size": len(kb),
        }
    }

    out_json = ROOT / "eval" / "results" / "vulrag_eval.json"
    out_json.parent.mkdir(parents=True, exist_ok=True)
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump({"config": config, "metrics": metrics, "cwe_distribution": dict(Counter(cve_map[c]["cwe"] for c in cve_map))}, f, indent=2, ensure_ascii=False)
    print(f"\nWrote {out_json}")

    out_md = ROOT / "eval" / "results" / "vulrag_eval.md"
    def fmt(x):
        if x is None:
            return "N/A"
        if isinstance(x, float):
            return f"{x:.3f} ({x*100:.1f}%)"
        return str(x)

    md_lines = []
    md_lines.append("# Vul-RAG Retrieval-Only Evaluation")
    md_lines.append("")
    md_lines.append(f"**Repo:** `{repo}`  | **Seed:** `42` | **Total unique CVE:** `{len(cve_map)}` | **Indexed (80%):** `{len(indexed)}` | **Unseen (20%):** `{len(unseen)}` | **Temp KB:** `{tmp_kb_path}`")
    md_lines.append("")
    md_lines.append("## Summary Table")
    md_lines.append("")
    md_lines.append("| Query Set | Mode | N | Top-1 Acc | Top-5 Acc | MRR | CWE-match (wrong CVE, right CWE) | Sibling Confusions |")
    md_lines.append("|---|---|---|---|---|---|---|---|")
    md_lines.append(f"| In-KB (indexed) | truncated (first 50% desc) | {in_truncated_base['n']} | {fmt(in_truncated_base['top1_acc'])} | {fmt(in_truncated_base['top5_acc'])} | {fmt(in_truncated_base['mrr'])} | {in_truncated_base['cwe_match']} ({fmt(in_truncated_base['cwe_rate'])}) | {in_truncated_base['cwe_match']} |")
    if not in_knowledge_details:
        md_lines.append(f"| In-KB (indexed) | knowledge (extracted) | 0 | SKIPPED | SKIPPED | SKIPPED | 0 | 0 | *no joinable* |")
    else:
        md_lines.append(f"| In-KB (indexed) | knowledge (extracted) | {in_knowledge_base['n']} | {fmt(in_knowledge_base['top1_acc'])} | {fmt(in_knowledge_base['top5_acc'])} | {fmt(in_knowledge_base['mrr'])} | {in_knowledge_base['cwe_match']} ({fmt(in_knowledge_base['cwe_rate'])}) | {in_knowledge_base['cwe_match']} |")
    md_lines.append("")
    md_lines.append("### Per-Threshold In-KB Coverage / Precision / Correct Lost")
    md_lines.append("")
    md_lines.append("| Threshold | Mode | Coverage (answered/N) | Precision@Coverage (correct/answered) | Correct Lost (lost/correct_at_0) | Correct Retained |")
    md_lines.append("|---|---|---|---|---|---|")
    for thr in thresholds:
        r = in_truncated_thr[str(thr)]
        md_lines.append(f"| {thr:.1f} | truncated | {r['answered']}/{r['n']} ({r['coverage']*100:.1f}%) | {r['correct_answered']}/{r['answered']} ({r['precision_at_coverage']*100:.1f}%) | {r['correct_lost']}/{r['correct_at_0']} ({r['correct_lost_pct']*100:.1f}%) | {r['correct_retained']} |")
    if in_knowledge_details:
        for thr in thresholds:
            r = in_knowledge_thr[str(thr)]
            md_lines.append(f"| {thr:.1f} | knowledge | {r['answered']}/{r['n']} ({r['coverage']*100:.1f}%) | {r['correct_answered']}/{r['answered'] if r['answered'] else 1} ({r['precision_at_coverage']*100:.1f}%) | {r['correct_lost']}/{r['correct_at_0']} ({r['correct_lost_pct']*100:.1f}%) | {r['correct_retained']} |")
    md_lines.append("")
    md_lines.append("### Unseen Queries (20% held out, truncated) - Abstention")
    md_lines.append("")
    md_lines.append("| Threshold (cosine) | Correct Abstention | False Citation | N |")
    md_lines.append("|---|---|---|---|")
    for thr in thresholds:
        r = unseen_thr[str(thr)]
        md_lines.append(f"| {thr:.1f} | {r['correct_abstain']}/{r['n']} ({r['correct_abstention_rate']*100:.1f}%) | {r['false_cite']}/{r['n']} ({r['false_citation_rate']*100:.1f}%) | {r['n']} |")
    md_lines.append("")
    md_lines.append("**Existing threshold in `retrieval.py`:** *NONE* - `CveStore` uses exact key lookup (no similarity), `CisIndex.search` returns top-k filtered by `applies_to` with no score threshold (only abstains when no candidate tags or empty vocab). For this eval, default is treated as `0.0` (never abstain); sweep shows trade-off above.")
    md_lines.append("")
    md_lines.append("### Combined Table per Threshold (truncated mode primary)")
    md_lines.append("")
    md_lines.append("| Threshold | In-KB Coverage | In-KB Precision | In-KB Correct Lost | Unseen Correct Abstention | Unseen False Citation | Score (retained+abstain) |")
    md_lines.append("|---|---|---|---|---|---|---|")
    for thr in thresholds:
        ct = in_truncated_thr[str(thr)]
        ut = unseen_thr[str(thr)]
        score = ct["correct_retained"] + ut["correct_abstain"]
        md_lines.append(f"| {thr:.1f} | {ct['coverage']*100:.1f}% ({ct['answered']}/{ct['n']}) | {ct['precision_at_coverage']*100:.1f}% | {ct['correct_lost']}/{ct['correct_at_0']} ({ct['correct_lost_pct']*100:.1f}%) | {ut['correct_abstention_rate']*100:.1f}% ({ut['correct_abstain']}/{ut['n']}) | {ut['false_citation_rate']*100:.1f}% | {score} |")
    if in_knowledge_details:
        md_lines.append("")
        md_lines.append("### Combined Table per Threshold (knowledge mode)")
        md_lines.append("")
        md_lines.append("| Threshold | In-KB Coverage | In-KB Precision | In-KB Correct Lost | Unseen Correct Abstention | Unseen False Citation | Score |")
        md_lines.append("|---|---|---|---|---|---|---|")
        for thr in thresholds:
            ct = in_knowledge_thr[str(thr)]
            ut = unseen_thr[str(thr)]
            score = ct["correct_retained"] + ut["correct_abstain"]
            md_lines.append(f"| {thr:.1f} | {ct['coverage']*100:.1f}% ({ct['answered']}/{ct['n']}) | {ct['precision_at_coverage']*100:.1f}% | {ct['correct_lost']}/{ct['correct_at_0']} ({ct['correct_lost_pct']*100:.1f}%) | {ut['correct_abstention_rate']*100:.1f}% | {ut['false_citation_rate']*100:.1f}% | {score} |")
    md_lines.append("")
    md_lines.append(f"**Suggestion (maximizing retained + abstention, truncated mode):** threshold **{best_thr}** (score {best_score} = retained {in_truncated_thr[str(best_thr)]['correct_retained']} + abstain {unseen_thr[str(best_thr)]['correct_abstain']}) - *suggestion only, not tuned* . Knowledge mode best: **{best_thr_k}** (score {best_score_k}).")
    md_lines.append("")
    md_lines.append("## Caveats")
    md_lines.append("")
    md_lines.append("- **Dataset:** Linux kernel CVEs from `Linux_kernel_clean_data_top10_CWEs.json` (top-10 CWEs, 2740 entries -> 1325 unique CVE). Covers kernel-specific weakness classes (CWE-416, CWE-476, etc.), not general vulns.")
    md_lines.append("- **Function-level code was not used:** Evaluation uses only `cve_id`, `cwe`, `cve_description` and `vulnerability knowledge` text; `code_before_change`, `code_after_change`, `patch`, `function_modified_lines` were ignored per task, so this does NOT measure code-level vulnerability detection.")
    md_lines.append("- **Retrieval vs detection:** This measures retrieval and abstention accuracy (can we retrieve the right CVE entry from its description/knowledge), not vulnerability-detection accuracy. It is **NOT comparable to Vul-RAG's reported numbers** (which evaluate LLM-based vulnerable vs patched code classification).")
    md_lines.append("- **Demo CVEs not in dataset:** The demo CVEs used elsewhere (`CVE-2017-0143` EternalBlue/SMBv3, `CVE-2011-2523` vsftpd backdoor, `CVE-2014-0160` Heartbleed, etc.) are **not in this Linux kernel dataset** (verified: overlap check shows kernel CVEs are `CVE-2006-3635` etc.; demo synthetic KB at `data/knowledge_base/synthetic_cve_kb.json` contains only 20 synthetic entries). Results here do not reflect performance on those demo vulns.")
    md_lines.append("- **CveStore is exact-ID lookup with no threshold; this evaluates a TF-IDF retriever mirroring CisIndex.** `CveStore` in `src/retrieval.py:46` is `dict` key lookup (`lookup(cve_id)`) with no vectorization, no `similarity_score`, no `top_k`, no abstention threshold. This eval builds a *new* TF-IDF index (`TfidfVectorizer(stop_words='english') + cosine_similarity`) over the temp KB text to mirror `CisIndex.search` logic for retrieval simulation.")
    md_lines.append("- **Assumptions:** `cve_id` is the join key (`CVE_id` in knowledge == `cve_id` in dataset); `cwe` primary is first `CWE-xxx` in list; truncated = first 50% words; knowledge query = concatenated `purpose`+`function`+`analysis`+`solution`+`vulnerability_behavior` fields; TF-IDF retrieval mirrors `CisIndex` logic but without `service_tags` filtering (CVE text only); thresholds sweep is around implicit `0.0` (no abstention) in `retrieval.py`.")
    md_lines.append("- **No LLM/network calls:** All retrieval is local TF-IDF (`sklearn`) over temp KB at `eval/results/tmp_vulrag_kb.json` in `CveStore` schema; real KB `data/knowledge_base/synthetic_cve_kb.json` unchanged.")
    md_lines.append("")

    out_md.write_text("\n".join(md_lines), encoding="utf-8")
    print(f"Wrote {out_md}")

    print("\n" + "\n".join(md_lines))

    # Show git status (repo may not be git - fallback to file checks)
    print("\n=== GIT STATUS ===")
    import subprocess
    for cwd in [str(ROOT), str(repo)]:
        try:
            result = subprocess.run(["git", "status", "--porcelain"], cwd=cwd, capture_output=True, text=True, timeout=5)
            print(f"git status in {cwd}:")
            print(result.stdout if result.stdout else "(clean)")
            if result.stderr:
                print(result.stderr)
        except Exception as e:
            print(f"git status failed in {cwd}: {e}")
    # Also show protected files status
    print("\nProtected files check (should be unchanged):")
    for p in [ROOT / "data" / "knowledge_base" / "synthetic_cve_kb.json", ROOT / "demo_dashboard.html", ROOT / "benchmark_exhibit.html" if (ROOT / "benchmark_exhibit.html").exists() else None, ROOT / "src" / "retrieval.py"]:
        if p and p.exists():
            print(f"  {p.relative_to(ROOT)} exists, mtime {p.stat().st_mtime}")
        elif p:
            print(f"  {p.relative_to(ROOT)} NOT FOUND (expected if not in repo)")

if __name__ == "__main__":
    evaluate()
