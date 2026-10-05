"""promptshield command line."""
from __future__ import annotations

import argparse
import json
import sys

from .corpus import generate
from .guard import PromptGuard, train_classifier

MARK = {"block": "BLOCK", "flag": "FLAG ", "allow": "ALLOW"}


def evaluate(n: int = 2000) -> dict:
    from sklearn.metrics import precision_recall_fscore_support

    guard = PromptGuard(model=train_classifier(3000, seed=1))
    texts, labels = generate(n, seed=99)
    pred = [int(guard.scan(t).verdict != "allow") for t in texts]
    p, r, f, _ = precision_recall_fscore_support(labels, pred, average="binary")
    fp = sum(1 for y, q in zip(labels, pred) if q and not y) / max(1, labels.count(0))
    return {"precision": p, "recall": r, "f1": f, "false_positive_rate": fp, "n": n}


def evaluate_holdout(guard: PromptGuard | None = None) -> dict:
    """80 hand-written prompts that share no templates with the training corpus."""
    from importlib.resources import files

    guard = guard or PromptGuard()
    rows = [json.loads(line) for line in files("promptshield").joinpath("data/holdout.jsonl")
            .read_text(encoding="utf-8").splitlines() if line.strip()]
    tp = fp = fn = tn = 0
    for row in rows:
        flagged = guard.scan(row["text"]).verdict != "allow"
        tp += flagged and row["label"] == 1
        fp += flagged and row["label"] == 0
        fn += (not flagged) and row["label"] == 1
        tn += (not flagged) and row["label"] == 0
    return {"recall": tp / (tp + fn), "precision": tp / (tp + fp), "false_positive_rate": fp / (fp + tn),
            "n": len(rows)}


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(prog="promptshield", description="Prompt-injection firewall")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan", help="scan text (argument or stdin)")
    s.add_argument("text", nargs="?")
    s.add_argument("--document", action="store_true", help="treat as retrieved content (stricter)")
    s.add_argument("--json", action="store_true")
    sub.add_parser("evaluate", help="precision/recall on a held-out generated set")
    sv = sub.add_parser("serve")
    sv.add_argument("--port", type=int, default=8000)
    a = ap.parse_args(argv)

    if a.cmd == "scan":
        text = a.text if a.text is not None else sys.stdin.read()
        r = PromptGuard().scan(text, "document" if a.document else "user")
        if a.json:
            print(json.dumps(r.as_dict()))
        else:
            print(f"{MARK[r.verdict]}  risk={r.risk:.2f}  ml={r.ml_probability:.2f}  {', '.join(r.categories) or '-'}")
            for h in r.hits:
                print(f"   - {h.signature:<18} ...{h.excerpt}...")
        sys.exit(1 if r.verdict == "block" else 0)
    elif a.cmd == "evaluate":
        for title, res in (("templated test set", evaluate()), ("hand-written hold-out set", evaluate_holdout())):
            print(f"== {title}")
            for k, v in res.items():
                print(f"  {k:<20} {v:.4f}" if isinstance(v, float) else f"  {k:<20} {v}")
    else:
        import uvicorn

        uvicorn.run("promptshield.api:app", host="127.0.0.1", port=a.port)


if __name__ == "__main__":
    main()
