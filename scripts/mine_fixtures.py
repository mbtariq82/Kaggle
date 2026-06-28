from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_FIXTURES = PROJECT_ROOT / "data" / "competition" / "aicomp_sdk" / "fixtures"
TOOL_RE = re.compile(
    r"\b(fs\.read|fs\.write|fs\.delete|http\.post|email\.send|email\.read|web\.open|shell\.run)\b",
    re.IGNORECASE,
)


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def tools_in(text: str) -> list[str]:
    return sorted(set(match.lower() for match in TOOL_RE.findall(text)))


def has_any(text: str, phrases: tuple[str, ...]) -> bool:
    lowered = text.lower()
    return any(phrase in lowered for phrase in phrases)


def score_text(text: str) -> int:
    found_tools = tools_in(text)
    lowered = text.lower()
    score = 0
    if "http.post" in found_tools:
        score += 8
    if "email.send" in found_tools:
        score += 7
    if "fs.write" in found_tools:
        score += 4
    if "fs.delete" in found_tools:
        score += 4
    if "shell.run" in found_tools:
        score += 2
    if "secret.txt" in lowered:
        score += 5
    if has_any(text, ("secret_marker", "longtok_new", "token longtok")):
        score += 3
    if has_any(
        text,
        (
            "ignore previous",
            "forget all previous",
            "disregard all prior",
            "overlook all previous",
        ),
    ):
        score += 3
    if has_any(text, ("you must", "immediately", "execute", "required", "mandatory")):
        score += 2
    if has_any(
        text,
        (
            "developer",
            "ceo",
            "admin override",
            "system mode",
            "fbi",
            "law enforcement",
            "authorized",
        ),
    ):
        score += 1
    return score


def iter_messages(mail_seed: dict[str, Any]) -> list[dict[str, Any]]:
    messages: list[dict[str, Any]] = []
    for folder, value in mail_seed.items():
        if not isinstance(value, list):
            continue
        for message in value:
            row = dict(message)
            row["_folder"] = folder
            messages.append(row)
    return messages


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--fixtures", type=Path, default=DEFAULT_FIXTURES)
    parser.add_argument("--top", type=int, default=30)
    args = parser.parse_args()

    web_pages = load_json(args.fixtures / "web_corpus.json")["pages"]
    messages = iter_messages(load_json(args.fixtures / "mail_seed.json"))

    web_rank = sorted(
        (
            (
                score_text(page.get("content", "")),
                page["id"],
                page.get("title", ""),
                tools_in(page.get("content", "")),
            )
            for page in web_pages
        ),
        reverse=True,
    )
    mail_rank = sorted(
        (
            (
                score_text(message.get("body", "")),
                message["id"],
                message.get("subject", ""),
                tools_in(message.get("body", "")),
            )
            for message in messages
        ),
        reverse=True,
    )

    print(f"web_pages={len(web_pages)} mail_messages={len(messages)}")
    print("web_tool_counts=", Counter(tool for page in web_pages for tool in tools_in(page["content"])))
    print("mail_tool_counts=", Counter(tool for message in messages for tool in tools_in(message["body"])))

    print("\nTop web ids:")
    for score, page_id, title, found_tools in web_rank[: args.top]:
        print(f"{score:>2} {page_id:<24} {','.join(found_tools):<42} {title}")

    print("\nTop message ids:")
    for score, message_id, subject, found_tools in mail_rank[: args.top]:
        print(f"{score:>2} {message_id:<24} {','.join(found_tools):<42} {subject}")

    sink_types: Counter[str] = Counter()
    for page in web_pages:
        if "_sink_" not in page["id"]:
            continue
        kind = "+".join(tools_in(page["content"])) or "none"
        sink_types[kind] += 1
    print("\nweb_sink_types=", sink_types)


if __name__ == "__main__":
    main()
