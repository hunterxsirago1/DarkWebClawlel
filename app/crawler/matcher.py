# app/crawler/matcher.py
import re
import hashlib


def compute_hash(content: str) -> str:
    return hashlib.sha256(content.encode()).hexdigest()


class Matcher:
    def __init__(self, watchlist: list[dict]):
        self.watchlist = watchlist
        self.keyword_rules = [(e["id"], e["value"], e["severity"]) for e in watchlist if e["type"] == "keyword"]
        self.regex_rules = [(e["id"], re.compile(e["value"]), e["severity"]) for e in watchlist if e["type"] == "regex"]
        self.hash_rules = {e["id"]: e["value"] for e in watchlist if e["type"] == "hash"}

    def match(self, content: str, source_url: str) -> list[dict]:
        matches = []
        seen_values: set[str] = set()
        seen_watchlist_ids: set[int] = set()

        for watchlist_id, keyword, severity in self.keyword_rules:
            if watchlist_id in seen_watchlist_ids:
                continue
            for match_val in self._find_all_keyword_occurrences(content, keyword):
                if match_val not in seen_values:
                    seen_values.add(match_val)
                    seen_watchlist_ids.add(watchlist_id)
                    matches.append({
                        "watchlist_id": watchlist_id,
                        "matched_value": match_val,
                        "context": self._context(content, match_val),
                        "severity": severity,
                    })
                    break  # one match per keyword rule

        for watchlist_id, regex, severity in self.regex_rules:
            if watchlist_id in seen_watchlist_ids:
                continue
            for match in regex.finditer(content):
                match_val = match.group(0)
                if match_val not in seen_values:
                    seen_values.add(match_val)
                    seen_watchlist_ids.add(watchlist_id)
                    matches.append({
                        "watchlist_id": watchlist_id,
                        "matched_value": match_val,
                        "context": self._context(content, match_val),
                        "severity": severity,
                    })
                    break  # one match per regex rule

        content_hash = compute_hash(content)
        for watchlist_id, hash_value in self.hash_rules.items():
            if watchlist_id in seen_watchlist_ids:
                continue
            if content_hash == hash_value:
                seen_watchlist_ids.add(watchlist_id)
                matches.append({
                    "watchlist_id": watchlist_id,
                    "matched_value": hash_value,
                    "context": "[hash match]",
                    "severity": "high",
                })

        return matches

    def _find_all_keyword_occurrences(self, content: str, keyword: str) -> list[str]:
        results = []
        start = 0
        while True:
            idx = content.lower().find(keyword.lower(), start)
            if idx == -1:
                return results
            start = idx + 1
            candidate = content[idx:idx + len(keyword)]
            if candidate.lower() == keyword.lower():
                results.append(candidate)
                start = idx + 1  # move past to avoid same match overlapping

    def _context(self, content: str, matched_value: str, window: int = 50) -> str:
        idx = content.find(matched_value)
        if idx == -1:
            idx = content.lower().find(matched_value.lower())
        if idx == -1:
            return ""
        start = max(0, idx - window)
        end = min(len(content), idx + len(matched_value) + window)
        return content[start:end]