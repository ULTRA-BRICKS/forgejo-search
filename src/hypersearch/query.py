from __future__ import annotations

import re
import shlex
from dataclasses import dataclass

_FIELDS = {
    "repo",
    "owner",
    "path",
    "lang",
    "type",
    "symbol",
    "def",
    "ref",
    "ast",
    "text",
}
_IDENT = re.compile(r"^[A-Za-z_$][\w$]*(?:::[A-Za-z_$][\w$]*)*(?:\.[A-Za-z_$][\w$]*)?$")
_FILEISH = re.compile(r"(?:^|/)[^/\s]+\.[A-Za-z0-9]{1,12}$")
_NATURAL_DEF = re.compile(
    r"^(?:function|fn|def|class|interface|struct|type|enum)\s+"
    r"([A-Za-z_$][\w$]*)$",
    re.IGNORECASE,
)
_NATURAL_REF = re.compile(
    r"^(?:ref|refs|reference|references|uses?|usages?)\s+"
    r"([A-Za-z_$][\w$]*)$",
    re.IGNORECASE,
)
_NATURAL_FILE = re.compile(r"^(?:file|filename)\s+(.+)$", re.IGNORECASE)
# Automatic AST refinement is intentionally limited to structural punctuation.
# Bare words such as "class" or "function" stay on the fast text path; callers
# can always force AST matching with ast:<pattern> or type:ast.
_SYNTAX = re.compile(r"\([^)]*\)|\{[^}]*\}|=>|->")
_CODE_TOKEN = re.compile(
    r"[A-Za-z_$][\w$]*|\d+(?:\.\d+)?|==={0,1}|!==?|=>|->|::|&&|\|\||"
    r"[+*/%<>]=?|[-!&|^~]=?|[()[\]{}.,:;?]"
)


@dataclass(frozen=True)
class SearchQuery:
    raw: str
    text: str = ""
    repo: str | None = None
    owner: str | None = None
    path: str | None = None
    lang: str | None = None
    mode: str = "auto"
    symbol: str | None = None
    symbol_role: str | None = None

    @property
    def ast_candidate(self) -> bool:
        return self.mode == "ast" or (
            self.mode == "auto" and bool(_SYNTAX.search(self.text))
        )

    @property
    def file_candidate(self) -> bool:
        return self.mode == "file" or (
            self.mode == "auto" and bool(_FILEISH.search(self.text))
        )

    @property
    def symbol_candidate(self) -> bool:
        return self.mode == "symbol" or (
            self.mode == "auto" and bool(_IDENT.fullmatch(self.text.strip()))
        )


def _split(raw: str) -> list[str]:
    try:
        return shlex.split(raw, posix=True)
    except ValueError:
        return raw.split()


def parse_query(raw: str) -> SearchQuery:
    values: dict[str, str] = {}
    terms: list[str] = []
    for token in _split(raw.strip()):
        key, sep, value = token.partition(":")
        if sep and key.lower() in _FIELDS and value:
            values[key.lower()] = value
        else:
            terms.append(token)

    mode = values.get("type", "auto").lower()
    symbol = values.get("symbol")
    symbol_role = None
    if "def" in values:
        symbol, symbol_role, mode = values["def"], "definition", "symbol"
    elif "ref" in values:
        symbol, symbol_role, mode = values["ref"], "reference", "symbol"
    elif symbol:
        mode = "symbol"
    if "ast" in values:
        terms.append(values["ast"])
        mode = "ast"
    if "text" in values:
        terms.append(values["text"])
        mode = "text"
    if mode == "code":
        mode = "text"
    if mode not in {"auto", "text", "file", "symbol", "ast"}:
        mode = "auto"
    text = " ".join(terms).strip()
    if (
        mode == "auto"
        and symbol is None
        and "ast" not in values
        and "text" not in values
    ):
        if match := _NATURAL_DEF.fullmatch(text):
            symbol = match.group(1)
            symbol_role = "definition"
            mode = "symbol"
            text = symbol
        elif match := _NATURAL_REF.fullmatch(text):
            symbol = match.group(1)
            symbol_role = "reference"
            mode = "symbol"
            text = symbol
        elif match := _NATURAL_FILE.fullmatch(text):
            mode = "file"
            text = match.group(1).strip()
    if not text and symbol_role == "reference":
        text = symbol or ""
    return SearchQuery(
        raw=raw,
        text=text,
        repo=values.get("repo"),
        owner=values.get("owner"),
        path=values.get("path"),
        lang=values.get("lang"),
        mode=mode,
        symbol=symbol,
        symbol_role=symbol_role,
    )


def code_tokens(value: str) -> list[str]:
    return [m.group(0) for m in _CODE_TOKEN.finditer(value)]


def structural_signature(value: str) -> str:
    return " ".join(code_tokens(value))


def lexical_terms(value: str) -> list[str]:
    return re.findall(r"[\w$.-]+", value, flags=re.UNICODE)
