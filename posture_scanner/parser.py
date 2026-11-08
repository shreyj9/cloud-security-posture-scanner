from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path


RESOURCE_RE = re.compile(r'resource\s+"([^"]+)"\s+"([^"]+)"\s*\{')


@dataclass(frozen=True)
class ResourceBlock:
    resource_type: str
    resource_name: str
    body: str
    file: Path
    start_line: int

    @property
    def id(self) -> str:
        return f"{self.resource_type}.{self.resource_name}"


def _strip_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    text = re.sub(r"(?m)^\s*#.*$", "", text)
    text = re.sub(r"(?m)^\s*//.*$", "", text)
    return text


def extract_resource_blocks(path: Path) -> list[ResourceBlock]:
    raw = path.read_text(encoding="utf-8")
    text = _strip_comments(raw)
    blocks: list[ResourceBlock] = []

    for match in RESOURCE_RE.finditer(text):
        brace_index = text.find("{", match.start())
        depth = 0
        in_string = False
        escaped = False
        end = None

        for i in range(brace_index, len(text)):
            ch = text[i]
            if in_string:
                if escaped:
                    escaped = False
                elif ch == "\\":
                    escaped = True
                elif ch == '"':
                    in_string = False
                continue
            if ch == '"':
                in_string = True
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    end = i + 1
                    break

        if end is None:
            continue

        start_line = text.count("\n", 0, match.start()) + 1
        blocks.append(
            ResourceBlock(
                resource_type=match.group(1),
                resource_name=match.group(2),
                body=text[brace_index + 1 : end - 1],
                file=path,
                start_line=start_line,
            )
        )
    return blocks


def terraform_files(root: Path) -> list[Path]:
    if root.is_file():
        return [root] if root.suffix == ".tf" else []
    return sorted(p for p in root.rglob("*.tf") if ".terraform" not in p.parts)
