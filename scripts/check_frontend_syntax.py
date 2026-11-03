"""Syntax-check inline JavaScript shipped in the customer-facing HTML applications."""

from html.parser import HTMLParser
from pathlib import Path
import shutil
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]
HTML_FILES = (
    "customer_portal.html",
    "admin_portal.html",
    "agency_portal.html",
    "marketing.html",
)


class InlineScriptParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=False)
        self.scripts = []
        self._capture = False
        self._parts = []

    def handle_starttag(self, tag, attrs):
        if tag.lower() != "script":
            return
        attributes = dict(attrs)
        script_type = (attributes.get("type") or "").strip().lower()
        if "src" in attributes or script_type not in {"", "text/javascript", "application/javascript"}:
            self._capture = False
            return
        self._capture = True
        self._parts = []

    def handle_data(self, data):
        if self._capture:
            self._parts.append(data)

    def handle_endtag(self, tag):
        if tag.lower() == "script" and self._capture:
            self.scripts.append("".join(self._parts))
            self._parts = []
            self._capture = False


def main():
    node = shutil.which("node")
    if not node:
        raise SystemExit("Node.js is required to syntax-check inline frontend scripts.")

    checked = 0
    with tempfile.TemporaryDirectory(prefix="eaa-js-check-") as temp_dir:
        for relative_path in HTML_FILES:
            path = ROOT / relative_path
            if not path.exists():
                continue
            parser = InlineScriptParser()
            parser.feed(path.read_text(encoding="utf-8"))
            for index, source in enumerate(parser.scripts):
                if not source.strip():
                    continue
                script_path = Path(temp_dir) / f"{path.stem}-{index}.js"
                script_path.write_text(source, encoding="utf-8")
                subprocess.run([node, "--check", str(script_path)], check=True)
                checked += 1

    print(f"Syntax-checked {checked} inline JavaScript block(s).")


if __name__ == "__main__":
    main()
