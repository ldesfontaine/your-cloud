import ast
from html.parser import HTMLParser
from pathlib import Path
import re
import unittest


SOURCE_ROOT = Path(__file__).parents[1] / "src" / "your_cloud_console"
GENERATED = {SOURCE_ROOT / "protocol" / "telemetrie_pb2.py"}
REPOSITORY = Path(__file__).parents[2]
DOCUMENTS = (
    REPOSITORY / "README.md",
    REPOSITORY / "console" / "README.md",
    REPOSITORY / "daemon" / "README.md",
    REPOSITORY / "coordinateur" / "README.md",
    REPOSITORY / "docs" / "GUIDE-DU-BATISSEUR.md",
    REPOSITORY / "docs" / "guide-du-batisseur.html",
    REPOSITORY / "docs" / "ANATOMIE-DU-PROJET.md",
    REPOSITORY / "docs" / "anatomie-du-projet.html",
)


class LinkParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.hrefs: list[str] = []
        self.ids: set[str] = set()

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = dict(attrs)
        if attributes.get("id"):
            self.ids.add(attributes["id"] or "")
        if tag == "a" and attributes.get("href"):
            self.hrefs.append(attributes["href"] or "")


class DocumentationTests(unittest.TestCase):
    def test_modules_and_public_api_have_short_docstrings(self):
        missing: list[str] = []
        for path in sorted(SOURCE_ROOT.rglob("*.py")):
            if path in GENERATED:
                continue
            module = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            relative = path.relative_to(SOURCE_ROOT)
            if not ast.get_docstring(module):
                missing.append(f"{relative}:module")
            for node in module.body:
                if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
                    if not node.name.startswith("_") and not ast.get_docstring(node):
                        missing.append(f"{relative}:{node.name}")
                if isinstance(node, ast.ClassDef):
                    for member in node.body:
                        if isinstance(member, (ast.FunctionDef, ast.AsyncFunctionDef)):
                            if not member.name.startswith("_") and not ast.get_docstring(member):
                                missing.append(f"{relative}:{node.name}.{member.name}")
        self.assertEqual(missing, [], "API sans docstring : " + ", ".join(missing))

    def test_guides_have_valid_local_links_and_interactive_structure(self):
        missing: list[str] = []
        for path in DOCUMENTS:
            content = path.read_text(encoding="utf-8")
            links = re.findall(r"\]\(([^)]+)\)", content)
            if path.suffix == ".html":
                parser = LinkParser()
                parser.feed(content)
                links.extend(parser.hrefs)
                if path.name == "anatomie-du-projet.html":
                    self.assertTrue(
                        {"flow-explorer", "flow-view", "diagram-desc"} <= parser.ids
                    )
                    self.assertIn("prefers-reduced-motion", content)
                    self.assertIn("@media print", content)
                    self.assertNotRegex(content, r"(?:src|href)=\"https?://")
            for link in links:
                target = link.split("#", 1)[0]
                if not target or target.startswith(("http://", "https://", "mailto:")):
                    continue
                if not (path.parent / target).resolve().exists():
                    missing.append(f"{path.relative_to(REPOSITORY)} -> {target}")
        self.assertEqual(missing, [], "Liens locaux absents : " + ", ".join(missing))


if __name__ == "__main__":
    unittest.main()
