import re
import sys
from pathlib import Path

TOKEN = re.compile(
    r'//[^\n]*|/\*[\s\S]*?\*/|'
    r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|'
    r'[A-Za-z_][A-Za-z_0-9]*|[^\s]'
)
TYPE_WORDS = {"char", "short", "int", "long"}


def bare_unsigned_lines(source):
    line = 1
    end = 0
    pending = None
    violations = []
    for match in TOKEN.finditer(source):
        line += source[end : match.start()].count("\n")
        token = match.group()
        end = match.end()
        if token.startswith(("//", "/*")) or token[0] in "\"'":
            line += token.count("\n")
            continue
        if pending is not None:
            if token not in TYPE_WORDS:
                violations.append(pending)
            pending = None
        if token == "unsigned":
            pending = line
        line += token.count("\n")
    if pending is not None:
        violations.append(pending)
    return violations


failed = False
for name in sys.argv[1:]:
    path = Path(name)
    for line in bare_unsigned_lines(path.read_text(encoding="utf-8")):
        print(f"{path}:{line}: use an explicit type after 'unsigned'")
        failed = True
sys.exit(failed)
