"""Fixed, bounded static macro extraction subprocess; document bytes arrive on stdin."""
import resource
import sys

resource.setrlimit(resource.RLIMIT_CPU, (12, 12))
resource.setrlimit(resource.RLIMIT_AS, (512 * 1024 * 1024, 512 * 1024 * 1024))
from oletools.olevba import VBA_Parser

data = sys.stdin.buffer.read(2_000_001)
if len(data) > 2_000_000:
    raise ValueError('Document too large')
parser = VBA_Parser('evidence.xlsm', data=data)
remaining = 12000
try:
    found = False
    for _, stream, name, code in parser.extract_macros():
        found = True
        text = f'VBA stream: {stream}; module: {name}\n{code}\n'
        sys.stdout.write(text[:remaining])
        remaining -= min(len(text), remaining)
        if remaining == 0:
            break
    if not found:
        print('No VBA source found. This does not establish that the document is safe.')
finally:
    parser.close()
