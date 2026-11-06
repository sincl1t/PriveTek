"""Export team-only analytics. Key via environment, never URL or stdout."""
import argparse
import csv
import json
import os
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.error import URLError


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--days', type=int, choices=range(1,91), default=30, metavar='1..90')
    args = parser.parse_args()
    key = os.environ.get('STATUS_API_KEY')
    if not key:
        parser.error('Set STATUS_API_KEY privately in the environment')
    request = Request('https://lk.privetek.ru/api/internal/analytics/summary?days='+str(args.days), headers={'Authorization':'Bearer '+key})
    try:
        with urlopen(request, timeout=30) as response:
            data = json.load(response)
    except (URLError, ValueError):
        parser.exit(1, 'Summary unavailable; check access and service status.\n')
    args.output.mkdir(parents=True, exist_ok=True)
    (args.output/'summary.json').write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding='utf-8')
    for name in ['channels','accounts']:
        rows = data[name]
        with (args.output/(name+'.csv')).open('w',newline='',encoding='utf-8-sig') as handle:
            if rows:
                writer=csv.DictWriter(handle,fieldnames=list(rows[0]));writer.writeheader();writer.writerows(rows)
    print('Summary exported; account identifiers are internal IDs, not contact details.')


if __name__ == '__main__':
    main()
