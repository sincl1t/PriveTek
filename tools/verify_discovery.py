"""Fixed public examples only. No production DB, accounts, mail or search submissions."""
import argparse
import json
from pathlib import Path
import sys
import time
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import httpx
import trio
import discovery as d
from report_data import utc_now

FIXTURES = {'Roblox': ['builderman', 'Roblox'], 'Scratch': ['mres', 'griffpatch'], 'Codewars': ['g964', 'jhoffner']}
NEGATIVES = ['pvtkz8q4n2x7r9', 'pvtkq7v9m2k4z8']


async def verify():
    rows = []
    async with httpx.AsyncClient(timeout=12, follow_redirects=False, headers={
        'User-Agent': 'PriveTek/3.0 (+https://github.com/sincl1t/PriveTek)', 'Accept': 'application/json'}) as client:
        for repeat in range(2):
            for index in range(4):
                for source in d.SOURCES:
                    positive = index < 2
                    handle = FIXTURES[source[0]][index] if positive else NEGATIVES[index - 2]
                    started = time.monotonic()
                    check = await d.check(source, handle, client)
                    rows.append(dict(source=source[0], fixture=handle, repeat=repeat + 1,
                                     expected='found' if positive else 'not_found', status=check['status'],
                                     seconds=round(time.monotonic()-started, 3), method=check['method']))
                await trio.sleep(1.05)
    passed = all(row['expected'] == row['status'] for row in rows)
    return dict(checked_at=utc_now(), passed=passed, requests=len(rows), sources=len(d.SOURCES), rows=rows,
                limitation='Fixed public examples and synthetic negative controls, not population precision/recall. No user identifiers, full profiles or DB access.')


if __name__ == '__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--output', required=True);args=parser.parse_args()
    result=trio.run(verify)
    Path(args.output).write_text(json.dumps(result, ensure_ascii=False, indent=2)+'\n')
    print(json.dumps({k:v for k,v in result.items() if k != 'rows'}))
    raise SystemExit(0 if result['passed'] else 1)
