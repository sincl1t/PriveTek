"""Offline policy evaluation on synthetic fixtures; never contacts a model or database."""
import argparse
import json
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from analysis_layer import analyze

def evaluate():
    cases=json.loads((Path(__file__).resolve().parents[1]/'tests/fixtures/analysis_cases.json').read_text())
    rows=[]
    for case in cases:
        actual={key:value for key,value in analyze(case['data'])['priorities'].items() if value}
        rows.append(dict(name=case['name'],expected=case['expected'],actual=actual,passed=actual==case['expected']))
    return dict(passed=sum(row['passed'] for row in rows),total=len(rows),cases=rows,
                limitation='Synthetic rule-policy checks, not live-model quality or population precision/recall.')

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--output',required=True);args=parser.parse_args()
    result=evaluate();Path(args.output).write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({k:v for k,v in result.items() if k!='cases'}))
    raise SystemExit(0 if result['passed']==result['total'] else 1)
