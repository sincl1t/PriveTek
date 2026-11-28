"""Two fixed synthetic HIBP accounts only; no subscription or user identifiers."""
from pathlib import Path
import sys,json,time
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import hibp_client
CASES=(('account-exists@hibp-integration-tests.com','found'),('not-active-breach@hibp-integration-tests.com','not_found'))
if __name__=='__main__':
    results=[]
    for i,(email,expected) in enumerate(CASES):
        if i:time.sleep(7)
        rows,check=hibp_client.lookup(email,api_key='0'*32)
        results.append(dict(synthetic=True,status=check['status'],expected=expected,matched=check['status']==expected,breach_count=len(rows or [])))
    print(json.dumps(results))
    raise SystemExit(0 if all(x['matched'] for x in results) else 1)
