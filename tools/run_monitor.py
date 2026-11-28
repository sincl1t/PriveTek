"""Daily cron entry point: stdlib only, fixed endpoint, 600s process ceiling, no retries."""
import json
import os
import signal
import sys
import time
import urllib.request

URL='https://privetek.onrender.com/api/internal/monitor/tick'


def main(check=False):
    token=os.environ.get('MONITOR_RUNNER_TOKEN','')
    if len(token)<32:raise RuntimeError('Runner credential missing')
    if check:
        class NoRedirectCheck(urllib.request.HTTPRedirectHandler):
            def redirect_request(self,*args,**kwargs):return None
        request=urllib.request.Request(URL.rsplit('/',1)[0]+'/status',headers={'Authorization':'Bearer '+token})
        with urllib.request.build_opener(NoRedirectCheck()).open(request,timeout=15) as response:
            content=response.read(16385)
            if len(content)>16384:raise RuntimeError('Unexpected status response')
            status=json.loads(content)
        print(json.dumps({'ready':status.get('ready') is True,'pilot_ends_at':status.get('pilot_ends_at'),'read_only':True}))
        if status.get('ready') is not True:raise RuntimeError('Monitor is not ready')
        return
    signal.signal(signal.SIGALRM,lambda *_:sys.exit('Monitor runner time limit'))
    signal.alarm(600);deadline=time.monotonic()+590;processed=0
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self,*args,**kwargs):return None
    opener=urllib.request.build_opener(NoRedirect())
    for _ in range(25):
        remaining=deadline-time.monotonic()
        if remaining<10:break
        request=urllib.request.Request(URL,data=b'{}',method='POST',headers={'Content-Type':'application/json','Authorization':'Bearer '+token})
        with opener.open(request,timeout=min(240,remaining)) as response:
            content=response.read(16385)
            if len(content)>16384:raise RuntimeError('Unexpected runner response')
            outcome=json.loads(content)
        if outcome.get('operation') in ('idle','busy'):break
        if outcome.get('operation') not in ('scan','notification'):raise RuntimeError('Unexpected runner operation')
        processed+=1
    print(json.dumps({'operations':processed}));signal.alarm(0)


if __name__=='__main__':
    import argparse
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--check',action='store_true');args=parser.parse_args()
    try:main(check=args.check)
    except Exception:
        print('Monitor runner failed; inspect protected application status',file=sys.stderr)
        sys.exit(1)
