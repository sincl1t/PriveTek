"""Daily cron entry point: stdlib only, fixed endpoint, 600s process ceiling, no retries."""
import json
import os
import signal
import sys
import time
import urllib.request

URL='https://privetek.onrender.com/api/internal/monitor/tick'


def main():
    token=os.environ.get('MONITOR_RUNNER_TOKEN','')
    if len(token)<32:raise RuntimeError('Runner credential missing')
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
    try:main()
    except Exception:
        print('Monitor runner failed; inspect protected application status',file=sys.stderr)
        sys.exit(1)
