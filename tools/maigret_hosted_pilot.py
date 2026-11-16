"""Fixed public controls for an isolated Maigret comparison."""
import asyncio
import json
import logging
from datetime import datetime, timezone
from importlib.metadata import version
from pathlib import Path
from time import perf_counter

import aiohttp
import maigret as package
from maigret.checking import maigret
from maigret.sites import MaigretDatabase

POSITIVES = {
    'Bluesky': ('shamerli', 'govtrack', 'bellingcat'),
    'OpenStreetMap': ('blue', 'Firefishy', 'TomH'),
    'RubyGems': ('blue', 'tenderlove', 'indirect'),
}
NEGATIVES = ('pvtkm6q3z8d2', 'pvtk7k4n2x9s', 'pvtkq7m4z8n2x6')
BSKY_API = 'https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile'


async def run():
    db = MaigretDatabase()
    db.load_from_path(str(Path(package.__file__).parent / 'resources' / 'data.json'))
    logger = logging.getLogger('pilot')
    logger.setLevel(logging.CRITICAL)
    results = []
    for site, positives in POSITIVES.items():
        controls = [(name, 'CLAIMED') for name in positives]
        controls.extend((name, 'AVAILABLE') for name in NEGATIVES)
        for handle, expected in controls:
            started = perf_counter()
            checked = await maigret(handle, {site: db.sites_dict[site]}, logger,
                                    timeout=7, max_connections=1, no_progressbar=True,
                                    is_parsing_enabled=False, is_enrich_enabled=False,
                                    check_domains=False, retries=0)
            result = checked[site]
            status = result.get('status')
            results.append(dict(site=site, handle=handle, expected=expected,
                                status=status.status.name if status else 'UNKNOWN',
                                http=result.get('http_status'),
                                elapsed_ms=round(1000 * (perf_counter() - started))))
            await asyncio.sleep(0.5)
    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=7)) as client:
        try:
            async with client.get(BSKY_API, params={'actor': 'bsky.app'}, allow_redirects=False) as response:
                payload = await response.json() if response.status == 200 else {}
                domain_control = {'http': response.status, 'exact': payload.get('handle') == 'bsky.app'}
        except (aiohttp.ClientError, TimeoutError):
            domain_control = {'http': None, 'exact': False}
    bluesky_url = db.sites_dict['Bluesky'].url_probe
    return dict(timestamp=datetime.now(timezone.utc).isoformat(), maigret=version('maigret'),
                results=results, bluesky_domain_control=domain_control,
                bluesky_maigret_appends_bsky_social='.bsky.social' in bluesky_url)


async def diagnose():
    username = 'sincl1t'
    db = MaigretDatabase().load_from_path(str(Path(package.__file__).parent / 'resources' / 'data.json'))
    names = ('Bluesky', 'OpenStreetMap', 'RubyGems')
    log = logging.getLogger('fixed-control')
    log.setLevel(logging.CRITICAL)
    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=8),
                                     headers={'User-Agent': 'PriveTek/2.0'}) as client:
        async def direct(name, url):
            try:
                async with client.get(url, allow_redirects=False) as r:
                    await r.read()
                    return dict(source=name, http=r.status,
                                rate_remaining=r.headers.get('x-ratelimit-remaining'))
            except Exception as error:
                return dict(source=name, error=type(error).__name__)
        async def combined():
            try:
                rows = await asyncio.wait_for(maigret(username, {n: db.sites_dict[n] for n in names}, log,
                          timeout=8, max_connections=3, no_progressbar=True, retries=0,
                          is_parsing_enabled=False, is_enrich_enabled=False, check_domains=False), 12)
                return {name: {'status': rows[name]['status'].status.name, 'http': rows[name].get('http_status')}
                        for name in names}
            except Exception as error:
                return {'error': type(error).__name__}
        samples = {'GitHub':'https://api.github.com/users/' + username}
        samples.update({n:(db.sites_dict[n].url_probe or db.sites_dict[n].url).format(username=username) for n in names})
        result = await asyncio.gather(combined(), *(direct(n, u) for n,u in samples.items()))
    return dict(maigret=result[0], direct=result[1], timestamp=datetime.now(timezone.utc).isoformat())


if __name__ == '__main__':
    print(json.dumps(asyncio.run(diagnose()), indent=2))
