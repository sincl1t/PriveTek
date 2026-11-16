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


if __name__ == '__main__':
    print(json.dumps(asyncio.run(run()), indent=2))
