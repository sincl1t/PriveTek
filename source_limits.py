"""Shared pacing for outbound search requests, including redirects."""
import time

import httpx
import trio

import job_store
import search_queue

# Group API and website hosts belonging to the same provider.
DOMAINS = (
    'amazon.com', 'github.com', 'gitlab.com', 'spotify.com', 'gravatar.com',
    'instagram.com', 'haveibeenpwned.com', 'leakcheck.io', 'codeberg.org',
    'huggingface.co', 'dev.to', 'firebaseio.com', 'keybase.io', 'lichess.org',
    'chess.com', 'wikipedia.org', 'discourse.org', 'roblox.com', 'scratch.mit.edu',
    'codewars.com', 'bsky.app', 'openstreetmap.org', 'rubygems.org',
)
INTERVAL = 1.05


def try_acquire(source):
    with job_store.connect() as db:
        return db.execute("""
            INSERT INTO privetek_source_limits (source,next_at)
            VALUES (%s,clock_timestamp()+%s*interval '1 second')
            ON CONFLICT (source) DO UPDATE SET next_at=clock_timestamp()+%s*interval '1 second'
            WHERE privetek_source_limits.next_at <= clock_timestamp()
            RETURNING source
        """, (source, INTERVAL, INTERVAL)).fetchone() is not None


def wait_for_slot(url):
    host = url.host
    source = next((domain for domain in DOMAINS if host == domain or host.endswith('.' + domain)), None)
    if source is not None:
        deadline = time.monotonic() + 3
        try:
            while time.monotonic() < deadline:
                if try_acquire(source):
                    return
                time.sleep(0.15)
        except Exception:
            raise httpx.RequestError('Shared source limiter is unavailable') from None
        raise httpx.RequestError('Shared source limit reached')
    raise httpx.RequestError('Search source domain is not registered')


async def before_request(request):
    await trio.to_thread.run_sync(wait_for_slot, request.url)


def async_options():
    return {'event_hooks': {'request': [before_request]}} if search_queue.enabled() else {}


def sync_options():
    return {'event_hooks': {'request': [lambda request: wait_for_slot(request.url)]}} if search_queue.enabled() else {}


def get(url, **kwargs):
    if not search_queue.enabled():
        return httpx.get(url, **kwargs)
    with httpx.Client(**sync_options()) as client:
        return client.get(url, **kwargs)
