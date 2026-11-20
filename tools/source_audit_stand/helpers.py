"""The existing stand's TLS/mail helpers, with container-local artifact storage."""
from datetime import datetime, timedelta, timezone
import ipaddress
import json
import os
from pathlib import Path
import sys
import threading

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
STAND = Path(os.getenv('STAND_ARTIFACTS', '/artifacts'))
outbox = []
trace_context = threading.local()
trace_lock = threading.Lock()


def trace(stage, **fields):
    """Trace stand stages; authentication payloads and mail contents stay private."""
    job = getattr(trace_context, 'job_id', '-')
    details = ' | '.join(f'{key}={value}' for key, value in fields.items())
    with trace_lock:
        print(f'TRACE | job={job} | {stage}' + (' | ' + details if details else ''), flush=True)


def expect(response, status):
    assert response.status_code == status, (response.request.url.path, response.status_code)
    return response


def fixture(request):
    # Only mail is imitated. Live lookups use SourceTransport and product adapters.
    if request.url.host == 'api.brevo.com':
        outbox.append(json.loads(request.content))
        return httpx.Response(201, json={'messageId': 'fixture'})
    raise httpx.RequestError('Only local mail simulation is enabled on this transport', request=request)


def tls_paths():
    # Match the old stand: a self-signed certificate for 127.0.0.1.
    directory = Path('/tmp/privetek-source-audit-tls')
    directory.mkdir(parents=True, exist_ok=True)
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, '127.0.0.1')])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]), False)
            .sign(key, hashes.SHA256()))
    cert_path, key_path = directory / 'cert.pem', directory / 'tls-key.pem'
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                         serialization.NoEncryption()))
    key_path.chmod(0o600)
    STAND.mkdir(parents=True, exist_ok=True)
    return str(cert_path), str(key_path)
