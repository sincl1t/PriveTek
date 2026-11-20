"""Source audit stand: real product UI with live LeakCheck, GitHub and GitLab."""
import argparse
from hashlib import sha256
from io import BytesIO
import logging
import json
import os
from pathlib import Path
import re
import secrets
import socket
import signal
import ssl
import threading
import time
from unittest.mock import patch

import httpx
import psycopg
import uvicorn
from cryptography.fernet import Fernet
from psycopg import sql
from pypdf import PdfReader

from helpers import STAND, expect, fixture, outbox, tls_paths, trace, trace_context
from profiles import PROFILE_SOURCES, SourceTransport, skipped
import audit_log
import public_sources
from report_data import utc_now

# Each account is checked using its own email, including in the PDF snapshot.
CONTROLS = {
    "example@example.com": "found",
    "stage2-health-pvtkz8q4n2x7r9@example.com": "not_found",
}
HASHES = {
    sha256(address.encode()).hexdigest()[:24]: address
    for address in CONTROLS
}
LEAKCHECK_API = "https://leakcheck.io/api/public"
DEMO_PASSWORD = "PriveTek-Audit-2026!"


def register(client, email, password):
    challenge = expect(client.post(
        "/api/account/auth/register", json={"email": email, "password": password}
    ), 200).json()["challenge_id"]
    code, = re.findall(r"\b\d{8}\b", outbox[-1]["textContent"])
    expect(client.post("/api/account/auth/verify", json={"challenge_id": challenge, "code": code}), 200)


def verify_scenario(client, password, scenario, email, usernames, expected_leakcheck, expected_profiles):
    client.cookies.clear()
    expect(client.post('/api/account/auth/login', json={'email': email, 'password': password}), 200)
    csrf = {'X-CSRF-Token': expect(client.get('/api/account/me'), 200).json()['csrf_token']}
    payload = dict(consent=True, username=usernames[0], additional_usernames=usernames[1:])
    job_id = expect(client.post('/api/account/jobs', json=payload, headers=csrf), 202).json()['job_id']
    for _ in range(240):
        jobs = expect(client.get('/api/account/jobs'), 200).json()['items']
        job = next(item for item in jobs if item['id'] == job_id)
        if job['status'] in ('provider_accepted', 'failed', 'delivery_unknown'):
            break
        time.sleep(0.25)
    assert job['status'] == 'provider_accepted' and job['report_available'], job['status']
    url = '/api/account/jobs/' + job_id
    snapshot = expect(client.get(url + '/identity'), 200).json()
    leakcheck, = [r for r in snapshot['coverage']['entries'] if r['source'] == 'LeakCheck']
    profiles = [r for r in snapshot['coverage']['entries'] if r['source'] in PROFILE_SOURCES]
    by_query = {(r['source'], r['query_username']): r for r in profiles}
    content = expect(client.get(url + '/report'), 200).content
    pdf_path = STAND / f'sources-{scenario}.pdf'
    pdf_path.write_bytes(content)
    report = PdfReader(BytesIO(content))
    text = ' '.join(' '.join(page.extract_text() or '' for page in report.pages).split())
    section = text.split('Публичные профили по username', 1)[1]
    email_node, = [item for item in snapshot['identifiers'] if item['kind'] == 'email']
    local, domain = email.split('@')
    checks = {
        'account_email_matches': email_node['title'] == local[0] + '***@' + domain,
        'leakcheck_status': leakcheck['status'] == expected_leakcheck,
        'leakcheck_pdf_label': f"LeakCheck: {audit_log.LABELS.get(leakcheck['status'])}" in text,
        'profile_checks_count': len(profiles) == 2 * len(usernames),
        'profile_statuses': all(by_query.get(key, {}).get('status') == expected
                                for key, expected in expected_profiles.items()),
        'all_profile_requests_completed': all(r['status'] in ('found', 'not_found') for r in profiles),
        'profile_pdf_labels': all(f"{r['source']}: {audit_log.LABELS.get(r['status'])}" in section for r in profiles),
        'pdf_query_usernames': all('Проверялся username: ' + handle in section for handle in usernames),
        'no_automatic_ownership': not snapshot['owner_group'] and all(
            item['decision'] == 'unreviewed' for item in snapshot['findings']),
    }
    for (source, handle), expected in expected_profiles.items():
        if expected == 'found':
            home = 'https://github.com/' if source == 'GitHub' else 'https://gitlab.com/'
            profile_url = home + handle.lower()
            checks[source + '_canonical_link'] = profile_url in section and any(
                item['source'] == source and item['profile_url'] == profile_url
                for item in snapshot['findings'])
    if scenario == 'absent':
        checks['no_profile_findings'] = not [r for r in snapshot['findings'] if r['kind'] == 'username']
        checks['no_found_profile_pdf_labels'] = all(f'{name}: Найдены сведения' not in section for name in PROFILE_SOURCES)
    return dict(scenario=scenario, mode='live', leakcheck_status=leakcheck['status'],
               profiles=profiles, checks=checks, passed=all(checks.values()),
               pdf=pdf_path.name, pdf_pages=len(report.pages))


def verify_reports(client, password):
    scenarios = [
        ('known', 'example@example.com', ['octocat', 'sytses'], 'found',
         {('GitHub', 'octocat'): 'found', ('GitLab', 'sytses'): 'found'}),
        ('absent', 'stage2-health-pvtkz8q4n2x7r9@example.com', ['pvtkz8q4n2x7r9'], 'not_found',
         {('GitHub', 'pvtkz8q4n2x7r9'): 'not_found', ('GitLab', 'pvtkz8q4n2x7r9'): 'not_found'}),
        ('case', 'stage2-health-pvtkz8q4n2x7r9@example.com', ['Octocat', 'Sytses'], 'not_found',
         {('GitHub', 'Octocat'): 'found', ('GitLab', 'Sytses'): 'found'}),
    ]
    titles = {
        'known': 'Известные профили и совпадение по email',
        'absent': 'Контроль без совпадений',
        'case': 'Совпадение username с другим регистром',
    }
    rows = []
    for index, control in enumerate(scenarios, 1):
        scenario = control[0]
        print(f'\n{"=" * 72}\nСЦЕНАРИЙ {index}/{len(scenarios)} · {scenario} · {titles[scenario]}\n'
              f'{"=" * 72}', flush=True)
        try:
            rows.append(verify_scenario(client, password, *control))
        except Exception as error:
            reason = str(error) if isinstance(error, AssertionError) and error.args else type(error).__name__
            rows.append(dict(scenario=scenario, mode='live', passed=False, error=reason))
            # A job may still be running after an API error or timeout.
            break

    complete = len(rows) == len(scenarios)
    passed = complete and all(row['passed'] for row in rows)
    summary = dict(checked_at=utc_now(), complete=complete, passed=passed, rows=rows)
    (STAND / 'verification.json').write_text(json.dumps(summary, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    output = format_verification_summary(rows, list(titles))
    (STAND / 'verification.txt').write_text(output + '\n', encoding='utf-8')
    print(f'\n{output}', flush=True)
    return passed


def format_verification_summary(rows, scenarios):
    passed_count = sum(row['passed'] for row in rows)
    output = ['=' * 72, 'ИТОГИ АВТОМАТИЧЕСКОЙ ПРОВЕРКИ', '=' * 72,
              f'Прошли: {passed_count}/{len(scenarios)} · Ошибки: {len(rows) - passed_count}'
              f' · Не запущены: {len(scenarios) - len(rows)}']
    for row in rows:
        result = 'ПРОЙДЕН' if row['passed'] else 'НЕ ПРОЙДЕН'
        output.extend(['', f"{row['scenario']} — {result}"])
        if 'error' in row:
            output.append(f"  Ошибка выполнения: {row['error']}")
            continue
        output.append(f"  LeakCheck: {row['leakcheck_status']}")
        for source in ('GitHub', 'GitLab'):
            statuses = ', '.join(f"{profile['query_username']} = {profile['status']}"
                                 for profile in row['profiles'] if profile['source'] == source)
            output.append(f"  {source}: {statuses or 'нет результата'}")
        output.append(f"  PDF: {row['pdf']} (страниц: {row['pdf_pages']})")
        failed_checks = [name for name, matched in row['checks'].items() if not matched]
        if failed_checks:
            output.append('  Расхождения: ' + ', '.join(failed_checks))
    for scenario in scenarios[len(rows):]:
        output.extend(['', f'{scenario} — НЕ ЗАПУЩЕН'])
    return '\n'.join(output)


def serve(origin, listener, cert_path, key_path, verify):
    import server
    import osint
    import account_store

    original_search = osint.search
    original_run_checks = osint.run_checks
    original_record = server.job_store.record
    original_pdf = server.pdf_gen.create_report
    original_save = account_store.save_report
    original_reserve = server.guard.reserve
    original_profile_check = public_sources.check_profile

    stages = {
        'accepted': 'Заявка принята', 'searching': 'Начат поиск',
        'generating_report': 'Начата генерация отчёта', 'sending': 'Начата отправка письма',
        'provider_accepted': 'Письмо принято имитатором почты',
        'failed': 'Обработка завершилась ошибкой', 'delivery_unknown': 'Отправка не подтверждена',
    }

    def record(job_id, status, *args, **kwargs):
        trace_context.job_id = job_id
        value = original_record(job_id, status, *args, **kwargs)
        trace(stages.get(status, 'Обновлён статус задания'), status=status)
        return value

    def reserve(*args, **kwargs):
        job_id, duplicate = original_reserve(*args, **kwargs)
        trace_context.job_id = job_id
        trace('Запрос на запуск проверки', duplicate=duplicate)
        if duplicate:
            trace('Повторная заявка: используется существующее задание, новый поиск не запускается')
        return job_id, duplicate

    def search(email=None, phone=None, username=None, additional_usernames=None):
        usernames = [value for value in [username, *(additional_usernames or [])] if value]
        audit_log.begin(email, usernames, phone_supplied=bool(phone))
        trace('Вход в поиск', email=email, usernames=audit_log.compact(usernames), phone=bool(phone))
        try:
            result = original_search(email, phone, username, additional_usernames)
        except Exception as error:
            trace('Ошибка поиска', error_type=type(error).__name__)
            raise
        audit_log.processed(result)
        return result

    async def profile_check(source, username, client):
        if source[0] not in PROFILE_SOURCES:
            return skipped(source)
        return await original_profile_check(source, username, client)

    async def no_discovery(username=None, fixtures=False):
        return [skipped(source) for source in osint.discovery.SOURCES]

    def create_pdf(data, *args, **kwargs):
        trace('Сборка PDF', checks_count=len(data.get('checks', [])))
        path = original_pdf(data, *args, **kwargs)
        trace('PDF создан', bytes=Path(path).stat().st_size)
        if data.get('checks'):
            try:
                text = '\n'.join(page.extract_text() or '' for page in PdfReader(path).pages)
                audit_log.report(text)
            except Exception as error:
                trace('Не удалось прочитать PDF для журнала', error_type=type(error).__name__)
        return path

    def save_report(*args, **kwargs):
        value = original_save(*args, **kwargs)
        trace('Отчёт и карточка сохранены в кабинете')
        return value

    async def stand_checks(adapters, arguments):
        if adapters == [('Amazon', osint.ignorant_amazon)]:
            trace_context.amazon_active = True
            try:
                return await original_run_checks(adapters, arguments)
            finally:
                trace_context.amazon_active = False
        if adapters[0][0] == "Gravatar":
            return [dict(name="Gravatar", status="skipped", reason="Отключено на демостенде.")]
        return [dict(name=name, rateLimit=True, reason="Отключено на демостенде.") for name, _ in adapters]

    runner = uvicorn.Server(uvicorn.Config(server.app, ssl_certfile=cert_path, ssl_keyfile=key_path,
                                         access_log=False, log_config=None))
    def stop(signum, frame):
        runner.should_exit = True

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    logging.getLogger("fontTools").setLevel(logging.WARNING)
    transport = httpx.MockTransport(fixture)
    async_client = httpx.AsyncClient
    context = ssl.create_default_context(cafile=cert_path)

    def routed_async_client(**kwargs):
        return async_client(transport=SourceTransport(amazon=getattr(trace_context, 'amazon_active', False)), **kwargs)

    with httpx.Client(trust_env=False) as live, httpx.Client(transport=transport) as mail:
        def lookup_http(url, **kwargs):
            digest = (kwargs.get("params") or {}).get("check")
            if url != LEAKCHECK_API or digest not in HASHES:
                trace('Живой запрос отклонён: значение вне фиксированных контролей')
                raise httpx.RequestError("Only fixed LeakCheck demo requests can reach the network")
            email = HASHES[digest]
            audit_log.request('LeakCheck', email, 'GET', str(httpx.URL(url, params=kwargs.get('params'))))
            started = time.monotonic()
            try:
                response = live.get(url, **kwargs)
            except httpx.HTTPError as error:
                audit_log.failure('LeakCheck', email, error)
                raise
            audit_log.response('LeakCheck', email, response, round((time.monotonic() - started) * 1000))
            return response

        def send_mail(url, **kwargs):
            payload = kwargs.get('json') or {}
            trace('Имитация почты', attachments_count=len(payload.get('attachment') or []))
            return mail.post(url, **kwargs)

        with patch.object(osint, "run_checks", stand_checks), \
                patch.object(osint, "search", search), \
                patch.object(public_sources, "check_profile", profile_check), \
                patch.object(osint.discovery, "run", no_discovery), \
                patch.object(server.guard, "reserve", reserve), \
                patch.object(server.job_store, "record", record), \
                patch.object(server.pdf_gen, "create_report", create_pdf), \
                patch.object(account_store, "save_report", save_report), \
                patch.object(httpx, "get", lookup_http), \
                patch.object(httpx, "post", send_mail), \
                patch.object(httpx, "AsyncClient", routed_async_client):
            thread = threading.Thread(target=runner.run, kwargs={"sockets": [listener]})
            thread.start()
            try:
                for _ in range(100):
                    if runner.started or not thread.is_alive():
                        break
                    time.sleep(0.05)
                assert runner.started, "Local HTTPS server did not start."
                password = DEMO_PASSWORD
                with httpx.Client(base_url=origin, headers={"Origin": origin},
                                  verify=context, trust_env=False) as client:
                    for email in CONTROLS:
                        register(client, email, password)
                        client.cookies.clear()
                        expect(client.post(
                            "/api/account/auth/login", json={"email": email, "password": password}
                        ), 200)
                        account = expect(client.get("/api/account/me"), 200).json()
                        assert account["email"] == email
                        print(f"LOGIN VERIFIED: {email}", flush=True)
                    client.cookies.clear()
                    Path('/tmp/source-audit-ready').write_text('ready')
                    print(f'\nСТЕНД АУДИТА ИСТОЧНИКОВ ГОТОВ: {origin}/account/login', flush=True)
                    print('Живые источники: LeakCheck, GitHub, GitLab, Amazon по телефону.', flush=True)
                    print('Регистрация не нужна: два тестовых аккаунта уже подготовлены.', flush=True)
                    if verify:
                        return verify_reports(client, password)
                    else:
                        print(f"\nOpen {origin}/account/login", flush=True)
                        for email in CONTROLS:
                            print(f"  Login and audit email: {email}", flush=True)
                        print(f"Password for both audit logins: {password}", flush=True)
                        print('Profile controls: octocat, sytses, pvtkz8q4n2x7r9; case variants: Octocat, Sytses.', flush=True)
                        while not runner.should_exit and thread.is_alive():
                            time.sleep(0.25)
            except KeyboardInterrupt:
                pass
            finally:
                runner.should_exit = True
                thread.join()
    return True


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--verify", action="store_true")
    options = parser.parse_args()
    Path('/tmp/source-audit-ready').unlink(missing_ok=True)
    cert_path, key_path = tls_paths()
    base = os.environ["STAND_DATABASE_BASE"].rstrip("/")
    database = "source_audit_" + secrets.token_hex(4)
    with psycopg.connect(base + "/postgres", autocommit=True) as db:
        db.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(database)))
    try:
        with socket.socket() as listener:
            listener.bind(("0.0.0.0", 8443))
            origin = "https://127.0.0.1:8443"
            os.environ.update(
                DATABASE_URL=f"{base}/{database}", REQUIRE_DATABASE="true",
                ACCOUNTS_ENABLED="true", ACCOUNT_ORIGIN=origin,
                ACCOUNT_SECRET=secrets.token_hex(32), ACCOUNT_REPORT_KEY=Fernet.generate_key().decode(),
                MAIL_PROVIDER="brevo", MAIL_FROM="sender@example.com", BREVO_API_KEY="fixture-only",
                AI_SUMMARY_ENABLED="false", MONITOR_ENABLED="false", HIBP_API_KEY="", RENDER="false",
            )
            if not serve(origin, listener, cert_path, key_path, options.verify):
                raise SystemExit(1)
    finally:
        with psycopg.connect(base + "/postgres", autocommit=True) as db:
            db.execute(sql.SQL("DROP DATABASE {} WITH (FORCE)").format(sql.Identifier(database)))


if __name__ == "__main__":
    main()
