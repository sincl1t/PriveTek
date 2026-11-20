"""Simulated source-quality audit: email, profiles, and phone.

Only synthetic data and mocked HTTP responses. Product code stays unchanged.
"""
import httpx
import pytest

import leakcheck_client
import osint
import public_sources
from pdf_gen import create_report
from pypdf import PdfReader


@pytest.fixture(autouse=True)
def no_live_network(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("Live network is forbidden in simulated audit tests")

    async def async_forbidden(*args, **kwargs):
        pytest.fail("Live network is forbidden in simulated audit tests")

    monkeypatch.setattr(httpx.HTTPTransport, "handle_request", forbidden)
    monkeypatch.setattr(httpx.AsyncHTTPTransport, "handle_async_request", async_forbidden)


@pytest.mark.parametrize(
    ("response", "expected_status", "expected_group", "expected_label"),
    [
        pytest.param(
            httpx.Response(429, json={"success": False, "error": "Not found"}),
            "unavailable", "Ограничения проверки", "Проверка недоступна",
            id="rate-limit",
        ),
        pytest.param(
            httpx.Response(429, json={"success": False, "error": "Too many requests"}),
            "unavailable", "Ограничения проверки", "Проверка недоступна",
            id="rate-limit-documented",
        ),
        pytest.param(
            httpx.Response(200, json={"success": True, "found": 0}),
            "not_found", "Проверки без находок", "Находок в источнике нет",
            id="no-matches",
        ),
        pytest.param(
            httpx.ReadTimeout("Timed out while reading the response"),
            "unavailable", "Ограничения проверки", "Проверка недоступна",
            id="timeout",
        ),
        pytest.param(
            httpx.Response(200, text="<html>Unexpected page</html>"),
            "unavailable", "Ограничения проверки", "Проверка недоступна",
            id="unexpected-html",
        ),
        pytest.param(
            httpx.Response(
                200,
                json={
                    "success": True,
                    "found": 5,
                    "fields": ["password"],
                    "sources": [
                        {"name": "Synthetic Alpha", "date": "2020-01"},
                        {"name": "Synthetic Beta", "date": "2021-02"},
                    ],
                },
            ),
            "found", "Находки и возможные совпадения", "Найдены сведения",
            id="five-matches-two-sources",
        ),
    ],
)
def test_leakcheck_result_in_pdf(
    monkeypatch, tmp_path, response, expected_status, expected_group, expected_label
):
    from pypdf import PdfReader

    import osint
    from pdf_gen import create_report

    requests = []

    def fake_get(url, **kwargs):
        requests.append(url)
        if isinstance(response, httpx.ReadTimeout):
            raise response
        return response

    async def skip_other_email_checks(adapters, arguments):
        if adapters[0][0] == "Gravatar":
            return [{"name": "Gravatar", "status": "skipped"}]
        return []

    monkeypatch.setattr(leakcheck_client.httpx, "get", fake_get)
    monkeypatch.setattr(leakcheck_client, "_last_request", 0.0)
    monkeypatch.setattr(osint, "run_checks", skip_other_email_checks)
    monkeypatch.setattr(
        osint.hibp_client,
        "lookup",
        lambda email: (
            None,
            {
                "source": "HIBP",
                "kind": "breach",
                "status": "skipped",
                "reason": "HIBP отключён в этом тесте.",
            },
        ),
    )

    results = osint.search(email="reader@example.com")

    assert requests == ["https://leakcheck.io/api/public"]
    leakcheck = next(
        check for check in results["checks"] if check["source"] == "LeakCheck"
    )
    assert leakcheck["status"] == expected_status

    pdf_path = create_report(results, tmp_path)
    extracted_text = " ".join(page.extract_text() or "" for page in PdfReader(pdf_path).pages)
    pdf_text = " ".join(extracted_text.split())
    breach_section = pdf_text.split("Утечки данных по email", 1)[1].split(
        "Регистрации email на сайтах", 1
    )[0]

    source_label = f"LeakCheck: {expected_label}"
    assert source_label in breach_section
    before_label = breach_section.split(source_label, 1)[0]
    assert expected_group in before_label

    if expected_status == "found":
        rows = results["email_breach"]
        expected_rows = [
            ("Synthetic Alpha", "2020-01"),
            ("Synthetic Beta", "2021-02"),
        ]
        assert [(row["name"], row["date"]) for row in rows] == expected_rows
        for name, date in expected_rows:
            assert f"{name} Дата утечки: {date}. Источник сведений: LeakCheck." in breach_section
        assert breach_section.count("Категории во всех совпавших утечках: пароли") == 2
        assert "Записей об утечках: 2." in pdf_text
    else:
        assert results["email_breach"] == ([] if expected_status == "not_found" else None)
        assert "Источник сведений: LeakCheck." not in breach_section
        if expected_status == "unavailable":
            assert "LeakCheck: Находок в источнике нет" not in breach_section


def profile_cases():
    for source in public_sources.SOURCES:
        name = source[0]
        if name not in ("GitHub", "GitLab"):
            continue
        github = name == "GitHub"
        account = {"id": 42, "login": "audit-user", "type": "User"} if github else {
            "id": 42, "username": "audit-user"
        }

        def payload(row):
            return row if github else [row]

        missing_id = {key: value for key, value in account.items() if key != "id"}
        wrong_account = dict(account, **{"login" if github else "username": "audit-user2"})
        miss = httpx.Response(404, json={"message": "Not Found"}) if github else httpx.Response(200, json=[])
        cases = [
            ("exact-match", "audit-user", httpx.Response(200, json=payload(account)), "found"),
            ("case-insensitive", "Audit-User", httpx.Response(200, json=payload(account)), "found"),
            ("no-matches", "audit-user", miss, "not_found"),
            ("similar-username", "audit-user", httpx.Response(200, json=payload(wrong_account)), "unavailable"),
            ("timeout", "audit-user", httpx.ReadTimeout("Synthetic timeout"), "unavailable"),
            ("rate-limit", "audit-user", httpx.Response(429, json={"message": "Too many requests"}), "unavailable"),
            ("rate-limit-with-miss-body", "audit-user", httpx.Response(429, json={"message": "Not Found"} if github else []), "unavailable"),
            ("unexpected-html", "audit-user", httpx.Response(200, text="<html>Challenge</html>"), "unavailable"),
            ("invalid-json", "audit-user", httpx.Response(200, text="{broken"), "unavailable"),
            ("invalid-structure", "audit-user", httpx.Response(200, json={"unexpected": True}), "unavailable"),
            ("missing-id", "audit-user", httpx.Response(200, json=payload(missing_id)), "unavailable"),
            ("boolean-id", "audit-user", httpx.Response(200, json=payload(dict(account, id=True))), "unavailable"),
        ]
        if github:
            cases.append(("organization", "audit-user", httpx.Response(200, json=dict(account, type="Organization")), "unavailable"))
            cases.append(("invalid-username", "audit_user", None, "skipped"))
        else:
            cases.append(("multiple-users", "audit-user", httpx.Response(200, json=[account, wrong_account]), "unavailable"))
        for scenario, username, response, status in cases:
            yield pytest.param(source, username, response, status, id=name + "-" + scenario)


def mock_profile_http(monkeypatch, sources, responses):
    """Keep run_profiles/check_profile real, replacing only HTTP and other platforms."""
    requests = []
    async_client = httpx.AsyncClient

    def handler(request):
        requests.append(request)
        response = responses[request.url.host]
        if isinstance(response, httpx.HTTPError):
            raise response
        return response

    def client(**kwargs):
        return async_client(transport=httpx.MockTransport(handler), **kwargs)

    async def no_discovery(username):
        return []

    monkeypatch.setattr(public_sources, "SOURCES", sources)
    monkeypatch.setattr(httpx, "AsyncClient", client)
    monkeypatch.setattr(osint.discovery, "run", no_discovery)
    return requests


def assert_profile_report(results, tmp_path, source, username, expected_status):
    name = source[0]
    check, = [row for row in results["checks"] if row["source"] == name]
    assert check["kind"] == "username"
    assert check["status"] == expected_status
    assert check["query_username"] == username
    assert check["source_url"] == source[1]
    assert bool(check["checked_at"]) == (expected_status != "skipped")

    profiles = [row for row in results["username_profiles"] if row["site"] == name]
    snapshot = results["identity_resolution"]
    findings = [row for row in snapshot["findings"] if row["source"] == name]
    coverage, = [row for row in snapshot["coverage"]["entries"] if row["source"] == name]
    assert coverage["status"] == expected_status
    assert coverage["query_username"] == username

    pdf_text = " ".join(" ".join(page.extract_text() or "" for page in PdfReader(
        create_report(results, tmp_path)
    ).pages).split())
    section = pdf_text.split("Публичные профили по username", 1)[1]
    labels = {
        "found": ("Находки и возможные совпадения", "Найдены сведения"),
        "not_found": ("Проверки без находок", "Находок в источнике нет"),
        "unavailable": ("Ограничения проверки", "Проверка недоступна"),
        "skipped": ("Ограничения проверки", "Не проверялось"),
    }
    group, label = labels[expected_status]
    source_label = f"{name}: {label}"
    assert source_label in section
    assert group in section.split(source_label, 1)[0]
    assert f"Проверялся username: {username}" in section

    if expected_status == "found":
        expected_url = source[1] + "audit-user"
        assert check["profile_url"] == expected_url
        assert profiles == [{"site": name, "profile_url": expected_url}]
        finding, = findings
        assert finding["profile_url"] == expected_url
        assert finding["decision"] == "unreviewed"
        assert finding["evidence"] == "source_match"
        assert not snapshot["owner_group"]
        assert "Принадлежность человеку не подтверждена." in section
        assert "Профиль: " + expected_url in section
    else:
        assert check["profile_url"] is None
        assert profiles == []
        assert findings == []
        assert f"{name}: Найдены сведения" not in section
        assert "Профиль: " + source[1] not in section
        if expected_status in ("unavailable", "skipped"):
            assert f"{name}: Находок в источнике нет" not in section


@pytest.mark.parametrize("source,username,response,expected_status", profile_cases())
def test_profile_result_in_pdf(monkeypatch, tmp_path, source, username, response, expected_status):
    host = "api.github.com" if source[0] == "GitHub" else "gitlab.com"
    requests = mock_profile_http(monkeypatch, [source], {host: response})

    results = osint.search(username=username)

    if expected_status == "skipped":
        assert requests == []
    else:
        request, = requests
        assert request.method == "GET"
        if source[0] == "GitHub":
            assert str(request.url) == "https://api.github.com/users/" + username
        else:
            assert str(request.url.copy_with(query=None)) == "https://gitlab.com/api/v4/users"
            assert dict(request.url.params) == {"username": username}
    assert_profile_report(results, tmp_path, source, username, expected_status)


@pytest.mark.parametrize("unavailable_source", ["GitHub", "GitLab"])
def test_profile_failure_does_not_hide_other_source(monkeypatch, tmp_path, unavailable_source):
    selected = [source for source in public_sources.SOURCES if source[0] in ("GitHub", "GitLab")]
    responses = {
        "api.github.com": httpx.Response(200, json={"id": 42, "login": "audit-user", "type": "User"}),
        "gitlab.com": httpx.Response(200, json=[{"id": 43, "username": "audit-user"}]),
    }
    failed_host = "api.github.com" if unavailable_source == "GitHub" else "gitlab.com"
    responses[failed_host] = httpx.Response(429, json={"message": "Not Found"})
    requests = mock_profile_http(monkeypatch, selected, responses)

    results = osint.search(username="audit-user")

    assert len(requests) == 2
    for source in selected:
        expected = "unavailable" if source[0] == unavailable_source else "found"
        assert_profile_report(results, tmp_path, source, "audit-user", expected)


@pytest.mark.parametrize(
    "response,expected_status,reason_fragment",
    [
        pytest.param(
            httpx.Response(200, text='<form><input name="password" type="password"></form>'),
            "possible", "Косвенный признак", id="password-form",
        ),
        pytest.param(
            httpx.Response(200, text="<h1>Looks like you're new to Amazon</h1>"
                                     "<button>Proceed to create an account</button>"),
            "unavailable", "распознаваемый результат", id="new-account-screen",
        ),
        pytest.param(
            httpx.ReadTimeout("Synthetic read timeout"),
            "unavailable", "Ошибка соединения", id="timeout",
        ),
        pytest.param(
            httpx.Response(429, text='<form><input name="password" type="password"></form>'),
            "unavailable", "HTTP 429", id="rate-limit",
        ),
        pytest.param(
            httpx.Response(200, text='<html><main>Unexpected page</main></html>'),
            "unavailable", "распознаваемый результат", id="unexpected-html",
        ),
    ],
)
def test_amazon_phone_result_in_pdf(monkeypatch, tmp_path, response, expected_status, reason_fragment):
    requests = []

    def handler(request):
        requests.append(request)
        if request.method == "GET":
            return httpx.Response(
                200, text='<form method="post" action="/ap/signin"><input name="email"></form>',
            )
        if isinstance(response, httpx.ReadTimeout):
            raise response
        return response

    async_client = httpx.AsyncClient

    def mock_client(**kwargs):
        return async_client(transport=httpx.MockTransport(handler), **kwargs)

    monkeypatch.setattr(osint.httpx, "AsyncClient", mock_client)
    results = osint.search(phone="+1 (202) 555-0123")

    assert [(request.method, request.url.host) for request in requests] == [
        ("GET", "www.amazon.com"), ("POST", "www.amazon.com"),
    ]
    assert requests[1].content == b"email=12025550123"
    check, = [row for row in results["checks"] if (row["source"], row["kind"]) == ("Amazon", "phone")]
    assert check["status"] == expected_status
    assert reason_fragment in check["reason"]
    assert check["checked_at"]
    assert check["profile_url"] is None

    pdf_path = create_report(results, tmp_path)
    pdf_text = " ".join(" ".join(page.extract_text() or "" for page in PdfReader(pdf_path).pages).split())
    section = pdf_text.split("Регистрации телефона на сайтах", 1)[1].split(
        "Публичные профили по username", 1,
    )[0]
    assert reason_fragment in section
    assert "Amazon: Находок в источнике нет" not in section
    findings = results["identity_resolution"]["findings"]
    if expected_status == "possible":
        finding, = findings
        assert finding["source"] == "Amazon"
        assert finding["decision"] == "unreviewed"
        assert finding["evidence"] == "indirect_signal"
        assert finding["identifier_id"] == "identifier-phone"
        assert "Находки и возможные совпадения Amazon: Возможная регистрация" in section
        assert "Косвенный признак." in pdf_text
    else:
        assert findings == []
        assert results["phone_registrations"] is None
        assert "Ограничения проверки Amazon: Проверка недоступна" in section
