# Новые источники — 4 октября 2026

Выбраны для оценки Spotify, Pinterest и Mozilla Accounts: используются отдельные запросы валидации/статуса, а не создание аккаунта.

Spotify: GET https://spclient.wg.spotify.com/signup/public/v1/account с validate=1. Проверка на вымышленном адресе example.com вернула HTTP 200, status=1. Адаптер подключён в локальный поиск по email. Код 20 даёт «Возможная регистрация», код 1 — «Неопределённый результат» с пояснением о доступности email. Неизвестный формат, HTTP-ошибки и ограничения — «Проверка недоступна». Запросы не повторяются, перенаправления выключены. Пароль и согласие на регистрацию не отправляются.

Pinterest: на тестовый запрос получен HTTP 403. Mozilla Accounts: HTTP 406. Они не включены в основной поиск. Discord исключён: старый модуль отправляет пароль и consent=true на endpoint регистрации. GitHub требует дополнительной проверки актуальной формы и не включён.

59 тестов прошли: 44 прежних и 15 дополнительных. Проверено попадание возможного Spotify-совпадения и пояснения в PDF. После явного разрешения пользователя проверены два контрольных адреса: A (аккаунт есть) — exists=true, B (аккаунта нет) — exists=false. Оба ответа совпали с данными пользователя. Это два примера с локального компьютера, не оценка общей точности и не проверка с Render. Адреса в отчёт и тесты не включены.

Изменения пока локальные, GitHub и Render ещё не обновлены этой итерацией. Обновить osint.py, source_checks.py и tests/test_source_checks.py одновременно; новых зависимостей нет.

Источники для выбора протокола:
https://raw.githubusercontent.com/megadose/holehe/master/holehe/modules/music/spotify.py
https://raw.githubusercontent.com/megadose/holehe/master/holehe/modules/social_media/pinterest.py
https://raw.githubusercontent.com/mozilla/fxa/main/packages/fxa-auth-server/lib/routes/account.ts
