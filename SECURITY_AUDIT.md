# Звіт аудиту безпеки — «Електронний деканат»

| Поле | Значення |
|---|---|
| Аудитор | Козинський Руслан Ярославович, група Б2F501ЗОФ23 (233з) |
| Дата аудиту | 2026-10-16 |
| Версія системи | commit `631601a` (ЗПР-2, етап 3) |
| Обсяг (scope) | API FastAPI, БД SQLite, Docker-образ, Nginx, залежності |
| Поза обсягом | фронтенд, хост-ОС, соціальна інженерія (лише оцінка ризику) |
| Методи | STRIDE, OWASP Top 10 (2021), Trivy 0.56.2, pip-audit, Bandit, `scripts/security_check.sh`, `scripts/pentest_mini.sh` |

## 1. Резюме для керівництва

Система має сім незалежних шарів захисту, і всі 12 мінітестів на вразливості пройдено як через Nginx, так і напряму в API. `security_check.sh` завершується з `SECURITY CHECK PASSED` (FAIL 0, WARN 2). Критичних знахідок, які можна експлуатувати в поточній конфігурації, не виявлено. Головна відкрита проблема — застарілі залежності, зафіксовані ще в ЗПР-1: 21 відома вразливість у 5 пакетах (starlette, python-multipart, python-jose, bleach, ecdsa). Друга за важливістю — відсутність MFA, через що найвищими залишаються ризики фішингу викладача та вразливих залежностей (по 12 балів).

Рекомендації: (1) оновити fastapi/starlette, python-multipart, bleach і перейти з python-jose на PyJWT; (2) додати MFA для викладачів і адміністраторів.

| Критичні | Високі | Середні | Низькі |
|---|---|---|---|
| 0 | 2 | 6 | 7 |

Ще одна знахідка має рівень Info (F-16).

## 2. Інвентаризація активів

| Актив | Тип | Критичність | Обґрунтування |
|---|---|---|---|
| `data/app.db` | Дані | Критичний | ПІБ, email (зашифровано), оцінки, хеші паролів, журнал аудиту |
| `ENCRYPTION_KEY`, `BLIND_INDEX_KEY`, `JWT_SECRET_KEY` | Секрети | Критичний | Компрометація = підробка токенів / розшифрування PII; втрата `ENCRYPTION_KEY` = втрата всіх email |
| `data/backups/*.db.enc` | Дані | Високий | Повна копія БД, зашифрована тим самим `ENCRYPTION_KEY` |
| `audit_log` | Дані | Середній | Докази для розслідувань, підзвітність викладачів |
| `nginx/certs/selfsigned.key` | Секрет | Середній | Приватний ключ TLS (self-signed, лише для localhost) |
| Docker-образ `information-security-practice-api` | Інфраструктура | Високий | Код і всі залежності; базовий образ Debian 13.7 |
| Облікові записи admin / teacher | Ідентичності | Високий | admin має всі 7 дозволів; teacher змінює оцінки |
| Вихідний код і `requirements.txt` на GitHub | Код | Середній | Публічний репозиторій; секретів у ньому немає (перевірено) |

## 3. Реалізовані шари захисту (Defense in Depth)

| Шар | Механізм | Де (файл / робота) |
|---|---|---|
| Автентифікація | bcrypt (cost 12), JWT access (30 хв) + refresh (7 днів), однакова 401 проти enumeration | ЗПР-1, `app/security.py`, `app/auth/` |
| Авторизація | RBAC admin/teacher/student, ролі з БД, `type == "access"` | ЗПР-1, `app/auth/dependencies.py` |
| Веб-рівень | Pydantic (allow-list, діапазони), bleach, CSP, HSTS, CORS allow-list, slowapi | ЗПР-1, `app/schemas.py`, `app/middleware/` |
| Шифрування даних | Fernet для email/phone, сліпий індекс HMAC-SHA256, MultiFernet для ротації, зашифрований бекап | ЗПР-2, `app/crypto/`, `scripts/backup_db.py` |
| Аудит і моніторинг | `audit_log` за 5W, детектор Brute Force і off-hours, `/admin/security-stats`, JSON-логи | ЗПР-2, `app/audit/` |
| Середовище | non-root `appuser`, read-only FS, `cap_drop: ALL`, `no-new-privileges`, HTTPS (TLS 1.2+), API лише на 127.0.0.1 | ЗПР-2, `Dockerfile`, `docker-compose.yml`, `nginx/nginx.conf` |
| DevSecOps | Trivy, pip-audit, Bandit, `security_check.sh`, `pentest_mini.sh` | ЗПР-2, `scripts/`, `reports/` |

## 4. Модель загроз STRIDE

| STRIDE | Загроза | Реалізований контрзахід | Залишковий ризик |
|---|---|---|---|
| Spoofing | Підбір пароля викладача; підробка JWT; фішинг | bcrypt; HS256 з `algorithms=[ALGORITHM]` (T2, T3 → 401); slowapi 5/хв + детектор Brute Force (T12 → 429) | Немає MFA; HS256 зі спільним секретом (бажано RS256/EdDSA); python-jose має невиправлені CVE про algorithm confusion |
| Tampering | Студент змінює оцінку; підміна шифротексту в БД; SQL Injection; Stored XSS | `require_role` з ролями з БД (T5–T7 → 403); Pydantic; ORM і `text()` з параметрами (T10); bleach; HMAC у Fernet (підміна символу → `[ПОМИЛКА РОЗШИФРУВАННЯ]`) | Записи `audit_log` не підписані й не зчеплені хешами |
| Repudiation | Викладач заперечує виставлену оцінку | `grades.assigned_by`; `audit_log` 5W із `data_change` (`new: {grade}`); перегляд журналу теж логується | Журнал у тій самій БД: адміністратор БД може його стерти; немає віддаленого зберігання логів |
| Information Disclosure | Витік `app.db` або бекапу; перехоплення трафіку; витік через логи | Fernet для email/phone; зашифрований бекап з правами 600; HTTPS; у логах і `audit_log` 0 паролів/JWT/шифротексту (перевірено) | `full_name` і оцінки зберігаються відкрито; ключі лежать на тому самому хості, що й БД |
| Denial of Service | Флуд `/auth/login`; великі тіла запитів; блокування чужого акаунта | slowapi; Nginx `limit_req 10r/s burst 20`; `client_max_body_size 1m` | Lockout за логіном можна навмисно зловживати; ліміти slowapi в пам'яті процесу; DoS-CVE у starlette/python-multipart |
| Elevation of Privilege | Студент → admin; вихід з контейнера | RBAC (ролі з БД, не з токена); реєстрація лише з роллю student; `appuser` UID 1000; код належить root; read-only FS; `cap_drop: ALL`; `no-new-privileges` | IDOR у майбутніх ендпоінтах; немає seccomp/AppArmor-профілю; контроль за ролями, а не за дозволами (`edit_grades`) |

## 5. Матриця ризиків (залишковий ризик)

Ризик = Ймовірність (1–5) × Вплив (1–5). Рівні: 1–4 низький, 5–9 середній, 10–15 високий, 16–25 критичний.

| # | Загроза | Й (1–5) | В (1–5) | Ризик | Рівень | Обґрунтування |
|---|---|---|---|---|---|---|
| R1 | Brute Force | 2 | 4 | 8 | Середній | bcrypt, slowapi і детектор роблять перебір вкрай повільним (≤ 5 спроб/хв з IP), але без MFA вдалий підбір слабкого пароля дає повний доступ до акаунта |
| R2 | SQL Injection | 1 | 5 | 5 | Середній | Усі запити через ORM або `text()` з параметрами, Bandit 0 знахідок, T10 → 401; вплив максимальний, бо ін'єкція дала б доступ до всієї БД |
| R3 | Stored XSS | 1 | 3 | 3 | Низький | Allow-list для `full_name` (T9 → 422), bleach вирізає теги з коментаря, API віддає лише JSON із CSP `default-src 'none'` |
| R4 | Крадіжка JWT | 2 | 4 | 8 | Середній | Токен у заголовку (не в cookie), HTTPS, access живе 30 хв; але відкликання немає, а refresh діє 7 днів |
| R5 | Витік БД або бекапу | 2 | 3 | 6 | Середній | Email/phone і бекап зашифровано, але ПІБ і оцінки відкриті, а ключі зберігаються на тому самому хості |
| R6 | Втрата `ENCRYPTION_KEY` | 2 | 5 | 10 | Високий | Немає формалізованого депонування ключа; бекап зашифровано тим самим ключем, тому втрата ключа = безповоротна втрата всіх email |
| R7 | Вразлива залежність | 3 | 4 | 12 | Високий | 21 відома вразливість у 5 пакетах (pip-audit), 2 CRITICAL у python-jose (Trivy); для більшості є виправлені версії, але їх ще не встановлено |
| R8 | Фішинг викладача | 3 | 4 | 12 | Високий | Соціальна інженерія поза обсягом технічних контролів; без MFA викрадений пароль одразу дає право змінювати оцінки |
| R9 | Знищення або підміна журналу аудиту | 2 | 3 | 6 | Середній | Журнал у тій самій БД, не підписаний; є дублювання у stdout (`docker logs`), але без віддаленого збору |
| R10 | Зловживання блокуванням чужого акаунта | 3 | 2 | 6 | Середній | Будь-хто може 5 невдалими спробами заблокувати вхід конкретного користувача на 5 хв; вплив обмежений часом |

## 6. Знахідки та рекомендації

| ID | Рівень | Знахідка | Доказ | Рекомендація | Статус |
|---|---|---|---|---|---|
| F-01 | High | Fallback JWT-секрет у `config.py` і `:-dev…` у compose (ЗПР-1) | `security_check.sh` на коді ЗПР-1 | Прибрати fallback, fail-fast при старті | Виправлено (етап 3); retest: `[OK] fallback-секретів у коді немає`, `[OK] docker-compose.yml без dev-секретів` |
| F-02 | High | starlette 0.37.2 (через fastapi 0.111.0): 7 вразливостей, зокрема DoS (CVE-2024-47874, multipart без обмеження розміру поля) | `reports/pip-audit.txt`, `reports/trivy.txt` | Оновити fastapi до версії зі starlette ≥ 1.3.1, перезібрати, повторити мінітести | Відкрито, план п. 1 |
| F-03 | Medium | python-jose 3.3.0: 4 вразливості, у т.ч. CRITICAL CVE-2024-33663 і CVE-2026-85394 (algorithm confusion з ECDSA/DER-ключами) | `reports/trivy.txt`, `reports/pip-audit.txt` | Мігрувати на PyJWT. Ризик знижено до Medium, бо ми використовуємо лише HS256 і жорсткий список `algorithms=["HS256"]`; T3 (`alg=none`) → 401 | Прийнятий ризик до міграції (план п. 1) |
| F-04 | Medium | python-multipart 0.0.9: 7 вразливостей (DoS у парсері multipart, CVE-2024-53981) | `reports/pip-audit.txt` | Оновити до ≥ 0.0.31. Ендпоінтів з `Form`/файлами немає, тому експлуатація малоймовірна | Відкрито, план п. 1 |
| F-05 | Medium | bleach 6.1.0: 2 вразливості (GHSA-gj48-438w-jh9v, GHSA-8rfp-98v4-mmr6) | `reports/pip-audit.txt` | Оновити до 6.4.0; ми використовуємо `tags=[]`, тож обхід allow-list тегів малоймовірний | Відкрито, план п. 1 |
| F-06 | Medium | Базовий образ Debian 13.7: 44 HIGH (util-linux, ncurses, systemd-libs, perl-base та ін.), CRITICAL 0 | `reports/trivy.txt` | Регулярно перезбирати образ, закріпити digest, розглянути distroless | Відкрито |
| F-07 | Medium | Журнал аудиту в тій самій БД, без захисту від зміни | Код `app/audit/logger.py`, R9 | Hash-chain для `audit_log`, відправлення логів у віддалений SIEM | Відкрито, план п. 3 |
| F-08 | Medium | Ключі шифрування зберігаються в `.env` на тому самому хості, що й БД | `.env`, `docker-compose.yml` | Менеджер секретів (Vault, Docker secrets), депонування `ENCRYPTION_KEY` окремо від бекапів | Відкрито, план п. 4 |
| F-09 | Low | Блокування за логіном можна використати для DoS чужого акаунта | `app/audit/detector.py`, R10 | Прогресивна затримка або CAPTCHA замість жорсткого блокування; блокувати пару IP + логін | Прийнятий ризик (компроміс захисту від розподіленого перебору) |
| F-10 | Low | ecdsa 0.19.2: CVE-2024-23342 (Minerva timing), виправлення немає | `reports/pip-audit.txt` | Код ECDSA не використовується (HS256); зникне після міграції на PyJWT | Прийнятий ризик |
| F-11 | Low | Ліміти slowapi зберігаються в пам'яті процесу: скидаються при перезапуску, не працюють між репліками | `app/middleware/rate_limiter.py` | Redis як сховище лімітів | Відкрито |
| F-12 | Low | `--forwarded-allow-ips "*"`: API довіряє будь-якому `X-Forwarded-For` | `Dockerfile` | Безпечно лише тому, що 8000 відкрито тільки на 127.0.0.1; у production вказати IP Nginx | Прийнятий ризик; retest: `curl http://10.49.170.167:8000/health` з LAN → немає відповіді |
| F-13 | Low | `full_name` (PII) зберігається відкрито | Схема `users` | Шифрувати `full_name` так само, як email (пошук за ним не потрібен) | Відкрито |
| F-14 | Low | `login_failed` із `reason=brute_force_blocked` записується з кодом 401, хоча клієнт отримує 429 | `audit_log` id 80, `app/auth/router.py` | Передавати фактичний код 429 у `log_login_failed` | Відкрито |
| F-15 | Low | Хибне спрацювання `security_check.sh`: заглушка `replace-me-with-64-hex-chars` для `JWT_SECRET_KEY` з `.env.example` ЗПР-1 сприймалася як секрет в історії Git | `security_check.sh` до виправлення: FAIL 1 | Перевірку уточнено: ігнорується лише це конкретне значення-заглушка, а не типи файлів. Справжні ключі з `.env` в історії відсутні (0 збігів для кожного з 3 ключів). Контрольні тести: фіктивний ключ у `leak.txt` і справжній ключ у `.env.example` обидва дають FAIL. Перша версія виправлення (виключення `*.example`) не врахувала цитату заглушки в цьому звіті — виявлено перевіркою з чистого клону і виправлено | Виправлено; retest: `SECURITY CHECK PASSED` (робоча копія і чистий клон) |
| F-16 | Info | На простий (не preflight) запит із `Origin: https://evil.example` відповідь містить `access-control-allow-credentials: true` без `access-control-allow-origin` | Ручний тест CORS, розділ 9 | Впливу немає: без ACAO браузер не віддасть відповідь сторінці | Прийнято |

## 7. Чеклист OWASP Top 10 (2021)

| ID | Категорія | Статус (✅/⚠️/❌/N/A) | Доказ / коментар |
|---|---|---|---|
| A01 | Broken Access Control | ✅ | T5, T6, T7 → 403; T8 → 200; студент бачить лише свої оцінки (id з токена, `app/routes/students.py`) |
| A02 | Cryptographic Failures | ✅ | bcrypt `$2b$12$`; Fernet для email/phone (T11 → `gAAAA`); TLS 1.2/1.3 (`openssl s_client`: за замовчуванням TLSv1.3; спроба TLS 1.1 → сервер відповідає `alert protocol version`, SSL alert 70); секретів у Git немає (`security_check.sh`) |
| A03 | Injection | ✅ | Лише ORM і `text()` з параметрами (`scripts/migrate_encrypt.py`); T10 → 401; T9 → 422; bleach для коментарів; Bandit — 0 |
| A04 | Insecure Design | ⚠️ | Модель загроз і компроміс lockout описано (розділи 4–5, F-09); немає MFA і відкликання токенів |
| A05 | Security Misconfiguration | ✅ | CSP, HSTS, X-Frame-Options, nosniff (`security_check.sh`); CORS без `*` (preflight evil.example → 400); `server_tokens off` (`Server: nginx`); без fallback-секретів |
| A06 | Vulnerable and Outdated Components | ❌ | 21 вразливість у 5 пакетах (`reports/pip-audit.txt`), 2 CRITICAL у python-jose і 44 HIGH в ОС (`reports/trivy.txt`); план оновлень — розділ 11, п. 1 |
| A07 | Identification and Authentication Failures | ✅ | slowapi + детектор (T12 → 429, `brute_force_detected`); `exp` у JWT; refresh ≠ access (T4 → 401); однакова відповідь проти enumeration |
| A08 | Software and Data Integrity Failures | ✅ | HMAC у Fernet (підміна символу → `[ПОМИЛКА РОЗШИФРУВАННЯ]`); версії залежностей закріплено; відновлення бекапу перевірено (`integrity_check=ok`); з іншим ключем → `InvalidToken` |
| A09 | Security Logging and Monitoring Failures | ⚠️ | `audit_log` 5W, алерти `brute_force_detected`, перегляд журналу логується, JSON у stdout; але журнал не захищений від зміни (F-07) і немає віддаленого збору |
| A10 | SSRF | N/A | Сервер не робить вихідних HTTP-запитів за URL від користувача (у коді немає HTTP-клієнтів, `requests`/`httpx`/`urllib` не використовуються в `app/`); єдиний `urllib` — у HEALTHCHECK на фіксований `127.0.0.1` |

## 8. Результати автоматизованого сканування

| Інструмент | Тип | CRITICAL | HIGH | MEDIUM | Дія |
|---|---|---|---|---|---|
| Trivy (ОС, Debian 13.7) | Container SCA | 0 | 44 | не сканувалось (`--severity HIGH,CRITICAL`) | Перезбирати образ регулярно, закріпити digest (F-06) |
| Trivy (Python-пакети) | Container SCA | 2 (python-jose) | 12 | — | Міграція на PyJWT, оновлення starlette/python-multipart (F-02–F-04) |
| pip-audit | Python SCA | — | 21 вразливість у 5 пакетах | — | Оновити 4 пакети, ecdsa — прийнятий ризик (F-10) |
| Bandit | SAST | — | 0 | 0 | Дій не потрібно; `# nosec` не використовується |
| security_check.sh | Конфігурація | FAIL: 0 | WARN: 2 | | WARN — pip-audit і Trivy CRITICAL (див. вище); F-15 виправлено |

Повні звіти: `reports/trivy.txt`, `reports/pip-audit.txt`, `reports/bandit.txt`, `reports/security_check.txt`.

## 9. Результати мінітестів

`./scripts/pentest_mini.sh` через Nginx (`https://localhost`), 2026-10-16 06:14 UTC — `reports/pentest_mini.md`:

| Тест | Фактично | Очікується | Висновок |
|---|---|---|---|
| T1 Доступ без токена (/auth/me) | 401 | 401 | ✅ захищено |
| T2 JWT з підробленим payload | 401 | 401 | ✅ захищено |
| T3 JWT з alg=none | 401 | 401 | ✅ захищено |
| T4 Refresh token замість access | 401 | 401 | ✅ захищено |
| T5 Студент → /admin/users | 403 | 403 | ✅ захищено |
| T6 Студент → /admin/audit-log | 403 | 403 | ✅ захищено |
| T7 Студент → чужі оцінки через /teachers | 403 | 403 | ✅ захищено |
| T8 Адмін → /admin/audit-log (контроль) | 200 | 200 | ✅ захищено |
| T9 XSS у full_name при реєстрації | 422 | 422 | ✅ захищено |
| T10 SQLi у логіні (' OR '1'='1) | 401 | 401 422 429 | ✅ захищено |
| T11 Email у БД зашифровано | gAAAA | gAAAA | ✅ захищено |
| T12 Brute Force (8 спроб) | 429 | 429 | ✅ захищено |

Повторний запуск напряму в API (`BASE=http://localhost:8000`, 06:16 UTC) — також 12/12 (`reports/pentest_mini_direct.md`).

Що саме повернуло 429 у T12 (за `audit_log`):
- через Nginx — **slowapi** (5 запитів/хв): 3 невдалі входи, далі `rate_limited`; детектор не встиг побачити 5 невдач;
- напряму — **детектор**: невдачі з тієї самої IP у 5-хвилинному вікні накопичились (3 + 2), запис `brute_force_detected` з `failed_attempts: 5`.

Тобто два механізми працюють незалежно (Defense in Depth).

**Ручний тест (CORS)** через HTTPS:

| Origin | Preflight `OPTIONS /auth/login` | `access-control-allow-origin` |
|---|---|---|
| `https://evil.example` | 400 Bad Request | відсутній ✅ |
| `http://localhost:3000` | 200 | `http://localhost:3000` |
| `https://localhost` | 200 | `https://localhost` |

Додатково на етапі 1 перевірено підміну шифротексту (→ `[ПОМИЛКА РОЗШИФРУВАННЯ]`) і ротацію ключа: бекап, зашифрований старим ключем, відновлюється з новим `ENCRYPTION_KEY` і старим у `ENCRYPTION_KEY_OLD` (`integrity_check=ok`), а лише з новим ключем дає `InvalidToken`.

## 10. Моніторинг і KPI

Лічильники з `GET /admin/security-stats?hours=24` на 2026-10-16 06:21 UTC (`reports/security_stats_24h.json`). У вікно потрапили тести етапу 2 (2026-10-15) і мінітести етапу 4.

| Показник | Значення | Джерело |
|---|---|---|
| Усього подій / 24 год | 89 | /admin/security-stats |
| Невдалих входів / 24 год | 14 | /admin/security-stats (`failed_logins`) |
| Відмов у доступі (403) | 7 | `access_denied` |
| Brute Force алертів | 3 | `brute_force_alerts` |
| Входів у неробочий час (00:00–06:00 Київ) | 0 | `off_hours_logins` |
| Змін даних (оцінки) | 1 | `data_changes` |
| Помилок сервера (5xx) | 0 | `server_errors` |
| Top IP за невдачами | `192.168.97.1` — 58 | `top_failure_ips`: шлюз Docker Desktop, тобто всі тести з цього Mac. Що це адреса клієнта, а не Nginx (`192.168.97.3`), підтверджує, що `--proxy-headers` працює |
| MTTD / MTTR детектора (тест T12) | 93,1 с / 0,011 с | `audit_log`, див. нижче |
| MTTR slowapi (тест T12 через Nginx) | 0,79 с | `audit_log` |
| Останній бекап / відновлення перевірено | `app_20261016_060723.db.enc` (2026-10-16 06:07 UTC) / так | `restore_db`: `integrity_check=ok, users=5` |

Як пораховано MTTD і MTTR (мітки часу з `audit_log`, UTC):

| Подія | Час | Запис |
|---|---|---|
| Перший `login_failed` з IP у 5-хвилинному вікні (T10, прогін через Nginx) | 06:14:48.145 | id 50 |
| Перша відповідь 429 від slowapi | 06:14:48.933 | id 56, `rate_limited` |
| `brute_force_detected` (`failed_attempts: 5`, прогін напряму) | 06:16:21.199 | id 79 |
| Перша відповідь 429 від детектора | 06:16:21.210 | id 81, `rate_limited`, 12,1 мс |

- **MTTD = 06:16:21.199 − 06:14:48.145 = 93,1 с.** Нижня межа задана slowapi: з однієї IP проходить ≤ 5 спроб за хвилину, тож шосту невдачу детектор у будь-якому разі побачить не раніше ніж через ~60 с. Решту часу додала пауза між двома прогонами тесту.
- **MTTR = 06:16:21.210 − 06:16:21.199 ≈ 0,011 с:** реакція автоматична, 429 повертається в тому самому запиті, що й виявлення.
- **slowapi** реагує раніше за детектор: 06:14:48.933 − 06:14:48.145 ≈ 0,79 с від першої невдачі до першої 429. Але він обмежує лише частоту запитів і не створює алерту.

## 11. План покращень

| Пріоритет | Захід | Яку загрозу закриває | Зусилля |
|---|---|---|---|
| 1 | Оновити fastapi/starlette, python-multipart, bleach; замінити python-jose на PyJWT; повторити `pentest_mini.sh` і `final_check.sh` | R7, F-02–F-05, F-10 (Tampering, DoS) | Низьке–середнє (1–2 дні) |
| 2 | MFA (TOTP) для викладачів і адміністраторів | R1, R8 (Spoofing, фішинг) | Середнє |
| 3 | Hash-chain для `audit_log` і відправлення логів у віддалений SIEM | R9, F-07 (Repudiation) | Середнє |
| 4 | Менеджер секретів; депонування `ENCRYPTION_KEY` окремо від бекапів; скрипт ротації з `MultiFernet.rotate()` | R5, R6, F-08 (Information Disclosure) | Середнє |
| 5 | Відкликання токенів (Redis-blacklist), коротший refresh, ротація refresh з інвалідацією старого | R4 (Spoofing) | Середнє |
| 6 | Redis для лімітів slowapi; прогресивна затримка замість жорсткого lockout | F-09, F-11, R10 (DoS) | Низьке |
| 7 | Шифрування `full_name`; seccomp/AppArmor-профіль; distroless-образ із закріпленим digest | F-13, F-06 (Information Disclosure, EoP) | Середнє |
| 8 | GitHub Actions з Bandit, pip-audit і Trivy на кожен push | R7 (Shift Left) | Низьке |

## 12. Висновок

Система готова до навчальної та пілотної експлуатації в закритій мережі: усі 12 мінітестів пройдено, конфігурація відповідає `security_check.sh` (FAIL 0), персональні дані зашифровано, а безпекові події фіксуються й виявляються. Для експлуатації з доступом з інтернету потрібно спершу виконати п. 1 плану (оновлення залежностей), бо найкритичніший залишковий ризик — **вразливі залежності (R7, 12 балів)**: це публічно відомі CVE з готовими експлойтами, і для більшості вже існують виправлення. Поряд із ним стоїть **фішинг викладача (R8, 12 балів)**, який технічно знімається лише MFA (п. 2 плану).
