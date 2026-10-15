#!/usr/bin/env bash
# Фінальна перевірка ЗПР-1: 20 сценаріїв з розділу 10 інструкції.
# Запуск (Git Bash / Linux / macOS) на свіжій БД після міграції та seed:
#   bash scripts/final_check.sh
# Логін має ліміт 5/хв, тому перед тестом 20 скрипт чекає 61 с.

B=${B:-http://localhost:8000}
JSON="Content-Type: application/json"
PASS=0; FAIL=0

row() {  # row <№> <сценарій> <очікуваний код> <фактичний код> [деталі]
  local mark="✅"
  if [ "$3" = "$4" ]; then PASS=$((PASS + 1)); else mark="❌"; FAIL=$((FAIL + 1)); fi
  printf '| %s | %s | %s | %s %s %s |\n' "$1" "$2" "$3" "$4" "$mark" "$5"
}
code() { curl -s -o /dev/null -w '%{http_code}' "$@"; }
login() { curl -s -X POST "$B/auth/login" -H "$JSON" -d "{\"username\":\"$1\",\"password\":\"$2\"}"; }
field() { sed -E "s/.*\"$1\":\"([^\"]+)\".*/\1/"; }

ST=$(login student01 'Student123!' | field access_token)
TT=$(login teacher01 'Teacher123!' | field access_token)
ADM=$(login admin 'Admin123!@#')
AT=$(echo "$ADM" | field access_token)
RT=$(echo "$ADM" | field refresh_token)

echo "| № | Сценарій | Очікування | Фактичний результат |"
echo "|---|---|---|---|"

r=$(code "$B/health"); body=$(curl -s "$B/health" | grep -o '"tables":[0-9]*')
row 1 "Health" 200 "$r" "$body"

reg='{"username":"newstudent","email":"new@university.edu","password":"SecurePass123","full_name":"Мар’яна Нова"}'
body=$(curl -s -w ' %{http_code}' -X POST "$B/auth/register" -H "$JSON" -d "$reg")
r=${body##* }; hash=$(echo "$body" | grep -c password_hash)
row 2 "Реєстрація (успіх)" 201 "$r" "(password_hash у відповіді: $([ "$hash" = 0 ] && echo немає || echo Є))"

row 3 "Дублікат" 409 "$(code -X POST "$B/auth/register" -H "$JSON" -d "$reg")"

row 4 "Слабкий пароль" 422 "$(code -X POST "$B/auth/register" -H "$JSON" \
  -d '{"username":"weakuser","email":"weak@university.edu","password":"password","full_name":"Слабкий Пароль"}')"

row 5 "XSS в імені" 422 "$(code -X POST "$B/auth/register" -H "$JSON" \
  -d '{"username":"xssuser","email":"xss@university.edu","password":"SecurePass123","full_name":"<script>alert(1)</script>"}')"

body=$(curl -s -w ' %{http_code}' -X POST "$B/auth/login" -H "$JSON" -d '{"username":"admin","password":"Admin123!@#"}')
r=${body##* }; toks=$(echo "$body" | grep -c '"access_token".*"refresh_token"')
row 6 "Логін (успіх)" 200 "$r" "$([ "$toks" = 1 ] && echo '(access_token + refresh_token)')"

body=$(curl -s -w ' %{http_code}' -X POST "$B/auth/login" -H "$JSON" -d '{"username":"admin","password":"wrong"}')
row 7 "Невірний пароль" 401 "${body##* }" "$(echo "$body" | grep -o 'Невірний логін або пароль')"

row 8 "Без токена" 401 "$(code "$B/auth/me")"
row 9 "Підроблений токен" 401 "$(code "$B/auth/me" -H 'Authorization: Bearer abc.def.ghi')"
row 10 "Refresh замість access" 401 "$(code "$B/auth/me" -H "Authorization: Bearer $RT")"
row 11 "Оновлення токенів" 200 "$(code -X POST "$B/auth/refresh" -H "$JSON" -d "{\"refresh_token\":\"$RT\"}")"
row 12 "Свої оцінки" 200 "$(code "$B/students/me/grades" -H "Authorization: Bearer $ST")"
row 13 "Студент → admin" 403 "$(code "$B/admin/users" -H "Authorization: Bearer $ST")"
row 14 "Викладач → admin" 403 "$(code "$B/admin/users" -H "Authorization: Bearer $TT")"
row 15 "Адмін → admin" 200 "$(code "$B/admin/users" -H "Authorization: Bearer $AT")"

row 16 "Оцінка поза діапазоном" 422 "$(code -X POST "$B/teachers/grades" -H "Authorization: Bearer $TT" \
  -H "$JSON" -d '{"student_id":3,"subject_id":1,"grade":9999}')"

body=$(curl -s -w ' %{http_code}' -X POST "$B/teachers/grades" -H "Authorization: Bearer $TT" -H "$JSON" \
  -d '{"student_id":3,"subject_id":1,"grade":88,"comment":"<script>alert(document.cookie)</script>Добре"}')
comment=$(echo "$body" | grep -o '"comment":"[^"]*"')
row 17 "Stored XSS у коментарі" 201 "${body##* }" "(${comment//|/\\|})"

hdrs=$(curl -s -D - -o /dev/null "$B/health" | tr 'A-Z' 'a-z')
missing=""
for h in content-security-policy x-frame-options x-content-type-options strict-transport-security referrer-policy; do
  echo "$hdrs" | grep -q "^$h:" || missing="$missing $h"
done
row 18 "Security Headers" "5/5" "$([ -z "$missing" ] && echo 5/5 || echo "немає:$missing")"

pre=$(curl -s -i -X OPTIONS "$B/auth/login" -H "Origin: http://evil.example" -H "Access-Control-Request-Method: POST")
r=$(echo "$pre" | head -1 | awk '{print $2}'); acao=$(echo "$pre" | grep -ci 'access-control-allow-origin')
row 19 "CORS чужий домен" 400 "$r" "$([ "$acao" = 0 ] && echo '(без access-control-allow-origin)' || echo '(є ACAO!)')"

echo "_Очікування 61 с, щоб скинувся ліміт логінів…_" >&2
sleep 61
codes=""
for i in 1 2 3 4 5 6; do
  codes="$codes $(code -X POST "$B/auth/login" -H "$JSON" -d '{"username":"admin","password":"wrong"}')"
done
row 20 "Rate Limiting" 429 "${codes##* }" "(коди:${codes})"

echo
echo "Пройдено: $PASS / $((PASS + FAIL))"
[ "$FAIL" = 0 ]
