[![Review Assignment Due Date](https://classroom.github.com/assets/deadline-readme-button-22041afd0340ce965d47ae6ef1cefeee28c7c493a6346c4f15d667ab976d596c.svg)](https://classroom.github.com/a/NSTTkgmb)
# Лабораторная работа №4 — Анализ и тестирование безопасности веб-приложения

## Цель

Научиться находить уязвимости в реальном коде, формулировать security test cases, классифицировать проблемы через CWE, оценивать их серьёзность через CVSS и оформлять результаты как профессиональный pentest-отчёт.

---

## Описание приложения

Учебное REST API на **Javalin (Java)** для аналитики пользовательской активности.

### Эндпоинты

| Метод  | Путь               | Параметры                                      | Описание                                  |
|--------|--------------------|------------------------------------------------|-------------------------------------------|
| POST   | `/register`        | `userId`, `userName`                           | Регистрация пользователя                  |
| POST   | `/recordSession`   | `userId`, `loginTime`, `logoutTime` (ISO 8601) | Запись сессии активности                  |
| GET    | `/totalActivity`   | `userId`                                       | Суммарное время активности (в минутах)    |
| GET    | `/inactiveUsers`   | `days`                                         | Список неактивных пользователей           |
| GET    | `/monthlyActivity` | `userId`, `month` (yyyy-MM)                    | Активность по дням за месяц              |
| GET    | `/userProfile`     | `userId`                                       | HTML-профиль пользователя                 |
| GET    | `/exportReport`    | `userId`, `filename`                           | Экспорт отчёта в файл на сервере          |
| POST   | `/notify`          | `userId`, `callbackUrl`                        | Уведомление по webhook                    |

### Запуск приложения

```bash
./gradlew run
# Сервер стартует на http://localhost:7000
```

---

## Задание

### Этап 1 — Asset Inventory (инвентаризация активов)

Перед поиском уязвимостей необходимо понять, что именно защищаем.

Заполните таблицу активов системы:

| Актив | Тип | Ценность | Примечание |
|-------|-----|----------|------------|
| Данные пользователей (userId, userName) | Данные | Высокая | В нашей системе, зная userId можно смотреть чужую информацию, так как никакой проверки прав не реализовано|
| Данные о сессиях (время входа/выхода) | Данные | Низкая | Зная только время входа и выхода, никаких данных других получить нельзя. Однако отсутствие авторизации позволяет подделывать сессии других пользователей, искажая аналитику. |
| Файловая система сервера | Инфраструктура | Высокая | Path Traversal. Возможны чтения системных файлов (/etc/passwd), чтение исходного кода (конфигурация БД, api ключи), запись файла в любое место (remote code execution, загрузка веб-шелла)|
| Внутренняя сеть / метаданные окружения | Инфраструктура | Высокая | Возможны Server-Side Request Forgery, подделка запроса от имени сервера для, например, кражи api ключей|

> **Вопрос для размышления:** какие из активов наиболее критичны и почему?
> Наиболее критичны Внутренняя сеть/метаданные окружения и файловая система сервера.
> Внутренняя сеть и метаданные облака — самый критичный актив, потому что через SSRF-уязвимость злоумышленник получает доступ не к одному серверу, а ко всей облачной инфраструктуре компании. Файловая система сервера критична, потому что через Path Traversal атакующий может записать веб-шелл в любую директорию и получить удаленное выполнение команд на сервере. Это дает полный контроль над самим хостом. 

---

### Этап 2 — Threat Modeling

Проведите базовое моделирование угроз по методологии **STRIDE**:

| Категория угрозы | Расшифровка            | Применимо к этому приложению? |
|------------------|------------------------|-------------------------------|
| **S**poofing     | Подмена идентификации  | Да. Источник угрозы - внешний злоумышленник. Все эндпоинты, принимающие userId как параметр. Потенциальный ущерб - доступ к чужим данным и выполненией действий от имени другого пользователя.                             |
| **T**ampering    | Модификация данных     | Да. Источник угроы - внешний злоумышленник. Эндпоинты /recordSession, /exportData. Искажение аналитики, подделка отчётов, запись произвольных файлов на сервер.                             |
| **R**epudiation  | Отказ от авторства     | Да. Источник угрозы - внешний или внутренний пользователь. Поверхность атака - эндпоинты, где нет логирования. Невозможность доказать факт совершения действия, расследовать инцидент.                             |
| **I**nformation Disclosure | Утечка данных |  Да. Источник угрозы - внешний злоумышленник. Поверхность атаки - эндпоинты /userProfile, /totalActivity                         |
| **D**enial of Service | Отказ в обслуживании | Да. Внешнией злоумешленник. Поверхность атаки - /register, /recordSession. В приложении нет rate limiting, поэтому можно сделать тысячи запросов в секунду, зарегистрировать миллионы пользователей и сессий, что приведёт в outOfMemoryException.                          |
| **E**levation of Privilege | Повышение привилегий | Да. Внешний злоумышленник. /exportReport, /notify. Получение прав на выполнение на сервере, доступ к облачной инфраструктуре.                       |

Для каждой применимой угрозы укажите:
- **Источник угрозы** (кто/что может её реализовать)
- **Поверхность атаки** (через какой эндпоинт/параметр)
- **Потенциальный ущерб**

---

### Этап 3 — Ручное тестирование

Исследуйте каждый эндпоинт вручную — с помощью `curl`, Postman, Burp Suite или браузера.

**Что проверять:**
- Как приложение обрабатывает неожиданные значения параметров?
- Что происходит при передаче спецсимволов (`<`, `>`, `"`, `'`, `/`, `..`)?
- Что возвращается в теле ответа при ошибках?
- Что происходит с параметрами-путями к файлам или URL?
- Есть ли ограничения на количество запросов или размер данных?

**Пример — начало исследования `/userProfile`:**

```bash
# 1. Зарегистрировать тестового пользователя
curl -X POST "http://localhost:7000/register?userId=test&userName=Alice"

# 2. Посмотреть, как отображается профиль
curl "http://localhost:7000/userProfile?userId=test"

# 3. Попробовать имя со спецсимволами
curl -X POST "http://localhost:7000/register?userId=evil&userName=%3Cscript%3Ealert(1)%3C%2Fscript%3E"
curl "http://localhost:7000/userProfile?userId=evil"
# → Что вернёт сервер? Что отрендерит браузер?
```

> Данный пример — лишь отправная точка. Исследуйте **все** эндпоинты самостоятельно.

Коллекция ручных запросов в Postman:   

<img width="726" height="1176" alt="image" src="https://github.com/user-attachments/assets/4053d0a3-8937-4516-b487-bd4a984077b4" />

Пример XSS alert:   
<img width="530" height="180" alt="image" src="https://github.com/user-attachments/assets/b6398ecd-ef60-49a9-8849-0feb81deea0d" />


---

### Этап 4 — Статический анализ с Semgrep

[Semgrep](https://semgrep.dev/) — инструмент статического анализа кода, который ищет паттерны уязвимостей без запуска приложения.

#### Установка

```bash
# Linux / macOS (через pip)
pip install semgrep

# macOS (через Homebrew)
brew install semgrep

# Проверка установки
semgrep --version
```

#### Запуск на проекте

```bash
# Перейти в корень проекта
cd /path/to/software_testing_lab_4

# Базовый запуск — встроенные правила для Java
semgrep --config "p/java" src/

# Расширенный запуск — правила безопасности OWASP
semgrep --config "p/owasp-top-ten" src/

# Сохранить отчёт в формате SARIF
semgrep --config "p/java" --sarif -o semgrep-report.sarif src/
```

#### Что такое SARIF?

**SARIF (Static Analysis Results Interchange Format)** — стандартный формат обмена результатами статического анализа (ISO/IEC 5055). Используется в GitHub Actions, GitLab CI, VS Code и IDE для отображения findings прямо в интерфейсе.

Откройте `semgrep-report.sarif` и изучите структуру:

```json
{
  "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
  "version": "2.1.0",
  "runs": [{
    "tool": { "driver": { "name": "Semgrep", "rules": [ ... ] } },
    "results": [{
      "ruleId": "java.lang.security.audit.xss.no-direct-response-writer",
      "level": "warning",
      "message": { "text": "..." },
      "locations": [{
        "physicalLocation": {
          "artifactLocation": { "uri": "src/..." },
          "region": { "startLine": 42 }
        }
      }]
    }]
  }]
}
```

Ключевые поля для отчёта:

| Поле SARIF | Что означает |
|---|---|
| `ruleId` | Идентификатор правила / уязвимости |
| `level` | Серьёзность: `error`, `warning`, `note` |
| `message.text` | Описание проблемы |
| `locations[].region.startLine` | Строка в исходном коде |
| `relatedLocations` | Связанные места (data flow) |

#### Что делать с результатами

1. Изучите каждый `finding` в выводе и в `.sarif`-файле
2. Определите, является ли он реальной уязвимостью или ложным срабатыванием (false positive)
3. Для каждого finding сопоставьте `ruleId` с соответствующим CWE
4. Включите результаты Semgrep в финальный отчёт с пометкой о верификации

> **Важно:** Semgrep — вспомогательный инструмент. Статический анализ не заменяет ручное тестирование. Некоторые уязвимости он найдёт, некоторые — нет.

Результат работы semgrep

```
✅ Scan completed successfully.
 • Findings: 0 (0 blocking)
 • Rules run: 113
 • Targets scanned: 6
 • Parsed lines: ~100.0%
 • Scan skipped: 
   ◦ Files matching .semgrepignore patterns: 1
 • Scan was limited to files tracked by git
 • For a detailed list of skipped files and lines, run semgrep with the --verbose flag
Ran 113 rules on 6 files: 0 findings
```
Был выполнен запуск Semgrep с официальным репозиторием правил для Java (113 правил). Найдено 0 findings, так как правила ориентированы на Spring/Jakarta EE и не покрывают паттерны фреймворка Javalin.
Мы создали правила специально под Javalin

Файл rules.yaml

```java
rules:
  - id: javalin-xss-in-userprofile
    patterns:
      - pattern: |
          ctx.contentType("text/html").result(...)
      - pattern: |
          $HTML + $USERINPUT
    message: |
      Potential Reflected XSS (CWE-79).
      User-controlled data (userName) is concatenated directly into HTML response without escaping.
      Use HTML encoding (e.g., StringEscapeUtils.escapeHtml4) or a template engine.
    languages:
      - java
    severity: ERROR
    metadata:
      cwe: "CWE-79"
      owasp: "A03:2021 - Injection"
      confidence: HIGH

  - id: javalin-path-traversal-in-export
    pattern: |
      new File($DIR + $FILENAME)
    message: |
      Potential Path Traversal (CWE-22).
      User-controlled filename is concatenated with base directory without validation.
      Attacker can use "../" to write files outside /tmp/reports/.
      Use Paths.get(baseDir).resolve(filename).normalize() and verify the result starts with baseDir.
    languages:
      - java
    severity: ERROR
    metadata:
      cwe: "CWE-22"
      owasp: "A01:2021 - Broken Access Control"
      confidence: HIGH

  - id: javalin-ssrf-in-notify
    patterns:
      - pattern: |
          URL $URL = new URL($USERINPUT);
          ...
          $URL.openConnection();
    message: |
      Potential Server-Side Request Forgery (CWE-918).
      User-controlled URL is used to make server-side HTTP requests without validation.
      Attacker can access internal services (localhost, 169.254.169.254, internal IPs).
      Validate URL against allowlist and block private/internal IP ranges.
    languages:
      - java
    severity: ERROR
    metadata:
      cwe: "CWE-918"
      owasp: "A10:2021 - Server-Side Request Forgery"
      confidence: HIGH

  - id: javalin-info-disclosure-in-errors
    pattern-either:
      - pattern: |
          ctx.status(400).result("Invalid data: " + e.getMessage())
      - pattern: |
          ctx.status(400).result(e.getMessage())
    message: |
      Potential Information Disclosure (CWE-209).
      Exception messages are returned directly to the client, revealing internal logic.
      Return generic error messages and log detailed errors server-side.
    languages:
      - java
    severity: WARNING
    metadata:
      cwe: "CWE-209"
      confidence: MEDIUM

```

Результаты работы, найдено 4 уязвимости по нашим правилам.

```java
    src/main/java/ru/itmo/testing/lab4/controller/UserAnalyticsController.java
    ❯❱ javalin-info-disclosure-in-errors
          ❰❰ Blocking ❱❱
          Potential Information Disclosure (CWE-209). Exception messages are returned directly to the client,
          revealing internal logic. Return generic error messages and log detailed errors server-side.       
                                                                                                             
           74┆ ctx.status(400).result("Invalid data: " + e.getMessage());
            ⋮┆----------------------------------------
          115┆ ctx.status(400).result("Invalid data: " + e.getMessage());
   
   ❯❯❱ javalin-path-traversal-in-export
          ❰❰ Blocking ❱❱
          Potential Path Traversal (CWE-22). User-controlled filename is concatenated with base directory
          without validation. Attacker can use "../" to write files outside /tmp/reports/. Use           
          Paths.get(baseDir).resolve(filename).normalize() and verify the result starts with baseDir.    
                                                                                                         
          154┆ File reportFile = new File(REPORTS_BASE_DIR + filename);
   
   ❯❯❱ javalin-ssrf-in-notify
          ❰❰ Blocking ❱❱
          Potential Server-Side Request Forgery (CWE-918). User-controlled URL is used to make server-side    
          HTTP requests without validation. Attacker can access internal services (localhost, 169.254.169.254,
          internal IPs). Validate URL against allowlist and block private/internal IP ranges.                 
                                                                                                              
          180┆ URL url = new URL(callbackUrl);
          181┆ URLConnection connection = url.openConnection();
```

---

### Этап 5 — Оформление отчёта

Для **каждой найденной уязвимости** заполните карточку по следующему шаблону:

---

#### 🔴 Finding #1 — Reflected Cross-Site Scripting (XSS)

| Поле | Значение |
|------|----------|
| **Компонент** | UserAnalyticsController.java, эндпоинт GET /userProfile |
| **Тип** | Reflected XSS |
| **CWE** | CWE-79 — Improper Neutralization of Input During Web Page Generation |
| **CVSS v3.1** | 6.1 MEDIUM (AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N) |
| **Статус** | Confirmed |

**Описание:**
> Эндпоинт /userProfile возвращает HTML-страницу, вставляя userName из хранилища напрямую в разметку без экранирования. Злоумышленник может зарегистрировать пользователя с именем, содержащим JavaScript-код. Когда жертва откроет профиль, скрипт выполнится в её браузере.

**Шаги воспроизведения:**
```
1. POST /register?userId=xss_test&userName=<script>alert('XSS')</script>
2. GET /userProfile?userId=xss_test
3. Ожидаемый результат: тег отображается как текст (&lt;script&gt;...)
   Фактический результат: тег вставлен в HTML как есть, браузер выполняет скрипт
```

**Влияние:**
> Атакующий может украсть cookies, токены из localStorage, перенаправить жертву на фишинговый сайт, выполнить действия от имени жертвы.

**Рекомендации по исправлению:**
> Экранировать HTML-спецсимволы перед вставкой в разметку. Например, использовать 

**Security Test Case:**
```java
XssPentestTest.java
```

---

#### 🔴 Finding #2 — Path Traversal

| Поле | Значение |
|------|----------|
| **Компонент** | UserAnalyticsController.java, эндпоинт GET /exportReport |
| **Тип** | Path Traversal |
| **CWE** | CWE-22 — Improper Limitation of a Pathname to a Restricted Directory |
| **CVSS v3.1** | 7.5 HIGH (AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N) |
| **Статус** | Confirmed |

**Описание:**
> Эндпоинт /exportReport принимает параметр filename и конкатенирует его с REPORTS_BASE_DIR без валидации. Атакующий может использовать ../ для выхода за пределы /tmp/reports/ и записи файла в произвольную директорию, что ведет к RCE (Remote Code Execution) через загрузку веб-шелла (командная оболочка для удалённого управления веб-сервером).

**Шаги воспроизведения:**
```
1. POST /register?userId=test&userName=Test
2. GET /exportReport?userId=test&filename=../../../tmp/hack.txt
3. Ожидаемый результат: файл создается в /tmp/reports/ или запрос отклоняется
   Фактический результат: файл создается в /tmp/hack.txt
```

**Влияние:**
> Атакующий может записать веб-шелл (командная оболочка для удалённого управления веб-сервером) в директорию веб-сервера и получить удаленное выполнение команд (remote code execution), что дает контроль над сервером.

**Рекомендации по исправлению:**
> Использовать Paths.get(REPORTS_BASE_DIR).resolve(filename).normalize() и проверять, что итоговый путь начинается с REPORTS_BASE_DIR

**Security Test Case:**
```java
class PathTraversalTest {

    private static final int TEST_PORT = 7000;
    private static final String BASE_URL = "http://localhost:" + TEST_PORT;
    private static final Path EVIL_FILE = Paths.get("/tmp/hack.txt");

    private static Javalin app;
    private static HttpClient http;

    @BeforeAll
    static void startServer() {
        app = UserAnalyticsController.createApp();
        app.start(TEST_PORT);
        http = HttpClient.newHttpClient();
    }

    @AfterAll
    static void stopServer() {
        app.stop();
    }

    @BeforeEach
    void cleanup() throws Exception {
        Files.deleteIfExists(EVIL_FILE);
    }

    @Test
    @DisplayName("[SECURITY] Path Traversal allows writing file outside /tmp/reports/")
    void pathTraversalWritesOutsideReportsDir() throws Exception {
        // Arrange: регистрируем пользователя
        HttpRequest registerReq = HttpRequest.newBuilder()
                .uri(URI.create(BASE_URL + "/register?userId=test&userName=Test"))
                .POST(HttpRequest.BodyPublishers.noBody())
                .build();
        http.send(registerReq, HttpResponse.BodyHandlers.ofString());

        // Act: пытаемся записать файл в /tmp/ через Path Traversal
        String payload = "../hack.txt";
        HttpRequest exportReq = HttpRequest.newBuilder()
                .uri(URI.create(BASE_URL + "/exportReport?userId=test&filename=" + payload))
                .GET()
                .build();
        HttpResponse<String> response = http.send(exportReq, HttpResponse.BodyHandlers.ofString());

        // Assert: уязвимость подтверждена — файл создался за пределами /tmp/reports/
        assertTrue(Files.exists(EVIL_FILE),
                "FAIL: File was created outside /tmp/reports/. Path Traversal confirmed.");
    }

}
```

---

#### 🔴 Finding #3 — Server-Side Request Forgery (SSRF)

| Поле | Значение |
|------|----------|
| **Компонент** | UserAnalyticsController.java, эндпоинт POST /notify |
| **Тип** | Server-Side Request Forgery (SSRF) |
| **CWE** | CWE-918 — Server-Side Request Forgery (SSRF) |
| **CVSS v3.1** | 7.5 HIGH (AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N) |
| **Статус** | Confirmed |

**Описание:**
> Эндпоинт /notify принимает параметр callbackUrl и делает HTTP-запрос по этому адресу без валидации. Сервер выступает как прокси, позволяя атакующему сканировать внутреннюю сеть, получать доступ к облачным метаданным (169.254.169.254) и атаковать внутренние сервисы.

**Шаги воспроизведения:**
```
1. POST /register?userId=test&userName=Test
2. POST /notify?userId=test&callbackUrl=http://127.0.0.1:7000/userProfile?userId=test
3. Ожидаемый результат: запрос отклонен (403/400)
   Фактический результат: сервер выполняет запрос и возвращает HTML своего же эндпоинта
```

**Влияние:**
> Атакующий может украсть IAM-ключи из облачных метаданных, получить доступ к внутренним базам данных, отсканировать локальные порты, обойти файрвол.

**Рекомендации по исправлению:**
> Валидировать URL

**Security Test Case:**
```java
package ru.itmo.testing.lab4.pentest;

import io.javalin.Javalin;
import org.junit.jupiter.api.*;
import ru.itmo.testing.lab4.controller.UserAnalyticsController;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import static org.junit.jupiter.api.Assertions.*;

public class SSRTTest {

    private static final int TEST_PORT = 7779;
    private static final String BASE_URL = "http://localhost:" + TEST_PORT;

    private static Javalin app;
    private static HttpClient http;

    @BeforeAll
    static void startServer() {
        app = UserAnalyticsController.createApp();
        app.start(TEST_PORT);
        http = HttpClient.newHttpClient();
    }

    @AfterAll
    static void stopServer() {
        app.stop();
    }

    @Test
    @Order(1)
    @DisplayName("[SECURITY] SSRF allows request to localhost")
    void ssrfAllowsLocalhostRequest() throws Exception {
        // Arrange: регистрируем пользователя
        HttpRequest registerReq = HttpRequest.newBuilder()
                .uri(URI.create(BASE_URL + "/register?userId=test&userName=Test"))
                .POST(HttpRequest.BodyPublishers.noBody())
                .build();
        http.send(registerReq, HttpResponse.BodyHandlers.ofString());

        // Act: пытаемся сделать запрос к localhost (сами к себе)
        String internalUrl = "http://127.0.0.1:" + TEST_PORT + "/userProfile?userId=test";
        String encodedUrl = URLEncoder.encode(internalUrl, StandardCharsets.UTF_8);
        HttpRequest notifyReq = HttpRequest.newBuilder()
                .uri(URI.create(BASE_URL + "/notify?userId=test&callbackUrl=" + encodedUrl))
                .POST(HttpRequest.BodyPublishers.noBody())
                .build();
        HttpResponse<String> response = http.send(notifyReq, HttpResponse.BodyHandlers.ofString());

        // Assert: уязвимость подтверждена — сервер сделал запрос к localhost
        assertTrue(response.body().contains("Profile: Test"),
                "FAIL: SSRF confirmed — server made request to localhost and returned internal data.");
    }

}
```

---


#### 🔴 Finding #4 — Server-Side Request Forgery (SSRF)

| Поле | Значение |
|------|----------|
| **Компонент** | UserAnalyticsController.java, эндпоинты /recordSession, /monthlyActivity |
| **Тип** | Information Disclosure through Error Messages |
| **CWE** | CWE-209 — Generation of Error Message Containing Sensitive Information |
| **CVSS v3.1** | 5.3 MEDIUM (AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N) |
| **Статус** | Confirmed |

**Описание:**
> При возникновении ошибок (неверный формат даты, отсутствие сессий) приложение возвращает клиенту полный текст исключения: "Invalid data: " + e.getMessage(). Это раскрывает внутреннюю логику, используемые библиотеки и структуру системы.

**Шаги воспроизведения:**
```
1. GET /monthlyActivity?userId=ghost&month=2026/01
2. Ожидаемый результат: "Invalid request" или "Bad request"
   Фактический результат: "Invalid data: Text '2026/01' could not be parsed at index 4"
```

**Влияние:**
> Атакующий получает информацию о внутреннем устройстве приложения (Java, парсинг дат), что помогает в разведке и построении более сложных атак.

**Рекомендации по исправлению:**
> Возвращать обобщенные сообщения об ошибках: "Invalid request parameters". Детали ошибки логировать на сервере, но не отправлять клиенту.

**Security Test Case:**
```java
package ru.itmo.testing.lab4.pentest;

import io.javalin.Javalin;
import org.junit.jupiter.api.*;
import ru.itmo.testing.lab4.controller.UserAnalyticsController;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

import static org.junit.jupiter.api.Assertions.*;

@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class InfoDisclosureTest {

    private static final int TEST_PORT = 7780;
    private static final String BASE_URL = "http://localhost:" + TEST_PORT;

    private static Javalin app;
    private static HttpClient http;

    @BeforeAll
    static void startServer() {
        app = UserAnalyticsController.createApp();
        app.start(TEST_PORT);
        http = HttpClient.newHttpClient();
    }

    @AfterAll
    static void stopServer() {
        app.stop();
    }

    @Test
    @Order(1)
    @DisplayName("[SECURITY] Error messages disclose internal parsing details")
    void errorMessagesDiscloseInternalDetails() throws Exception {
        // Act: отправляем невалидный формат месяца
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(BASE_URL + "/monthlyActivity?userId=test&month=2026/01"))
                .GET()
                .build();
        HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());

        // Assert: уязвимость подтверждена — ответ содержит детали парсинга
        assertEquals(400, response.statusCode());
        assertTrue(response.body().contains("could not be parsed"),
                "FAIL: Error message discloses internal parsing details.");
        assertTrue(response.body().contains("Text '2026/01'"),
                "FAIL: User input reflected in error message with parsing context.");
    }

    @Test
    @Order(2)
    @DisplayName("[SECURITY] Error message discloses business logic for non-existent user")
    void errorMessageDisclosesBusinessLogic() throws Exception {
        // Act: запрашиваем несуществующего пользователя
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(BASE_URL + "/monthlyActivity?userId=nonexistent&month=2026-01"))
                .GET()
                .build();
        HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());

        // Assert: уязвимость подтверждена — раскрывается информация о сессиях
        assertEquals(400, response.statusCode());
        assertTrue(response.body().contains("No sessions found for user"),
                "FAIL: Error message discloses that user exists but has no sessions.");
    }

}
```

---

#### 🔴 Finding #5 — Missing Authentication / Broken Access Control

| Поле | Значение |
|------|----------|
| **Компонент** | Все эндпоинты приложения |
| **Тип** | Broken Access Control / Missing Authentication |
| **CWE** | 	CWE-306 — Missing Authentication for Critical Function |
| **CVSS v3.1** | 7.5 HIGH (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N) |
| **Статус** | Confirmed |

**Описание:**
> Приложение не реализует механизм аутентификации. Любой запрос с корректным userId обрабатывается без проверки, что инициатор имеет право действовать от имени этого пользователя. Знание userId дает полный доступ к данным и действиям пользователя.

**Шаги воспроизведения:**
```
1. POST /register?userId=alice&userName=Alice
2. POST /register?userId=bob&userName=Bob (злоумышленник)
3. GET /totalActivity?userId=alice (злоумышленник запрашивает данные Alice)
4. Ожидаемый результат: 403 Forbidden
   Фактический результат: возвращаются данные Alice
```

**Влияние:**
> Злоумышленник может получить доступ к данным любого пользователя, подделывать сессии, искажать аналитику, дискредитировать пользователей. Возможен массовый сбор данных через перебор userId.

**Рекомендации по исправлению:**
> Внедрить аутентификацию (JWT, OAuth2, Session-based). Хранить userId в контексте сессии, а не передавать в query-параметрах. Все эндпоинты должны использовать userId из аутентифицированной сессии.

**Security Test Case:**
```java
package ru.itmo.testing.lab4.pentest;

import io.javalin.Javalin;
import org.junit.jupiter.api.*;
import ru.itmo.testing.lab4.controller.UserAnalyticsController;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

import static org.junit.jupiter.api.Assertions.*;

@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class MissingAuthPentestTest {

    private static final int TEST_PORT = 7781;
    private static final String BASE_URL = "http://localhost:" + TEST_PORT;

    private static Javalin app;
    private static HttpClient http;

    @BeforeAll
    static void startServer() {
        app = UserAnalyticsController.createApp();
        app.start(TEST_PORT);
        http = HttpClient.newHttpClient();
    }

    @AfterAll
    static void stopServer() {
        app.stop();
    }

    @Test
    @Order(1)
    @DisplayName("[SECURITY] Any user can access another user's data")
    void anyUserCanAccessAnotherUsersData() throws Exception {
        // Arrange: создаем двух пользователей
        http.send(HttpRequest.newBuilder()
                .uri(URI.create(BASE_URL + "/register?userId=alice&userName=Alice"))
                .POST(HttpRequest.BodyPublishers.noBody())
                .build(), HttpResponse.BodyHandlers.ofString());

        http.send(HttpRequest.newBuilder()
                .uri(URI.create(BASE_URL + "/register?userId=bob&userName=Bob"))
                .POST(HttpRequest.BodyPublishers.noBody())
                .build(), HttpResponse.BodyHandlers.ofString());

        // Добавляем сессию Alice
        http.send(HttpRequest.newBuilder()
                .uri(URI.create(BASE_URL + "/recordSession?userId=alice&loginTime=2026-01-15T10:00:00&logoutTime=2026-01-15T11:00:00"))
                .POST(HttpRequest.BodyPublishers.noBody())
                .build(), HttpResponse.BodyHandlers.ofString());

        // Act: Bob (злоумышленник) запрашивает данные Alice
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(BASE_URL + "/totalActivity?userId=alice"))
                .GET()
                .build();
        HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());

        // Assert: уязвимость подтверждена — Bob получил данные Alice
        assertEquals(200, response.statusCode());
        assertTrue(response.body().contains("60 minutes") || response.body().contains("Total activity:"),
                "FAIL: Missing authentication allows access to another user's data.");
    }

    @Test
    @Order(2)
    @DisplayName("[SECURITY] Any user can add sessions for another user")
    void anyUserCanAddSessionsForAnotherUser() throws Exception {
        // Act: Bob добавляет сессию для Alice
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(BASE_URL + "/recordSession?userId=alice&loginTime=2026-01-15T12:00:00&logoutTime=2026-01-15T13:00:00"))
                .POST(HttpRequest.BodyPublishers.noBody())
                .build();
        HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());

        // Assert: уязвимость подтверждена — сессия добавлена
        assertEquals(200, response.statusCode());
        assertTrue(response.body().contains("Session recorded"),
                "FAIL: Missing authentication allows modifying another user's data.");
    }

}
```




---

### Пример оформленного finding

В качестве образца изучите файл:

```
src/test/java/ru/itmo/testing/lab4/pentest/XssPentestTest.java
```

Он демонстрирует структуру pentest-теста для **одной** из уязвимостей приложения.  
Ваша задача — найти остальные, описать их по шаблону выше и написать аналогичные тесты.

---

## Полезные ресурсы

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CWE List](https://cwe.mitre.org/data/definitions/1000.html)
- [CVSS v3.1 Calculator](https://www.first.org/cvss/calculator/3.1)
- [Semgrep Registry](https://semgrep.dev/r) — готовые правила для Java
- [PortSwigger Web Security Academy](https://portswigger.net/web-security) — интерактивные материалы по уязвимостям
