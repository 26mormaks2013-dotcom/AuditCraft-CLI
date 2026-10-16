# AuditCraft CLI

Cross-platform CLI-утиліта для аудиторів см�рт-контрактів: підрахунок nSLOC, ведення структурованого звіту та базові статичні перевірки безпеки Solidity/Rust-коду.

## Можливості

- **scope** — рекурсивний підрахунок нормалізованих рядків коду (nSLOC = Total - Comments - Blank) для файлів .sol і .rs. Вивід: Rich-таблиця або --json.
- **report** — ведення звіту аудиту в три кроки: init (створити summary), add (додати знахідку), build (зрендерити Markdown через Jinja2).
- **check** — статичні детектори безпеки. 7 правил MVP: floating pragma, unchecked call/transfer, selfdestruct/delegatecall без guard, zero-address check, Rust/Anchor-правила. Вивід: Rich-таблиця або --json.
- **list-rules** — перелік усіх зареєстрованих правил.

## Встановлення

Потрібен Python 3.10+.

    cd auditcraft
    pip install -e .

Для розробки (тести + лінтер):

    pip install -e .[dev]

## Швидкий старт

### Підрахунок nSLOC

    auditcraft scope path/to/contracts

Машинно-читаний формат:

    auditcraft scope path/to/contracts --json

### Статичні перевірки

    auditcraft check path/to/contracts

Фільтри:

    auditcraft check . --rules SC001,SC003 --min-severity warning --json

Перелік правил:

    auditcraft list-rules

### Звіт аудиту

    auditcraft report init MyProtocol --auditor Alice
    auditcraft report add Floating-pragma -s high -d Pragma-not-pinned. -r Pin-0.8.20. --non-interactive
    auditcraft report build

Результат — AUDIT_REPORT.md у поточному каталозі (шлях можна задати через -o).

## Структура проєкту

    auditcraft/
      auditcraft/
        cli/          # scope.py, check.py, report.py (чисті функції)
        core/         # sloc_counter, static_checker, report_builder
        models/       # Pydantic-моделі (Finding, ReportSummary, Severity)
        templates/    # Jinja2-шаблон звіту
        main.py       # Typer-додаток і реєстрація команд
      tests/          # pytest-тести
      pyproject.toml

## Розширення детекторів

Нове правило додається у auditcraft/core/static_checker.py через реєстр — достатньо 10-15 рядків: оголосити Rule (id, severity, мови, regex/предикат) і зареєструвати його. Команди check і list-rules підхоплять правило автоматично.

## Тести та лінтер

    python -m pytest -q
    ruff check .

## Ігнорування

Під час сканування ігноруються каталоги node_modules, lib, target, out, test, mock.

## Ліцензія

MIT.
