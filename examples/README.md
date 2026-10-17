# AuditCraft — Приклади використання CLI

Ця папка містить 10 невеликих контрактів, кожен з яких демонструє окреме правило статичного аналізу AuditCraft. Приклади призначені для навчання, тестування детекторів і перевірки інтеграцій (CI, SARIF, PoC-генератор).

## Правила та приклади

| # | Файл | Мова | Правило | Опис |
|---|------|------|---------|------|
| 01 | `01_reentrancy.sol` | Solidity | SC006 | External call перед state write (CEI violation), без `nonReentrant` |
| 02 | `02_unprotected_init.sol` | Solidity | SC007 | `initialize()` без `initializer`/`onlyInitializing` |
| 03 | `03_unchecked_erc20.sol` | Solidity | SC008 | Прямий `IERC20.transfer()`/`transferFrom()` без SafeERC20 |
| 04 | `04_centralization.sol` | Solidity | SC009 | `onlyOwner` + критичні операції без timelock |
| 05 | `05_selfdestruct.sol` | Solidity | SC003 | `selfdestruct` без access control |
| 06 | `06_delegatecall.sol` | Solidity | SC004 | `delegatecall` до caller-influenced адреси без guard |
| 07 | `07_floating_pragma.sol` | Solidity | SC001 | Floating pragma `^0.8.0` (не зафіксована версія) |
| 08 | `08_safe.sol` | Solidity | — | Безпечний контракт (0 знахідок) |
| 09 | `09_anchor_no_constraint.rs` | Rust/Anchor | SC010 | Акаунт без `has_one`/`constraint` |
| 10 | `10_anchor_missing_signer.rs` | Rust/Anchor | SC011 | Відсутній `Signer` на privileged-акаунті |

## Швидкий старт

### 1. Показати scope

    auditcraft scope examples/
    auditcraft scope examples/ --json

### 2. Запустити перевірку правил

    # усі правила на всій папці
    auditcraft check examples/

    # лише конкретне правило
    auditcraft check examples/ --rule SC006

    # JSON-вивід для CI
    auditcraft check examples/ --json

    # мінімальна серйозність
    auditcraft check examples/ --min-severity high

### 3. Згенерувати звіт

    auditcraft report examples/ --format markdown -o report.md
    auditcraft report examples/ --format sarif -o report.sarif
    auditcraft report examples/ --format json -o report.json

### 4. Згенерувати PoC

    auditcraft poc generate examples/01_reentrancy.sol --rule SC006 -o poc/
    auditcraft poc generate examples/05_selfdestruct.sol --rule SC003 -o poc/

## Очікувані результати

- `01`–`07` та `09`–`10` — кожен дає **рівно одну** (або більше) знахідку відповідного правила.
- `08_safe.sol` — **0 знахідок**; якщо тут щось знайдено, це false positive.

> Приклади призначені **лише для навчання та тестування**. Не використовуйте цей код у продакшені.
