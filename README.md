# MikroTik Audit

`MikroTik Audit` — это набор инструментов для аудита сети на базе MikroTik, офлайн-анализа `.rsc` конфигураций, построения инвентаря и топологии, генерации remediation-скриптов, резервного копирования конфигов и публикации результатов в Excel, NDJSON и Google Sheets.

Проект состоит из трех основных частей:

- Python backend с CLI, сервисным режимом и FastAPI API
- React/Vite frontend для работы с API и снапшотами
- Docker-обвязка для периодического запуска по cron

## Возможности

- Аудит одного устройства или всего inventory
- Офлайн-анализ RouterOS `.rsc` файлов и директорий с конфигами
- Построение live topology по данным с устройств
- Сравнение с phpIPAM и построение отчета по расхождениям
- Генерация remediation-скриптов и OSPF-конфигурации
- Проверка и исправление RADIUS, scheduler, NTP/watchdog-политик
- Бэкап текстовых конфигураций RouterOS
- Экспорт отчетов в:
  - Excel (`.xlsx`)
  - NDJSON
  - Google Sheets
- HTTP API для CLI jobs, снапшотов и фронтенда
- Отдельный frontend для dashboard, inventory, operations и topology

## Структура проекта

```text
.
├─ mikrotik_audit/        Python-пакет проекта
│  ├─ app/                Офлайн-анализатор .rsc и связанная модель данных
│  ├─ cli_support/        Переиспользуемая логика CLI-команд
│  ├─ commands/           RouterOS команды и низкоуровневые шаблоны
│  ├─ config_parts/       Конфигурационные примитивы и нормализация inventory
│  ├─ domain/             Доменная логика аудита и phpIPAM
│  ├─ entrypoints/        Явные точки входа CLI/API/TUI
│  ├─ models/             Общие модели результатов аудита
│  ├─ platform_api/       FastAPI API и persistence слой
│  ├─ report/             Пайплайн отчетов и writers
│  ├─ runtime/            Runtime/bootstrap-обвязка
│  ├─ services/           SSH, firmware, backup, remediation и т.д.
│  ├─ sot/                Source of Truth / snapshot domain
│  ├─ tests/              Автотесты и smoke-кейсы
│  ├─ __main__.py         `python -m mikrotik_audit`
│  ├─ main.py             Совместимый CLI entrypoint
│  ├─ api_main.py         Совместимый API entrypoint
│  ├─ network_inventory.yml
│  ├─ secrets.yml
│  ├─ .env
│  └─ reqqurements.txt
├─ frontend/              React + Vite SPA
├─ docker/                Cron entrypoint scripts
├─ docker-compose.yml
└─ Dockerfile
```

## Требования

- Python 3.12+ рекомендуется
- Node.js 18+ для frontend
- Доступ по сети к MikroTik-устройствам
- SSH доступ к целевым устройствам

Для части функций также могут понадобиться:

- Google service account для Google Sheets
- phpIPAM API credentials
- SQLite/PostgreSQL для FastAPI API

## Быстрый старт

### 1. Установка Python-зависимостей

В проекте файл зависимостей называется `reqqurements.txt` именно так, с текущим написанием.

```powershell
cd D:\dev\mk
.\.venv\Scripts\python.exe -m pip install -r .\mikrotik_audit\reqqurements.txt
```

Если виртуальное окружение еще не создано:

```powershell
cd D:\dev\mk
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r .\mikrotik_audit\reqqurements.txt
```

### 2. Базовая настройка

Основные конфигурационные файлы:

- [mikrotik_audit/.env](D:/dev/mk/mikrotik_audit/.env)
- [mikrotik_audit/secrets.yml](D:/dev/mk/mikrotik_audit/secrets.yml)
- [mikrotik_audit/network_inventory.yml](D:/dev/mk/mikrotik_audit/network_inventory.yml)

Минимально нужно проверить:

- inventory-файл и целевые подсети
- учетные данные для подключения к устройствам
- пути для логов, отчетов и бэкапов
- интеграции phpIPAM / Google Sheets при необходимости

### 3. Проверка окружения

```powershell
cd D:\dev\mk
.\.venv\Scripts\python.exe -m mikrotik_audit doctor
```

### 4. Просмотр целевых IP

```powershell
.\.venv\Scripts\python.exe -m mikrotik_audit targets
```

### 5. Запуск аудита

Полный аудит inventory:

```powershell
.\.venv\Scripts\python.exe -m mikrotik_audit audit
```

Аудит одного устройства:

```powershell
.\.venv\Scripts\python.exe -m mikrotik_audit audit --ip 10.216.92.10
```

## CLI команды

Актуальный список команд:

- `doctor` — валидация окружения, inventory и интеграций
- `targets` — показать рассчитанный список целевых IP
- `config` — вывести эффективную runtime-конфигурацию
- `audit` — аудит одного устройства или inventory
- `export` — полный аудит с экспортом отчетов
- `phpipam-report` — отчет сравнения с phpIPAM
- `sync-phpipam` — legacy alias для `phpipam-report`
- `topology` — live collection топологии
- `analyze-file` — офлайн-анализ одного `.rsc`
- `analyze-dir` — офлайн-анализ директории `.rsc`
- `generate-script` — генерация remediation scripts
- `ospf-create` — генерация OSPF scripts
- `backup-configs` — бэкап конфигураций
- `firmware-update` — проверка и загрузка firmware
- `remediate` — targeted remediation по доменам
- `radius-fix` — проверка/исправление RADIUS
- `scheduler-fix` — проверка/исправление scheduler
- `service` — сервисный режим для циклического запуска

Полная справка:

```powershell
.\.venv\Scripts\python.exe -m mikrotik_audit --help
```

Примеры:

```powershell
.\.venv\Scripts\python.exe -m mikrotik_audit doctor
.\.venv\Scripts\python.exe -m mikrotik_audit targets --limit 10
.\.venv\Scripts\python.exe -m mikrotik_audit audit --ip 10.216.92.10 --no-export
.\.venv\Scripts\python.exe -m mikrotik_audit topology --export
.\.venv\Scripts\python.exe -m mikrotik_audit analyze-file --path .\router.rsc --format json
.\.venv\Scripts\python.exe -m mikrotik_audit remediate --ip 10.216.92.10 --domain ntp --domain scheduler
```

## Офлайн-анализ `.rsc`

Офлайн-анализатор расположен в [mikrotik_audit/app](D:/dev/mk/mikrotik_audit/app) и умеет:

- разбирать RouterOS `.rsc`
- определять identity, model и management IP
- классифицировать порты
- строить секции `analyzer_summary`, `analyzer_ports`, `terminations`

Примеры:

```powershell
.\.venv\Scripts\python.exe -m mikrotik_audit analyze-file --path .\sample.rsc
.\.venv\Scripts\python.exe -m mikrotik_audit analyze-dir --dir .\mikrotik_audit\logs\config-backup-history\configs --export
```

## FastAPI API

API-код находится в [mikrotik_audit/platform_api](D:/dev/mk/mikrotik_audit/platform_api).

Запуск локально:

```powershell
cd D:\dev\mk
.\.venv\Scripts\python.exe -m uvicorn mikrotik_audit.entrypoints.api:app --reload
```

По умолчанию API будет доступен на:

- `http://127.0.0.1:8000`

### Основные endpoint-ы

- `GET /api/v1/health`
- `POST /api/v1/auth/login`
- `POST /api/v1/auth/refresh`
- `GET /api/v1/auth/me`
- `GET /api/v1/cli/commands`
- `POST /api/v1/cli/jobs`
- `GET /api/v1/cli/jobs`
- `GET /api/v1/cli/jobs/{job_id}`
- `POST /api/v1/snapshots`
- `GET /api/v1/snapshots`

### Переменные окружения API

Конфиг определяется в [mikrotik_audit/platform_api/config.py](D:/dev/mk/mikrotik_audit/platform_api/config.py:1).

Основные переменные:

- `MIKROTIK_SOT_APP_NAME`
- `MIKROTIK_SOT_APP_VERSION`
- `MIKROTIK_SOT_DATABASE_URL`
- `MIKROTIK_SOT_AUTO_CREATE_SCHEMA`
- `MIKROTIK_SOT_CORS_ALLOWED_ORIGINS`
- `MIKROTIK_SOT_AUTH_USERNAME`
- `MIKROTIK_SOT_AUTH_PASSWORD`
- `MIKROTIK_SOT_AUTH_SECRET`
- `MIKROTIK_SOT_ACCESS_TOKEN_EXPIRES`
- `MIKROTIK_SOT_REFRESH_TOKEN_EXPIRES`

По умолчанию используется SQLite:

```text
sqlite+aiosqlite:///./mikrotik_sot.db
```

## Frontend

Frontend расположен в [frontend](D:/dev/mk/frontend) и собран на React + Vite.

### Установка

```powershell
cd D:\dev\mk\frontend
npm install
```

### Запуск dev-сервера

```powershell
npm run dev
```

### Production build

```powershell
npm run build
npm run preview
```

### Переменные окружения frontend

Сейчас используется:

- `VITE_API_BASE_URL`

Пример из [frontend/.env](D:/dev/mk/frontend/.env):

```env
VITE_API_BASE_URL=http://127.0.0.1:8000
```

### Разделы интерфейса

Из текущей маршрутизации:

- `/` — dashboard
- `/inventory` — inventory
- `/operations` — операции и jobs
- `/topology` — топология

## Docker и cron-режим

В репозитории есть контейнер для периодического запуска сервисного режима.

Сценарий:

- контейнер поднимает `cron`
- `cron` вызывает [docker/run-cron-job.sh](D:/dev/mk/docker/run-cron-job.sh)
- внутри выполняется `python ./main.py service --once --action ...`

### Запуск через Docker Compose

```powershell
cd D:\dev\mk
docker compose up --build
```

### Важные переменные

- `TZ`
- `CRON_SCHEDULE`
- `SERVICE_ACTION`
- `APP_HOME`

По умолчанию в `docker-compose.yml`:

- timezone: `Asia/Qyzylorda`
- cron: каждые 6 часов
- действие: `audit`

## Отчеты и артефакты

Типовые артефакты проекта:

- Excel-отчеты (`.xlsx`)
- NDJSON-выгрузки
- Google Sheets export
- RouterOS scripts
- OSPF scripts
- config backups
- topology snapshots

Часть артефактов по умолчанию уже лежит в каталоге [mikrotik_audit/logs](D:/dev/mk/mikrotik_audit/logs) и рядом с приложением:

- [mikrotik_audit/mikrotik_inventory.xlsx](D:/dev/mk/mikrotik_audit/mikrotik_inventory.xlsx)
- [mikrotik_audit/mikrotik_inventory.ndjson](D:/dev/mk/mikrotik_audit/mikrotik_inventory.ndjson)

## Конфигурация inventory

Проект поддерживает несколько форматов inventory, которые затем нормализуются в `normalize_inventory_data()`:

- `vlans`
- `inventory_groups`
- `environments`

Нормализация выполняется в [mikrotik_audit/config_parts/inventory.py](D:/dev/mk/mikrotik_audit/config_parts/inventory.py:1).

Это позволяет описывать:

- VLAN-ы и их сети
- inventory type / group
- ignored IP
- OSPF metadata
- gateway per subnet

## Разработка

### Полезные команды

Компиляционный smoke test:

```powershell
.\.venv\Scripts\python.exe -m compileall mikrotik_audit
```

Проверка запуска CLI:

```powershell
.\.venv\Scripts\python.exe -m mikrotik_audit --help
```

Проверка frontend types:

```powershell
cd D:\dev\mk\frontend
npm run lint
```

### Тесты

Тесты лежат в [mikrotik_audit/tests](D:/dev/mk/mikrotik_audit/tests).

Если `pytest` установлен:

```powershell
.\.venv\Scripts\python.exe -m pytest .\mikrotik_audit\tests -q
```

Если `pytest` еще не установлен:

```powershell
.\.venv\Scripts\python.exe -m pip install pytest
.\.venv\Scripts\python.exe -m pytest .\mikrotik_audit\tests -q
```

## Архитектурные заметки

- Python-часть уже оформлена как пакет `mikrotik_audit`
- Старые `main.py`, `api_main.py`, `bootstrap.py`, `runner.py` оставлены как совместимые entrypoint/shim
- Переиспользуемая логика CLI вынесена в `cli_support`
- Переиспользуемая логика offline analysis вынесена в `app/analysis_support.py`
- Общая механика табличных writers вынесена в `report/writers/tabular.py`
- FastAPI command execution использует dispatch-слой в `platform_api/command_runner.py`

## Известные особенности

- Имя файла зависимостей сейчас: `reqqurements.txt`
- В репозитории уже присутствуют runtime-артефакты и данные инвентаря рядом с кодом
- Для некоторых функций нужны реальные внешние интеграции: MikroTik SSH, phpIPAM, Google Sheets
- Некоторые команды чувствительны к корректности inventory и secrets-конфигурации

## Рекомендуемый сценарий использования

1. Настроить `.env`, `secrets.yml` и `network_inventory.yml`
2. Выполнить `doctor`
3. Проверить `targets`
4. Выполнить `audit` или `topology`
5. При необходимости построить `phpipam-report`
6. После верификации использовать `generate-script`, `remediate`, `radius-fix`, `scheduler-fix`
7. Для UI поднять API и frontend

## Лицензия

Явная лицензия в репозитории сейчас не обнаружена. Если проект планируется публиковать или передавать команде, лучше добавить отдельный `LICENSE`.
