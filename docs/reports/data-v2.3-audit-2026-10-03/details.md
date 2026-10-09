# Доказательства аудита S5Core 2.3.0

Данные собраны 3 октября 2026 на отдельной копии релизного дерева. Отчет: [Аудит качества кода](../v2.3-code-quality-audit-2026-10-03.md).

- `metadata.json`, `release-SHA256SUMS.txt` - версия исходников, среда, метод и границы измерений.
- `precommit.txt`, `checks-summary.json`, `checks-summary.md`, `skipped-tests.json` - полный стандартный pipeline и пропуски.
- `audit-reproductions.txt`, три `*-probes.go.txt` - шесть воспроизведений, выполненных с race. Эти диагностические тесты утверждают наличие нынешнего дефекта; они не являются приемкой исправления.
- `deadcode-*.txt` - результаты анализа достижимости. Runtime roots не включают внешних потребителей SDK; arm64 анализ статический.
- `audit-windows-tests.txt` - отрицательная проверка компиляции тестов сервера под Windows.
- `audit-*-bench.txt`, `native-bench.go.txt` - локальные microbenchmarks и исходник дополнительного native benchmark.
- `process-summary.json`, `process-repeat-summary.json` - агрегаты отдельных процессов. Сырые request samples проверены и сохранены локально; в публичном наборе оставлены агрегаты и CPU/RSS records.
- `audit-process-performance*.txt` - статус трех process runs. Всего 5880 запросов, длина и SHA-256 проверяются самим стендом.
- Оперативный снимок настройки узлов хранится локально и исключен из публикации. В отчете оставлены необходимые агрегаты измерений.
- `wan-summary.json`, `wan-https.json` - 96 корректно настроенных WAN HTTPS-проб. Первые неподходящие authentication attempts исключены. Тест обходит mihomo и не использует браузер/HTTP3; выборка не равна полной проверке пользователя.
- `audit-matrix-*.txt` - дополнительная проверка вложенного Go-модуля и 51 Python-теста.
- `reproduce.txt` - команды для локального повторения диагностик и process matrix без изменения исходного checkout.
- `manifest.json` - размер и SHA-256 файлов доказательств.

Скорости microbenchmark относятся к Linux amd64. ARM cross-build и статический анализ не являются ARM runtime benchmark. WAN-пробы выполнены против уже работавших тестовых серверов; их нельзя обозначать приемкой официального релиза на обеих сторонах.
