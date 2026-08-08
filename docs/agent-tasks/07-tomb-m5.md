# M5: Tomb — оставшиеся задачи

> Вставь перед этим текстом `00-CONTEXT.md`.

## Что уже сделано

`pkg/tomb` реализован и работает:

- **Coffin backend**: Init/Open/Close/Status, tar+age, shred, path traversal guard, O_EXCL
- **State file**: JSON sidecar, stale PID detection, atomic write, SHA-256 key (collision-free)
- **Auto-close**: timer + D-Bus (screenlock/suspend) на Linux, timer-only macOS/Windows
- **mlock** на Linux, pidIsDead, platform splits
- **CLI**: `binpass tomb init|open|close|status`, `binpass doctor`
- **--force**: skip shred (overwriteRandom) для ускоренного close
- **Symlink rejection**: writeTar skips, readTar rejects tar.TypeSymlink
- **Тесты**: unit + integration + 18 e2e, все платформы собираются, `CGO_ENABLED=0`
- **Документация**: doc.go, README.md, docs/tomb.md

Коммиты: `3af5ba9`, `05ce5a7`, `04e0da6`, `ecbaaeb` на ветке `feat/tomb`.

---

## T1: LUKS backend (Linux)

**Приоритет**: high (M5 критерий из §14)

**Что**: Реализовать `pkg/tomb/luks_linux.go` — LUKS-контейнер через `cryptsetup` (exec, не линковка).

**Требования**:

- `Init(dir, rcp, size)`: создать LUKS-контейнер (dd + cryptsetup luksFormat), ключ-файл зашифровать age, записать как `<dir>/store.tomb.key.age`
- `Open(dir, timer)`: расшифровать ключ age → cryptsetup luksOpen → mount → состояние в State
- `Close(dir, force)`: umount → cryptsetup luksClose → удалить ключ из RAM
- `Status(dir)`: проверить mapper и mount point
- Keyfile: 512 bytes random, encrypted to store recipients, stored alongside the container
- Container path: `<dir>/store.tomb` (sparse file, size from `--size`)
- Root/polkit: вернуть `ErrNeedRoot` если нет прав. Не пытаться обойти.
- **Совместимость с pass-tomb**: контейнер, созданный `pass tomb`, должен открываться. Проверить на реальном контейнере.

**DoD**:
- [ ] Init/Open/Close/Status реализованы
- [ ] `TestLUKS_*` в привилегированном Docker-раннере (`--privileged`, `/dev/loop`)
- [ ] pass-tomb interop: открыть контейнер, созданный `pass tomb init`
- [ ] ErrNeedRoot возвращается без root
- [ ] Force close пропускает sync перед umount
- [ ] Ключ-файл shred'ится из RAM после luksOpen

**Тестовая среда**: Docker с `--privileged --device /dev/loop-control`, `cryptsetup` установлен.

---

## T2: Sparsebundle backend (macOS)

**Приоритет**: medium

**Что**: Реализовать `pkg/tomb/sparsebundle_darwin.go` — encrypted APFS sparse bundle через `hdiutil`.

**Требования**:

- `Init(dir, rcp, size)`: `hdiutil create -size <size> -type SPARSEBUNDLE -encryption AES-256 -fs APFS`, ключ в Keychain или age-encrypted keyfile
- `Open(dir, timer)`: `hdiutil attach -mountpoint`, пароль из keychain или age-decrypted
- `Close(dir, force)`: `hdiutil detach`, forget key from keychain
- `Status(dir)`: проверить mount point
- Sparse bundle path: `<dir>/store.sparsebundle`

**DoD**:
- [ ] Init/Open/Close/Status реализованы
- [ ] `TestSparseBundle_*` на macOS-раннере (или skipped с `-short` если раннера нет)
- [ ] Keychain integration: ключ хранится в Keychain, не в файле
- [ ] hdiutil errors правильно классифицированы

---

## T3: Screen lock auto-close на macOS

**Приоритет**: medium (M5 критерий из §14)

**Что**: Реализовать IOKit-нотификации для детекции блокировки экрана на macOS.

**Требования**:

- Заменить timer-only `watcher_other.go` на platform-specific `watcher_darwin.go`
- Использовать IOKit (`kIOMessageSystemWillSleep`, display sleep/wake) через `exec("ioreg")` или CGO-free wrapper
- Альтернатива: мониторить `ioreg -l -w0 | grep -i "DisplaySleep"` или использовать `pmset log` через exec
- Fallback на timer если IOKit недоступен (headless macOS)

**DoD**:
- [ ] `watcher_darwin.go` реализован
- [ ] Screen lock detection работает на macOS (тест на CI или manual)
- [ ] Fallback на timer если IOKit недоступен
- [ ] `DoctorCheck()` на macOS возвращает статус IOKit

---

## T4: Screen lock auto-close на Windows

**Приоритет**: low (M5 критерий, но Windows — не primary target)

**Что**: Реализовать WinAPI-нотификации для детекции блокировки экрана на Windows.

**Требования**:

- Заменить timer-only `watcher_other.go` на platform-specific `watcher_windows.go`
- Использовать `WTSSessionNotification` или `SystemParametersInfo` через `syscall.Windows`
- Fallback на timer если WinAPI недоступен

**DoD**:
- [ ] `watcher_windows.go` реализован
- [ ] Screen lock detection работает на Windows
- [ ] Fallback на timer если WinAPI недоступен
- [ ] `DoctorCheck()` на Windows возвращает статус

---

## T5: Streaming packEncrypt

**Приоритет**: medium

**Что**: Убрать `bytes.Buffer` из `packEncrypt`, заменить на pipe `tar writer → age encrypt → file`.

**Проблема**: Сейчас полный tar архив собирается в памяти. Store >100MB → OOM или чрезмерный RSS. В коде есть TODO.

**Требования**:

- `packEncrypt` должен писать: `tar.NewWriter(age.Encrypt(file))` — без промежуточного буфера
- `writeTar` писать в `io.Writer`, не возвращать `[]byte`
- Проверить что atomic write (tmp + rename) сохраняется
- Peak memory: O(chunk) вместо O(store size)

**DoD**:
- [ ] `bytes.Buffer` убран из `packEncrypt`
- [ ] Peak memory не зависит от store size (проверить с `runtime.MemStats` в тесте)
- [ ] Все существующие тесты проходят без изменений
- [ ] Atomic write (tmp + rename) сохраняется

---

## T6: Identity key zeroization

**Приоритет**: low

**Что**: Explicit zeroize private key material после использования.

**Проблема**: `age.X25519Identity` не экспортит private key bytes. Go GC соберёт, но timing не детерминирован. В open session приватный ключ жив в `Coffin.identities` всё время.

**Подход**:
- Опция 1: fork `x25519` key exchange, хранить `[32]byte` напрямую, zeroize после использования
- Опция 2: обернуть identity в struct с `defer zeroize`, вызывать после `unpackDecrypt`
- Опция 3: признать что Go GC + mlock достаточно для M5, zeroization — nice-to-have

**DoD**:
- [ ] Выбран подход и реализован
- [ ] Ключ zeroize'ится явно после `unpackDecrypt`
- [ ] Тест: после zeroize key material — все нули (unsafe или reflect)

---

## T7: tar.TypeLink (hardlinks)

**Приоритет**: low

**Что**: Обработать hardlinks в `readTar` — сейчас молча пропускаются.

**Требования**:
- `writeTar`: skip hardlinks (password stores не должны содержать hardlinks, аналогично symlink)
- `readTar`: reject `tar.TypeLink` с понятной ошибкой
- Test: `TestReadTarRejectsHardlink`

**DoD**:
- [ ] `tar.TypeLink` rejected в `readTar`
- [ ] `writeTar` пропускает hardlinks
- [ ] Тест добавлен

---

## T8: trimSpace + \\r

**Приоритет**: low

**Что**: `trimSpace` в `coffin.go` не обрабатывает `\r` (Windows line endings).

**Проблема**: `.age-recipients` файл с `\r\n` (Windows git checkout) → recipient string содержит `\r` → age parse error → Close fails.

**Fix**: добавить `\r` в `trimSpace`.

**DoD**:
- [ ] `trimSpace` обрабатывает `\r`
- [ ] Тест: `.age-recipients` с `\r\n` корректно парсится

---

## T9: mlock munmap cleanup

**Приоритет**: low

**Что**: mmap'd regions в `mlock_linux.go` не munmap'ятся до process exit. `MAP_SHARED + overwriteRandom` инвалидирует mapping, но inode не freed.

**Подход**:
- Вызвать `unix.Munmap` после `overwriteRandom`
- Или: не использовать mmap, использовать `unix.Mlock` на slice (simpler)
- Проверить что RSS не растёт при многократных open/close циклах

**DoD**:
- [ ] `Munmap` вызывается после использования
- [ ] RSS стабилен при 100 open/close циклах
- [ ] Тест на Linux

---

## Вопросы к архитектуре (§15.4)

1. **Windows и tomb**: Coffin работает, LUKS нет, VHDX+BitLocker требует Pro-редакцию. Достаточно coffin или нужен третий бэкенд под Windows?
2. **LUKS interop**: pass-tomb использует конкретный layout (keyfile в GPG, container naming). Нужна ли двусторонняя совместимость или достаточно "открыть контейнер, созданный pass-tomb"?
3. **Keyfile management**: для LUKS ключ-файл зашифрован age. Должен ли он храниться внутри store dir или рядом? Если внутри — chicken-and-egg при open.
4. **Sparse bundle + Keychain**: macOS Keychain требует user interaction при первом access. Это блокирующая операция в `Open`. Допустимо ли? Альтернатива — age-encrypted keyfile без Keychain.
