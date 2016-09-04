# Evosec

## Установка
Ставим нужные пакеты:
```bash
    brew install qt
    brew install openssl
```

1 . Удаляем первые 512 байт из исходной файла
```bash
   tail -c 513 main.cvd > archive
   tar xzvf archive
```
2 . Добавляем сигнатуру файла virus.bin в базу с сигнатурами
```bash
    sigtool --md5 virus.bin >> main.hdb
```
3 . Копируем малварный файл в src/examples
```bash
    cp /path/to/malware.exe src/examples
    cd src/examples
    make
```

