# Evosec

## Installation
Install `qt` (version >= 5.5) and `openssl`


1 . Delete first 512 bytes from original file
```bash
   tail -c 513 main.cvd > archive
   tar xzvf archive
```
2 . Insert signature of virus.bin into database
```bash
    sigtool --md5 virus.bin >> main.hdb
```
3 . Compile the engine
```bash
    cd src/engine
    make
```

4 . Run an example
```bash
    cd ../examples
    ./main file1 file2
```

5 . Compile GUI
    cd ../gui
    `qmake && make`

6 . Enjoy!

<img src="https://github.com/vient/evosec_code/blob/master/gui.tiff" />
