# seal — Simple File Encryptor

`seal` is a minimal CLI tool for encrypting and decrypting files.

## Usage

```
seal <MODE> [OPTIONS]
```

### Modes

```
encrypt, e    Encrypt file
decrypt, d    Decrypt file
help, h       Show this message
```

### Options

```
-i, --input PATH     Input file path (required)
-o, --output PATH    Output file path (required)
-O, --override       Override output file if it already exists
```

## Examples

### Encrypt a file

```
seal encrypt -i plain.txt -o encrypted.bin
```

or:

```
seal e -i plain.txt -o encrypted.bin
```

### Decrypt a file

```
seal decrypt -i encrypted.bin -o decrypted.txt
```

or:

```
seal d -i encrypted.bin -o decrypted.txt
```

### Override output file

```
seal e -i file.txt -o out.bin -O
```

## Notes

* Both input and output paths are required.
* Use `-O` to overwrite an existing output file.
* Make sure the file paths are valid before running.

## License

[GPL-3.0](LICENSE)
