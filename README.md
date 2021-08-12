# configmatter-windows

ConfigMatter is a static configuration extractor implemented in Golang for BlackMatter Ransomware (targeting Microsoft Windows). By default the script will print the extracted information to stdout (using the ```-v``` (verbose) flag is recommended for deeper investigations (hexdump, debug information in case of errors). It is also capable of dumping the malware configuration to disk as a JSON file with the ```-j``` flag.

### Usage 

```shell
go run configmatter-windows.go [-v] [-j] path/to/sample.exe
```
### Screenshots

![Running the script](img/tool.png)

## Sources/Credits

## Configuration structure

![Encrypted and compressed configuration](img/hex-enccomp.png)


![Encrypted and compressed configuration](img/hex-dec.png)
