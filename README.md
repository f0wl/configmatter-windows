# configmatter-windows

ConfigMatter is a static configuration extractor implemented in Golang for BlackMatter Ransomware (targeting Microsoft Windows). By default the script will print the extracted information to stdout (using the ```-v``` (verbose) flag is recommended for deeper investigations (hexdump, debug information in case of errors). It is also capable of dumping the malware configuration to disk as a JSON file with the ```-j``` flag.

### Usage 

```shell
go run configmatter-windows.go [-v] [-j] path/to/sample.exe
```
### Screenshots

![Running the script](img/tool.png)

## Sources/Credits

Contrary to [Darkside-Config-Extract](https://github.com/advanced-threat-research/DarkSide-Config-Extract) developed by the McAfee Advanced Threat Research Team, which can handle both Darkside and BlackMatter samples, ConfigMatter can only extract BlackMatter configs. Since the Config Extractor by McAfee ATR is only available as a pre-compiled binary I decided to make my implementation public as well.

BlackMatter Ransomware and its configuration structure was covered in an [article](https://blog.group-ib.com/blackmatter) by Andrey Zhdanov for Group IB.

## Configuration structure

![Encrypted and compressed configuration](img/hex-enccomp.png)


![Encrypted and compressed configuration](img/hex-dec.png)
