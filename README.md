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

BlackMatter Ransomware and its configuration structure was covered in an [article](https://blog.group-ib.com/blackmatter) by Andrey Zhdanov for Group IB, which was quite helpful.

## Configuration structure

The first dword (green) contains the seed value for the decryption algorithm. The second dword (yellow) indicates the size of the following encrypted+compressed configuration (red).

![Encrypted and compressed configuration](img/hex-enccomp.png)

To extract the configuration we first need to decrypt it (Link to the [Implementation](https://github.com/f0wl/configmatter-windows/blob/4f1ada60bd47909dead8d424dc71cad776e56cf8/configmatter-windows.go#L117)). After that we can decompress the aPlib-compressed data. The result can be seen below: The first 80 bytes contain the RSA-1024 Public Key (red). After that we can find the victim ID (blue) and the AES Key (orange) used for encrypted information exfiltration. The following 8 bytes (green) define whether core capabilities of the ransomware are enabled or disbled. The yellow highlighed Bytes could not be identified yet. Lastly the configuration contains base64 encoded strings (pink) like for example process and service lists, exfiltration domains or the encrypted victim credentials and ransomnote.

![Encrypted and compressed configuration](img/hex-dec.png)

## Testing

This configuration extractor has been tested successfully with the following samples:

|                             SHA-256                              |                     Sample                              |
| :--------------------------------------------------------------: | :-----------------------------------------------------: |
| 22d7d67c3af10b1a37f277ebabe2d1eb4fd25afbd6437d4377400e148bcc08d6 | [Malshare](https://malshare.com/sample.php?action=detail&hash=22d7d67c3af10b1a37f277ebabe2d1eb4fd25afbd6437d4377400e148bcc08d6) |
| b824bbc645f15e213b4cb2628f7d383e9e37282059b03f6fe60f7c84ea1fed1f | [MalwareBazaar](https://malshare.com/sample.php?action=detail&hash=b824bbc645f15e213b4cb2628f7d383e9e37282059b03f6fe60f7c84ea1fed1f) |
| daed41395ba663bef2c52e3d1723ac46253a9008b582bb8d9da9cb0044991720 | [Malshare](https://malshare.com/sample.php?action=detail&hash=daed41395ba663bef2c52e3d1723ac46253a9008b582bb8d9da9cb0044991720) |
| 7f6dd0ca03f04b64024e86a72a6d7cfab6abccc2173b85896fc4b431990a5984 | [MalwareBazaar](https://bazaar.abuse.ch/sample/7f6dd0ca03f04b64024e86a72a6d7cfab6abccc2173b85896fc4b431990a5984) |

If you encounter an error with ConfigMatter, please file a bug report via an issue. Contributions are always welcome :)
