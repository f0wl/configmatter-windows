// ┌──────────────────────────────────┐
// │ Marius 'f0wL' Genheimer, 2021    │
// └──────────────────────────────────┘

package main

import (
	"crypto/md5"
	"crypto/sha256"
	"debug/pe"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/fatih/color"
	"github.com/hatching/aplib"
)

// check errors as they occur and panic :o
func check(e error) {
	if e != nil {
		panic(e)
	}
}

// ioReader acts as a wrapper function to make opening the file even easier
func ioReader(file string) io.ReaderAt {
	r, err := os.Open(file)
	check(err)
	return r
}

// calcSHA256 reads the sample file and calculates its SHA-256 hashsum
func calcSHA256(file string) string {
	f, readErr := os.Open(file)
	check(readErr)
	defer f.Close()

	h := sha256.New()
	_, hashErr := io.Copy(h, f)
	check(hashErr)
	return hex.EncodeToString(h.Sum(nil))
}

// calcMD5 reads the sample file and calculates its SHA-256 hashsum
func calcMD5(file string) string {

	f, readErr := os.Open(file)
	check(readErr)
	defer f.Close()

	h := md5.New()
	_, hashErr := io.Copy(h, f)
	check(hashErr)
	return hex.EncodeToString(h.Sum(nil))
}

// getFileInfo returns the size on disk of the specified file
func getFileInfo(file string) int64 {
	f, readErr := os.Open(file)
	check(readErr)
	defer f.Close()

	fileInfo, fileErr := f.Stat()
	check(fileErr)

	return fileInfo.Size()
}

// i32toB converts an uint32 to a byte slice (dword)
func i32toB(val uint32) []byte {
	r := make([]byte, 4)
	for i := uint32(0); i < 4; i++ {
		r[i] = byte((val >> (8 * i)) & 0xff)
	}
	return r
}

// byteToBool converts a config byte to a boolean value
func byteToBool(b []byte) bool {
	bstr := hex.EncodeToString(b)
	if bstr == "00" {
		return false
	} else if bstr == "01" {
		return true
	}
	return false
}

// removeEmptyStrings removes empty string values inside an array
// https://gist.github.com/johnpili/84c3064d30a9b041c87e43ba4bcb63a2
func removeEmptyStrings(s []string) []string {
	var r []string
	for _, str := range s {
		if str != "\x00\x00" {
			r = append(r, str)
		}
	}
	return r
}

// base64Decode decodes a base64 encoded byte slice
func base64Decode(message []byte) (b []byte) {
	b = make([]byte, base64.StdEncoding.DecodedLen(len(message)))
	l, b64Err := base64.StdEncoding.Decode(b, message)
	check(b64Err)
	return b[:l]
}

// blackMatterConfigDecrypt re-implements the algorithm to decrypt the config + credentials and ransomnote within
func configDecryptV1(ciphertext []byte, startValue uint32) []byte {
	var plaintext []byte
	var step, dword uint32
	seed := uint64(startValue)

	for i := 0; i < len(ciphertext); {
		dword = binary.LittleEndian.Uint32(ciphertext[i : i+4])
		seed = (0x8088405*seed + 1) & 0xFFFFFFFF
		xorkey := (seed * uint64(startValue)) >> 32
		step = dword ^ uint32(xorkey)
		plaintext = append(plaintext, i32toB(step)...)
		i += 4
	}

	return plaintext
}

// genKeystreamV3 implements the PCG PRNG used to create the XOR Keystream
func genKeystreamV3(startValue uint64, keyLen int) []byte {
	var keyData []byte

	step := startValue
	for i := 0; i < keyLen; {
		step = (0x5851F42D4C957F2D*step + 0x14057B7EF767814F) & 0xFFFFFFFFFFFFFFFF
		// additional multiplication
		mult := (step * startValue) & 0xFFFFFFFFFFFFFFFF

		qword_tmp := make([]byte, 8)
		binary.LittleEndian.PutUint64(qword_tmp, mult)
		keyData = append(keyData, qword_tmp...)
		i += 8
	}
	return keyData
}

// configDecryptV3 implements the XOR decryption algorithm used in BlackMatter Ransomware V2.x and V3.x
func configDecryptV3(ciphertext []byte, xorKeystream []byte, configLen int) []byte {
	plaintext := make([]byte, configLen)

	for i := 0; i < configLen-14; {
		plaintext[i] = ciphertext[i] ^ xorKeystream[i]
		plaintext[i+1] = ciphertext[i+1] ^ xorKeystream[i+5]
		plaintext[i+2] = ciphertext[i+2] ^ xorKeystream[i+1]
		plaintext[i+3] = ciphertext[i+3] ^ xorKeystream[i+4]
		plaintext[i+4] = ciphertext[i+4] ^ xorKeystream[i+2]
		plaintext[i+5] = ciphertext[i+5] ^ xorKeystream[i+7]
		plaintext[i+6] = ciphertext[i+6] ^ xorKeystream[i+3]
		plaintext[i+7] = ciphertext[i+7] ^ xorKeystream[i+6]
		i += 8
	}

	return plaintext
}

// Flag variables for commandline arguments
var verboseFlag bool
var jsonFlag bool
var versionFlag int

type b64Str struct {
	FolderHashes    []byte   `json:"folderHashes"`    // exclusion list of 4 byte hashes of folder names
	FileHashes      []byte   `json:"fileHashes"`      // exclusion list of 4 byte hashes of file names
	ExtensionHashes []byte   `json:"extensionHashes"` // exclusion list of 4 byte hashes of file extensions
	Processes       []string `json:"processes"`       // Substrings of processes to be killed
	Services        []string `json:"services"`        // Services to be killed
	ExfilServers    []string `json:"exfilServers"`    // Domains of the Data Exfiltration servers
	Credentials     []string `json:"credentials"`     // Compromised credentials of the targeted organization
	Ransomnote      string   `json:"Ransomnote"`      // Ransomnote that is dropped after encryption
}

type boolCfg struct {
	EncryptOddMB     bool `json:"encryptOdd"`           // Encrypt odd megabytes in large files
	AttemptAuth      bool `json:"attemptAuth"`          // Attempt to authenticate with compromised credentials
	MountVolumes     bool `json:"mountVolumes"`         // Mount attached volumes
	EncryptNetShares bool `json:"encryptNetworkShares"` // Encrypt files on network shares
	KillProcesses    bool `json:"killProcesses"`        // Kill processes matching the substring list
	StopServices     bool `json:"stopServices"`         // Stop services that are contained in the list
	CreateMutex      bool `json:"createMutex"`          // Create a Mutex to prevent multiple executions
	PrintRansomnote  bool `json:"printRansomnote"`      // Print out the ransomnote on the users default local printer
	ExfilInfo        bool `json:"exfilAttackInfo"`      // Report back information about the system to the attacker servers
}

// Structure to store extracted config information
type blackmatterConfig struct {
	Keyblob        []byte  `json:"rsaKeyblob"`     // RSA-1024 Public Key
	VictimID       []byte  `json:"victimID"`       // bot_company
	AESKey         []byte  `json:"aesKey"`         // AES-ECB-128 Key for Exfil communication
	BooleanConfig  boolCfg `json:"booleanConfig"`  // 8 Byte Boolean config
	ConfigOffsets  []byte  `json:"configOffsets"`  // Offsets of the following config contents
	Base64Contents b64Str  `json:"base64Contents"` // base64 encoded strings
}

func main() {

	fmt.Printf("\n             *       +")
	fmt.Printf("\n       '                  |          ___           __ _      __  __      _   _         ")
	fmt.Printf("\n   ()    .-.,=''''=.    - o -       / __|___ _ _  / _(_)__ _|  \\/  |__ _| |_| |_ ___ _ _ ")
	fmt.Printf("\n         '=/_       \\     |        | (__/ _ \\ ' \\|  _| / _` | |\\/| / _` |  _|  _/ -_) '_|")
	fmt.Printf("\n      *   |  '=._    |              \\___\\___/_||_|_| |_\\__, |_|  |_\\__,_|\\__|\\__\\___|_| ")
	fmt.Printf("\n           \\     `=./`,        '                       |___/                               ")
	fmt.Printf("\n        .   '=.__.=' `='      *")
	fmt.Printf("\n  +                       +         BlackMatter Windows Ransomware Configuration Extractor")
	fmt.Printf("\n    O      *        '       .       Marius 'f0wL' Genheimer | https://dissectingmalwa.re\n\n")

	// parse passed flags
	flag.BoolVar(&jsonFlag, "j", false, "Write extracted config to a JSON file")
	flag.BoolVar(&verboseFlag, "v", false, "Verbose output")
	flag.IntVar(&versionFlag, "version", 3, "Specify the version of the BlackMatter ransomware sample: 1 for v1.x, 2 for v2.x, 3 for v3.x")
	flag.Parse()

	if flag.NArg() == 0 {
		color.Red("✗ No path to sample provided.\n\n")
		os.Exit(1)
	}

	// calculate hash sums of the sample
	md5sum := calcMD5(flag.Args()[0])
	sha256sum := calcSHA256(flag.Args()[0])

	w1 := tabwriter.NewWriter(os.Stdout, 1, 1, 1, ' ', 0)
	fmt.Fprintln(w1, "→ File size (bytes): \t", getFileInfo(flag.Args()[0]))
	fmt.Fprintln(w1, "→ Sample MD5: \t", md5sum)
	fmt.Fprintln(w1, "→ Sample SHA-256: \t", sha256sum)
	w1.Flush()

	// ┌────────────────────────────────────────────────────────────────────────────────────────┐
	// │ Parsing the PE file, extracting the encrypted config and decrypting+decompressing it   │
	// └────────────────────────────────────────────────────────────────────────────────────────┘

	// read the PE
	sample := ioReader(flag.Args()[0])

	// parse the PE with debug/pe
	pe, parseErr := pe.NewFile(sample)
	check(parseErr)

	// dump out the contents of the .rsrc section
	sectionData, dumpErr := pe.Section(".rsrc").Data()
	check(dumpErr)

	if verboseFlag {
		color.Green("\n✓ Successfully dumped the .rsrc section")
	}

	var plainComp []byte
	var algStart_v1 uint32
	var algStart_v2 uint64
	var configLength int
	var xorKeystream []byte

	if versionFlag == 1 {

		// at the start of the config we can find two dwords containing the seed
		//value for the decryption algorithm and the length of the config
		algStart_v1 = binary.LittleEndian.Uint32(sectionData[:4])
		configLength = int(binary.LittleEndian.Uint32(sectionData[4:8])) + 8
		encryptedConfig := sectionData[8:configLength]

		// decrypt the config
		plainComp = configDecryptV1(encryptedConfig, algStart_v1)

	} else if versionFlag == 2 || versionFlag == 3 {

		// at the start of the V2/V3 config we can find two dwords containing
		//the seed value for the decryption algorithm and the length of the config
		algStart_v2 = binary.LittleEndian.Uint64(sectionData[:8])
		configLength = int(binary.LittleEndian.Uint32(sectionData[8:12])) + 14
		encryptedConfig := sectionData[12:configLength]

		// generate the keystream for the XOR operations
		xorKeystream = genKeystreamV3(algStart_v2, configLength)

		if verboseFlag {
			// Debugging printout for decryption data
			fmt.Printf("\n→ PCG Seed: 0x%x\n", algStart_v2)
			fmt.Printf("→ Config length: 0x%x\n\n", configLength)
			fmt.Printf("→ Compressed length: 0x%x\n\n", len(encryptedConfig))
			fmt.Printf("→ First 32 bytes of the XOR Keystream: \n%v\n", hex.Dump(xorKeystream[:32]))
		}

		// decrypt the config
		plainComp = configDecryptV3(encryptedConfig, xorKeystream, configLength)

		if verboseFlag {
			fmt.Printf("→ First 32 bytes of the decrypted config: \n%v\n", hex.Dump(plainComp[:32]))
		}

	}

	// the now decrypted config is compressed with aPlib, so we have to decompress it
	// the aPlib package is provided by Hatching.io, thanks :D
	plainDecomp := aplib.Decompress(plainComp)

	if verboseFlag {
		color.Green("\n✓ Decompressed config dump:")
		fmt.Print(hex.Dump(plainDecomp))
	}

	// ┌──────────────────────────────────────────────────────────────────────┐
	// │  Extracting information from the decrypted configuration.            │
	// │  For more information about the structure of the configuration       │
	// │  check out the README (https://github.com/f0wl/configmatter-windows) │
	// └──────────────────────────────────────────────────────────────────────┘

	var cfg blackmatterConfig
	var counter int

	cfg.Keyblob = plainDecomp[0:128]
	counter += 128
	cfg.VictimID = plainDecomp[counter : counter+16]
	counter += 16
	cfg.AESKey = plainDecomp[counter : counter+16]
	counter += 16
	cfg.BooleanConfig.EncryptOddMB = byteToBool(plainDecomp[counter : counter+1])
	counter += 1
	cfg.BooleanConfig.AttemptAuth = byteToBool(plainDecomp[counter : counter+1])
	counter += 1
	cfg.BooleanConfig.MountVolumes = byteToBool(plainDecomp[counter : counter+1])
	counter += 1
	cfg.BooleanConfig.EncryptNetShares = byteToBool(plainDecomp[counter : counter+1])
	counter += 1
	cfg.BooleanConfig.KillProcesses = byteToBool(plainDecomp[counter : counter+1])
	counter += 1
	cfg.BooleanConfig.StopServices = byteToBool(plainDecomp[counter : counter+1])
	counter += 1
	cfg.BooleanConfig.CreateMutex = byteToBool(plainDecomp[counter : counter+1])
	counter += 1
	if versionFlag == 1 {

		cfg.BooleanConfig.ExfilInfo = byteToBool(plainDecomp[counter : counter+1])
		counter += 1
		cfg.ConfigOffsets = plainDecomp[counter : counter+36]
		counter += 36

	} else if versionFlag == 2 || versionFlag == 3 {

		// the config option to physically print the ransomnote was introduced in BM version 2.0
		cfg.BooleanConfig.PrintRansomnote = byteToBool(plainDecomp[counter : counter+1])
		counter += 1
		cfg.BooleanConfig.ExfilInfo = byteToBool(plainDecomp[counter : counter+1])
		counter += 1
		cfg.ConfigOffsets = plainDecomp[counter : counter+44]
		counter += 44

	}

	// base64 strings in the config are separated by a nullbyte
	base64Spilt := strings.Split(string(plainDecomp[counter:]), "\x00")

	// loop through the base64 encoded strings and decode them
	for s := range base64Spilt {

		base64Spilt[s] = string(base64Decode([]byte(base64Spilt[s])))

	}

	length := len(base64Spilt)

	// the three unknown strings likely contain hashes of files and directories to be skipped
	// I still need to confirm this myself
	cfg.Base64Contents.FolderHashes = []byte(base64Spilt[0])
	cfg.Base64Contents.FileHashes = []byte(base64Spilt[1])
	cfg.Base64Contents.ExtensionHashes = []byte(base64Spilt[2])

	// extracting the lists of process substrings and services
	// the strings are split on three nullbytes into the string array in the structure
	cfg.Base64Contents.Processes = removeEmptyStrings(strings.Split(base64Spilt[3], "\x00\x00\x00"))
	cfg.Base64Contents.Services = removeEmptyStrings(strings.Split(base64Spilt[4], "\x00\x00\x00"))

	// if information edxfiltration is disabled there is no Server or Credentials string in the config
	if cfg.BooleanConfig.ExfilInfo {
		cfg.Base64Contents.ExfilServers = removeEmptyStrings(strings.Split(base64Spilt[length-4], "\x00\x00\x00"))

		// the compromised credentials are encrypted with the same algorithm as the config itself
		if versionFlag == 1 {

			cfg.Base64Contents.Credentials = removeEmptyStrings(strings.Split(string(configDecryptV1([]byte(base64Spilt[length-3]), algStart_v1)), "\x00\x00\x00"))

		} else if versionFlag == 2 || versionFlag == 3 {

			cfg.Base64Contents.Credentials = removeEmptyStrings(strings.Split(string(configDecryptV3([]byte(base64Spilt[length-3]), xorKeystream, len(base64Spilt[length-3]))), "\x00\x00\x00"))

		}
	}

	if versionFlag == 1 {

		// decrypting the ransomnote, same algorithm again
		cfg.Base64Contents.Ransomnote = string(configDecryptV1([]byte(base64Spilt[length-2]), algStart_v1))

	} else if versionFlag == 2 || versionFlag == 3 {

		cfg.Base64Contents.Ransomnote = string(configDecryptV3([]byte(base64Spilt[length-2]), xorKeystream, len(base64Spilt[length-2])))

	}

	// printing the extracted information to stdout
	color.Green("\n✓ Extracted configuration:\n\n")
	w2 := tabwriter.NewWriter(os.Stdout, 1, 1, 1, ' ', 0)
	fmt.Fprintln(w2, "→ RSA-1024 Public-Key Blob: \t", hex.EncodeToString(cfg.Keyblob))
	fmt.Fprintln(w2, "→ Victim ID: \t", hex.EncodeToString(cfg.VictimID))
	fmt.Fprintln(w2, "→ AES Key: \t", hex.EncodeToString(cfg.AESKey))
	fmt.Fprintln(w2, "\n→ Encrypt odd Megabytes: \t", cfg.BooleanConfig.EncryptOddMB)
	fmt.Fprintln(w2, "→ Attempt Authentication: \t", cfg.BooleanConfig.AttemptAuth)
	fmt.Fprintln(w2, "→ Mount Volumes: \t", cfg.BooleanConfig.MountVolumes)
	fmt.Fprintln(w2, "→ Encrypt Network Shares: \t", cfg.BooleanConfig.EncryptNetShares)
	fmt.Fprintln(w2, "→ Kill Processes w/ substrings: \t", cfg.BooleanConfig.KillProcesses)
	fmt.Fprintln(w2, "→ Stop Services: \t", cfg.BooleanConfig.StopServices)
	fmt.Fprintln(w2, "→ Create Mutex: \t", cfg.BooleanConfig.CreateMutex)
	fmt.Fprintln(w2, "→ Exfiltrate Information: \t", cfg.BooleanConfig.ExfilInfo)
	fmt.Fprintln(w2, "\n→ Process Substrings: \t", cfg.Base64Contents.Processes)
	fmt.Fprintln(w2, "→ Services: \t", cfg.Base64Contents.Services)
	fmt.Fprintln(w2, "→ Data Exfiltration Servers: \t", cfg.Base64Contents.ExfilServers)
	fmt.Fprintln(w2, "→ Compromised Credentials: \t", cfg.Base64Contents.Credentials)
	w2.Flush()

	color.Green("\n✓ Ransomnote:\n\n")
	fmt.Printf(cfg.Base64Contents.Ransomnote)
	print("\n")

	// if the program is run with -j the configuration will be written to disk in a JSON file
	if jsonFlag {

		// marshalling the config struct into a JSON string
		data, _ := json.Marshal(cfg)
		jsonString := string(data)
		// strip the unicode garbage
		jsonString = strings.ReplaceAll(jsonString, `\u0000`, "")

		// concat the filename for the json file output
		filename := "config-" + md5sum + ".json"

		// write the JSON string to a file
		jsonOutput, writeErr := os.Create(filename)
		check(writeErr)
		defer jsonOutput.Close()
		n3, err := jsonOutput.WriteString(jsonString)
		check(err)
		color.Green("\n✓ Wrote %d bytes to %v\n\n", n3, filename)
		jsonOutput.Sync()

	}
}
