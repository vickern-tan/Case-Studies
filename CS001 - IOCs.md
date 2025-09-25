
## Indicators of Compromise (IOCs)

> Suspicious activity consistent with potential exploitation of a SharePoint vulnerability was observed on a SharePoint host. Multiple alerts reported unusual DLL and ASPX files being deployed within the SharePoint web directory, indicating possible remote code execution (RCE).

|Type|Value / Pattern|Notes / Context|
|---|---|---|
|IP Address|`45.136.197.24`|Served payloads over HTTP (`:10888`, `:7933`); endpoints like `/asx`, `/asd`, `/1`–`/4`.|
|IP Address|`5.182.38.97`|Contacted via `Invoke-WebRequest` (purpose unclear).|
|IP Address|`179.43.141.208`|External host observed in telemetry.|
|IP Address|`38.47.124.201`|External host observed in telemetry.|
|Domain|`trryuphx.requestrepo[.]com`|Used for **HTTP POST exfil** (`whoami /all`, `dir`, `appcmd`, etc.).|
|Domain|`mpf1oyds.requestrepo[.]com`|Used for **HTTP POST exfil** and directory listings.|
|Domain|`cdn-chromos.s3.amazonaws[.]com/dWrJQTINu3`|Plain-HTTP **binary delivery** to `C:\Users\Public\Downloads\1.exe`.|
|URL|`hxxp://[C2_IP]:10888/asx` / `/asd` / `/1`–`/4`|Payload endpoints; some saved as EXE/DLL in `AppData\Local\...`.|
|File Path|`C:\Users\[SERVICE_ACCOUNT]\AppData\Local\SPDesk.exe`|Downloaded executable.|
|File Path|`C:\Users\[SERVICE_ACCOUNT]\AppData\Local\SPlog.exe`|Downloaded executable.|
|File Path|`C:\Users\[SERVICE_ACCOUNT]\AppData\Local\log.dll`|Downloaded DLL.|
|File Path|`C:\Users\[SERVICE_ACCOUNT]\AppData\Local\Product.Wsc.dll`|Downloaded DLL.|
|File Path|`C:\Users\[SERVICE_ACCOUNT]\AppData\Local\nvsmartmax64.dll`|Downloaded DLL.|
|File Path|`C:\Users\[SERVICE_ACCOUNT]\AppData\Local\txmlutil.dll`|Downloaded DLL.|
|File Path|`C:\ProgramData\defender.log`|Read and exfiltrated via HTTP POST.|
|File Path|`C:\inetpub\wwwroot\wss\VirtualDirectories\80\App_GlobalResources\0.css`|File-write via `cmd.exe` echo; used to verify write permissions.|
|File Path|`C:\PROGRA~1\COMMON~1\MICROS~1\WEBSER~1\16\TEMPLATE\LAYOUTS\spinstall0.aspx`|**Web shell** path written by decoded `-EncodedCommand`.|
|Process|`w3wp.exe → powershell.exe` / `cmd.exe`|IIS worker spawning PowerShell/Command Prompt.|
|Technique|`PowerShell -EncodedCommand`|Base64-encoded payload writes ASPX into SharePoint LAYOUTS.|



## File Hashes (SHA256)

| File Name                                | SHA256                                                             | Notes / Context                      |
|------------------------------------------|--------------------------------------------------------------------|--------------------------------------|
| `.1.avdtwnuschaqsaccnjdxsukiwoqbufpc.__relocated__.exe` | 929e3fdd3068057632b52ecdfd575ab389390c852b2f4e65dc32f20c87521600 | Dropped executable (suspicious)       |
| `nvsmartmax64.dll`                        | 459fc1c142917700a720745d5d99f23d47a60a3c0034dfa405dc9d0061be4519 | Malicious DLL placed in AppData       |
| `1.exe`                                   | 4214016a64f6442c08e9c866c57de1a2ca194c59a74c8c677d1308561df40bd1 | Downloaded binary via S3/CDN endpoint |
