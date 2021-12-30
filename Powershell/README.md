## Northstar-Launcher.ps1

Ensures there are certain number of Northstar Instaces running at any time.

## GUIDE

1) Copy Northstar-Launcher.ps1 to: `C:\Program Files (x86)\Origin Games\Titanfall2`

2) Import the functions in powershell file by running:
```ps1
. .\Northstar-Launcher.ps1
```
Note: if you get `cannot be loaded because the execution of scripts is disabled on this system` error, read the following post: https://stackoverflow.com/a/9167524/9296389

3) Run `EnsureNorthstarRunning` function(MAKE SURE YOU SET THE PARAMETERS THAT ARE RIGHT FOR YOUR ENVIRONMENT):
```ps1
EnsureNorthstarRunning -runningInstances 1 -serverPrefix "MyOwnServer" -serverRegion "US-East" -TCPPortMin 8081 -TCPPortMax 8081 -UDPPortMin 37015 -UDPPortMax 37015
```

You are also allowed to provide an array of availiable ports, instead of a range using -TCPPortList and -UDPPortList instead of TCPPortMin-TCPPortMax, UDPPortMin-UDPPortMax.
