## Northstar-Launcher.ps1

Ensures there are certain number of Northstar Instaces running at any time.

Copy Northstar-Launcher.ps1 to `C:\Program Files (x86)\Origin Games\Titanfall2`

Example Use:

```ps1
. .\Northstar-Launcher.ps1 ; EnsureNorthstarRunning -runningInstances 10 -serverPrefix L1ghtman -processPriority High -serverRegion "US-East" -TCPPortMin 7000 -TCPPortMax 10000 -UDPPortMin 35000 -UDPPortMax 39000
```

You are also allowed to provide an array of availiable ports, instead of a range
