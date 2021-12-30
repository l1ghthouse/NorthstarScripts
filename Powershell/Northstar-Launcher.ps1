#https://github.com/RamblingCookieMonster/PowerShell/blob/master/Get-NetworkStatistics.ps1
function Get-NetworkStatistics {
<#
        .SYNOPSIS
            Display current TCP/IP connections for local or remote system
        .FUNCTIONALITY
            Computers
        .DESCRIPTION
            Display current TCP/IP connections for local or remote system.  Includes the process ID (PID) and process name for each connection.
            If the port is not yet established, the port number is shown as an asterisk (*).	
        
        .PARAMETER ProcessName
            Gets connections by the name of the process. The default value is '*'.
        
        .PARAMETER Port
            The port number of the local computer or remote computer. The default value is '*'.
        .PARAMETER Address
            Gets connections by the IP address of the connection, local or remote. Wildcard is supported. The default value is '*'.
        .PARAMETER Protocol
            The name of the Protocol$Protocol (TCP or UDP). The default value is '*' (all)
        
        .PARAMETER State
            Indicates the state of a TCP connection. The possible states are as follows:
            
            Closed       - The TCP connection is closed. 
            Close_Wait   - The local endpoint of the TCP connection is waiting for a connection termination request from the local user. 
            Closing      - The local endpoint of the TCP connection is waiting for an acknowledgement of the connection termination request sent previously. 
            Delete_Tcb   - The transmission control buffer (TCB) for the TCP connection is being deleted. 
            Established  - The TCP handshake is complete. The connection has been established and data can be sent. 
            Fin_Wait_1   - The local endpoint of the TCP connection is waiting for a connection termination request from the remote endpoint or for an acknowledgement of the connection termination request sent previously. 
            Fin_Wait_2   - The local endpoint of the TCP connection is waiting for a connection termination request from the remote endpoint. 
            Last_Ack     - The local endpoint of the TCP connection is waiting for the final acknowledgement of the connection termination request sent previously. 
            Listen       - The local endpoint of the TCP connection is listening for a connection request from any remote endpoint. 
            Syn_Received - The local endpoint of the TCP connection has sent and received a connection request and is waiting for an acknowledgment. 
            Syn_Sent     - The local endpoint of the TCP connection has sent the remote endpoint a segment header with the synchronize (SYN) control bit set and is waiting for a matching connection request. 
            Time_Wait    - The local endpoint of the TCP connection is waiting for enough time to pass to ensure that the remote endpoint received the acknowledgement of its connection termination request. 
            Unknown      - The TCP connection state is unknown.
        
            Values are based on the TcpState Enumeration:
            http://msdn.microsoft.com/en-us/library/system.net.networkinformation.tcpstate%28VS.85%29.aspx
            
            Cookie Monster - modified these to match netstat output per here:
            http://support.microsoft.com/kb/137984
        .PARAMETER ShowHostNames
            If specified, will attempt to resolve local and remote addresses.
        .PARAMETER tempFile
            Temporary file to store results on remote system.  Must be relative to remote system (not a file share).  Default is "C:\netstat.txt"
        .PARAMETER AddressFamily
            Filter by IP Address family: IPv4, IPv6, or the default, * (both).
            If specified, we display any result where both the localaddress and the remoteaddress is in the address family.
        .EXAMPLE
            Get-NetworkStatistics | Format-Table
        .EXAMPLE
            Get-NetworkStatistics iexplore -computername k-it-thin-02 -ShowHostNames | Format-Table
        .EXAMPLE
            Get-NetworkStatistics -ProcessName md* -Protocol tcp
        .EXAMPLE
            Get-NetworkStatistics -Address 192* -State LISTENING
        .EXAMPLE
            Get-NetworkStatistics -State LISTENING -Protocol tcp
        .EXAMPLE
            Get-NetworkStatistics -Computername Computer1, Computer2
        .EXAMPLE
            'Computer1', 'Computer2' | Get-NetworkStatistics
        .OUTPUTS
            System.Management.Automation.PSObject
        .NOTES
            Author: Shay Levy, code butchered by Cookie Monster
            Shay's Blog: http://PowerShay.com
            Cookie Monster's Blog: http://ramblingcookiemonster.github.io/
        .LINK
            http://gallery.technet.microsoft.com/scriptcenter/Get-NetworkStatistics-66057d71
        #>
  [OutputType('System.Management.Automation.PSObject')]
  [CmdletBinding()]
  param(

    [Parameter(Position = 0)]
    [System.String]$ProcessName = '*',

    [Parameter(Position = 1)]
    [System.String]$Address = '*',

    [Parameter(Position = 2)]
    $Port = '*',

    [ValidateSet('*','tcp','udp')]
    [System.String]$Protocol = '*',

    [ValidateSet('*','Closed','Close_Wait','Closing','Delete_Tcb','DeleteTcb','Established','Fin_Wait_1','Fin_Wait_2','Last_Ack','Listening','Syn_Received','Syn_Sent','Time_Wait','Unknown')]
    [System.String]$State = '*',

    [switch]$ShowHostnames,

    [switch]$ShowProcessNames = $true,

    [System.String]$TempFile = "C:\netstat.txt",

    [ValidateSet('*','IPv4','IPv6')]
    [string]$AddressFamily = '*'
  )

  begin {
    #Define properties
    $properties = 'Protocol','LocalAddress','LocalPort','RemoteAddress','RemotePort','State','ProcessName','PID'

    #store hostnames in array for quick lookup
    $dnsCache = @{}

  }

  process {
    #Collect processes
    if ($ShowProcessNames) {
      try {
        $processes = Get-Process -ErrorAction stop | Select-Object name,id
      }
      catch {
        Write-Warning "Could not run Get-Process.  Verify permissions and connectivity.  Defaulting to no ShowProcessNames"
        $ShowProcessNames = $false
      }
    }

    $results = netstat -ano | Select-String -Pattern '\s+(TCP|UDP)'


    #initialize counter for progress
    $totalCount = $results.count
    $count = 0

    #Loop through each line of results    
    foreach ($result in $results) {

      $item = $result.line.split(' ',[System.StringSplitOptions]::RemoveEmptyEntries)

      if ($item[1] -notmatch '^\[::') {

        #parse the netstat line for local address and port
        if (($la = $item[1] -as [ipaddress]).AddressFamily -eq 'InterNetworkV6') {
          $localAddress = $la.IPAddressToString
          $localPort = $item[1].split('\]:')[-1]
        }
        else {
          $localAddress = $item[1].split(':')[0]
          $localPort = $item[1].split(':')[-1]
        }

        #parse the netstat line for remote address and port
        if (($ra = $item[2] -as [ipaddress]).AddressFamily -eq 'InterNetworkV6') {
          $remoteAddress = $ra.IPAddressToString
          $remotePort = $item[2].split('\]:')[-1]
        }
        else {
          $remoteAddress = $item[2].split(':')[0]
          $remotePort = $item[2].split(':')[-1]
        }

        #Filter IPv4/IPv6 if specified
        if ($AddressFamily -ne "*")
        {
          if ($AddressFamily -eq 'IPv4' -and $localAddress -match ':' -and $remoteAddress -match ':|\*')
          {
            #Both are IPv6, or ipv6 and listening, skip
            Write-Verbose "Filtered by AddressFamily:`n$result"
            continue
          }
          elseif ($AddressFamily -eq 'IPv6' -and $localAddress -notmatch ':' -and ($remoteAddress -notmatch ':' -or $remoteAddress -match '*'))
          {
            #Both are IPv4, or ipv4 and listening, skip
            Write-Verbose "Filtered by AddressFamily:`n$result"
            continue
          }
        }

        #parse the netstat line for other properties
        $procId = $item[-1]
        $proto = $item[0]
        $status = if ($item[0] -eq 'tcp') { $item[3] } else { $null }

        #Filter the object
        if ($remotePort -notlike $Port -and $localPort -notlike $Port) {
          Write-Verbose "remote $Remoteport local $localport port $port"
          Write-Verbose "Filtered by Port:`n$result"
          continue
        }

        if ($remoteAddress -notlike $Address -and $localAddress -notlike $Address) {
          Write-Verbose "Filtered by Address:`n$result"
          continue
        }

        if ($status -notlike $State) {
          Write-Verbose "Filtered by State:`n$result"
          continue
        }

        if ($proto -notlike $Protocol) {
          Write-Verbose "Filtered by Protocol:`n$result"
          continue
        }

        #If we are running showprocessnames, get the matching name
        if ($ShowProcessNames -or $PSBoundParameters.ContainsKey -eq 'ProcessName') {

          #handle case where process spun up in the time between running get-process and running netstat
          if ($procName = $processes | Where-Object { $_.id -eq $procId } | Select-Object -ExpandProperty name) {}
          else { $procName = "Unknown" }

        }
        else { $procName = "NA" }

        if ($procName -notlike $ProcessName) {
          Write-Verbose "Filtered by ProcessName:`n$result"
          continue
        }

        #if the showhostnames switch is specified, try to map IP to hostname
        if ($showHostnames) {
          $tmpAddress = $null
          try {
            if ($remoteAddress -eq "127.0.0.1" -or $remoteAddress -eq "0.0.0.0") {
              $remoteAddress = $Computer
            }
            elseif ($remoteAddress -match "\w") {

              #check with dns cache first
              if ($dnsCache.ContainsKey($remoteAddress)) {
                $remoteAddress = $dnsCache[$remoteAddress]
                Write-Verbose "using cached REMOTE '$remoteAddress'"
              }
              else {
                #if address isn't in the cache, resolve it and add it
                $tmpAddress = $remoteAddress
                $remoteAddress = [System.Net.DNS]::GetHostByAddress("$remoteAddress").hostname
                $dnsCache.Add($tmpAddress,$remoteAddress)
                Write-Verbose "using non cached REMOTE '$remoteAddress`t$tmpAddress"
              }
            }
          }
          catch {}

          try {

            if ($localAddress -eq "127.0.0.1" -or $localAddress -eq "0.0.0.0") {
              $localAddress = $Computer
            }
            elseif ($localAddress -match "\w") {
              #check with dns cache first
              if ($dnsCache.ContainsKey($localAddress)) {
                $localAddress = $dnsCache[$localAddress]
                Write-Verbose "using cached LOCAL '$localAddress'"
              }
              else {
                #if address isn't in the cache, resolve it and add it
                $tmpAddress = $localAddress
                $localAddress = [System.Net.DNS]::GetHostByAddress("$localAddress").hostname
                $dnsCache.Add($localAddress,$tmpAddress)
                Write-Verbose "using non cached LOCAL '$localAddress'`t'$tmpAddress'"
              }
            }
          }
          catch {}
        }

        #Write the object	
        New-Object -TypeName PSObject -Property @{
          PID = $procId
          ProcessName = $procName
          Protocol = $proto
          LocalAddress = $localAddress
          LocalPort = $localPort
          RemoteAddress = $remoteAddress
          RemotePort = $remotePort
          State = $status
        } | Select-Object -Property $properties

        #Increment the progress counter
        $count++
      }
    }
  }
}

function availiablePortInRange {
  param(
    [Parameter(
      Mandatory = $true,
      HelpMessage = "Port range to search for"
    )] [int[]]
    $PortList,
    [Parameter(Mandatory = $true)]
    [ValidateSet('udp','tcp')]
    [System.String]$Protocol
  )
  $Port = 0
  while ((Get-NetworkStatistics -Protocol $Protocol -Port $PortList[$Port]).count -ne 0) {
    Write-Host "Port $($PortList[$Port]) is in use($Protocol)"
    $Port++;
    if ($Port -ge $PortList.Length) {
      Write-Host "No available $($Protocol.ToUpper()) ports in range $PortList"
      -1
    }
  }
  $PortList[$Port]
}

function CommentConfig {
  param(
    [Parameter(
      Mandatory = $true,
      HelpMessage = "Pattern to comment out"
    )] [string]
    $pattern
  )
  $fileName = '.\R2Northstar\mods\Northstar.CustomServers\mod\cfg\autoexec_ns_server.cfg'
  $pattern = "^(?!\/\/.*$).*$pattern"
  $firstOccurrence = $true
  $insert = "//"
  $newContent = switch -Regex -File $fileName {
    $pattern {
      if ($firstOccurrence) {
        "$($insert)$($_)"
        $firstOccurrence = $false
      }
    }
    default { $_ }
  }
  $newContent | Set-Content $fileName -Force
}
function EnsureNorthstarRunning {
  [CmdletBinding(DefaultParameterSetName = 'Range')]
  param(
    [Parameter(
      Mandatory = $false,
      HelpMessage = "Number of Northstar Instances to launch",
      ParameterSetName = "Range"
    )] [int]
    [Parameter(
      Mandatory = $false,
      ParameterSetName = "List"
    )] [int]
    $runningInstances = 1,
    [Parameter(
      Mandatory = $false,
      HelpMessage = "Use software drivers for instead of GPU",
      ParameterSetName = "Range"
    )] [switch]
    [Parameter(
      Mandatory = $false,
      ParameterSetName = "List"
    )] [switch]
    $softwared3d11 = $false,
    [Parameter(
      Mandatory = $false,
      HelpMessage = "Allow Clients that haven't been authorized with northstar to connect",
      ParameterSetName = "Range"
    )] [switch]
    [Parameter(
      Mandatory = $false,
      ParameterSetName = "List"
    )] [switch]
    $ns_auth_allow_insecure = $false,
    [Parameter(
      Mandatory = $false,
      HelpMessage = "Specify this flag if you would like to open the actual game instance",
      ParameterSetName = "Range"
    )] [switch]
    [Parameter(
      Mandatory = $false,
      ParameterSetName = "List"
    )] [switch]
    $open_full_game = $false,
    [Parameter(
      Mandatory = $false,
      HelpMessage = "Tickrate used for the server",
      ParameterSetName = "Range"
    )] [int]
    [Parameter(
      Mandatory = $false,
      ParameterSetName = "List"
    )] [int]
    [ValidateSet(20,60,100)]
    $tickrate = 20,
    [Parameter(
      Mandatory = $false,
      HelpMessage = "Server Prefix",
      ParameterSetName = "Range"
    )] [string]
    [Parameter(
      Mandatory = $false,
      ParameterSetName = "List"
    )] [string]
    $serverPrefix = "Northstar",
    [Parameter(
      Mandatory = $false,
      HelpMessage = "Server Password",
      ParameterSetName = "Range"
    )] [string]
    [Parameter(
      Mandatory = $false,
      ParameterSetName = "List"
    )] [string]
    $ns_server_password = "",
    [Parameter(
      Mandatory = $false,
      HelpMessage = "Process Priority",
      ParameterSetName = "Range"
    )] [string]
    [Parameter(
      Mandatory = $false,
      ParameterSetName = "List"
    )] [string]
    [ValidateSet('High','RealTime','Normal')]
    $processPriority = "High",
    [Parameter(
      Mandatory = $false,
      HelpMessage = "Server Region",
      ParameterSetName = "Range"
    )] [string]
    [Parameter(
      Mandatory = $false,
      ParameterSetName = "List"
    )] [string]
    $serverRegion = "Region",
    [Parameter(
      Mandatory = $false,
      HelpMessage = "Starting address of TCP port range",
      ParameterSetName = "Range"
    )] [int]
    $TCPPortMin = 8081,
    [Parameter(
      Mandatory = $false,
      HelpMessage = "Ending address of TCP port range",
      ParameterSetName = "Range"
    )] [int]
    $TCPPortMax = 8081,
    [Parameter(
      Mandatory = $false,
      HelpMessage = "Starting address of UDP port range",
      ParameterSetName = "Range"
    )] [int]
    $UDPPortMin = 37015,
    [Parameter(
      Mandatory = $false,
      HelpMessage = "Ending address of UDP port range",
      ParameterSetName = "Range"
    )] [int]
    $UDPPortMax = 37015,
    [Parameter(
      Mandatory = $false,
      HelpMessage = "List of availiable UDP ports",
      ParameterSetName = "List"
    )] [int[]]
    $UDPPortList = @(37015),
    [Parameter(
      Mandatory = $false,
      HelpMessage = "List of availiable TCP ports",
      ParameterSetName = "List"
    )] [int[]]
    $TCPPortList = @(8081)
  )
  begin {
    if ($PSCmdlet.ParameterSetName -eq 'Range') {
      if ($UDPPortMin -gt $UDPPortMax) {
        throw "UDPPortMin must be less than UDPPortMax"
      }
      if ($TCPPortMin -gt $TCPPortMax) {
        throw "TCPPortMin must be less than TCPPortMax"
      }
      $UDPPortList = $UDPPortMin..$UDPPortMax
      $TCPPortList = $TCPPortMin..$TCPPortMax
    }
    if ($runningInstances -gt $UDPPortList.Length) {
      throw "Number of requested instances ($runningInstances) exceeds number of available UDP ports ($($UDPPortList.Length))"
    }
    if ($runningInstances -gt $TCPPortList.Length) {
      throw "Number of requested instances ($runningInstances) exceeds number of available TCP ports ($($TCPPortList.Length))"
    }

    if ($open_full_game -and $runningInstances -ne 1) {
      throw "when launching full game, running instances must be 1"
    } elseif (-not $open_full_game) {
      $dedicated = '-dedicated'
    } else {
      $dedicated = '-noborder -window'
    }

    $cl_cmdrate = $tickrate; #client commands, not needed for dedi
    $cl_updaterate_mp = $tickrate; #client commands, not needed for dedi
    $sv_updaterate_mp = $tickrate
    $sv_minupdaterate = $tickrate
    $sv_max_snapshots_multiplayer = $tickrate * 15
    $base_tickinterval_mp = [float](1 / $tickrate)

    CommentConfig -Pattern "ns_server_name"
    CommentConfig -Pattern "ns_player_auth_port"
    CommentConfig -Pattern "ns_auth_allow_insecure"
    CommentConfig -Pattern "ns_server_password"

    CommentConfig -Pattern "sv_updaterate_mp"
    CommentConfig -Pattern "cl_cmdrate"
    CommentConfig -Pattern "cl_updaterate_mp"
    CommentConfig -Pattern "sv_minupdaterate"
    CommentConfig -Pattern "sv_max_snapshots_multiplayer"
    CommentConfig -Pattern "base_tickinterval_mp"
    $password = $(if ($ns_server_password) { "+ns_server_password $ns_server_password" } else { "" })

    $ProcessName = "Titanfall2-unpacked"
    Write-Host "Parameters Validated"
  }

  process {
    try {

      #handles crashes in background, exit when parrent process exits
      $process = Start-Process powershell.exe @"
    `$PPID = $($PID)
    `$PPID
    while (`$true) {
        Get-Process $ProcessName -erroraction 'silentlycontinue' | ForEach-Object {
          if ("`$(`$_.MainWindowTitle)" -like 'Engine error') {
            Write-Host "Server `$(`$_.MainWindowTitle) crashed, restarting"
            Stop-Process -Id `$(`$_.Id) -erroraction 'silentlycontinue'
          }

          

        }
        if ((Get-Process | Where-Object { `$_.Id -eq `$PPID } | Measure-Object).Count -eq 0) {
            exit
        }
        Start-Sleep -Seconds 5
    }
"@ -NoNewWindow

      while ($true) {
        Write-Host "Checking if enough northstar isntances are running running"
        $all_instance_store = @()
        $instances = 0
        {
          Get-Process | Where-Object { $_.ProcessName -eq $ProcessName } | ForEach-Object{
            
            $cmd = $(Get-CimInstance Win32_Process -Filter "ProcessId = '$($_.Id)'").CommandLine
            $cmd_pid = Select-String -InputObject $cmd -Pattern "\+PID (\d+)" | ForEach-Object{$_.Matches[0].Groups[1].Value}
            if ($cmd_pid -eq $PID) {
              $instances++
            }
            $cmd_udp = Select-String -InputObject $cmd -Pattern "-port (\d+)" | ForEach-Object{$_.Matches[0].Groups[1].Value}
            $cmd_tcp = Select-String -InputObject $cmd -Pattern "\+ns_player_auth_port (\d+)" | ForEach-Object{$_.Matches[0].Groups[1].Value}
            $all_instance_store += @($cmd_pid, $cmd_udp, $cmd_tcp)
          
          }
          $all_instance_store | ForEach-Object {
            $i = $_
            $all_instance_store | ForEach-Object {
              $j = $_
              if ($i[0] -ne $j[0] -and ($i[1] -eq $j[1] -or $i[2] -eq $j[2])) {
                Write-Host "Duplicate instance found, killing the one with lower PID"
                if ($i[0] -lt $j[0]) {
                  Stop-Process -Id $i[0] -erroraction 'silentlycontinue'
                } else {
                  Stop-Process -Id $j[0] -erroraction 'silentlycontinue'
                }
              }
            }
          }
        }
         

        if ($runningInstances -gt $instances) {
          Write-Host "Not enough instances running, starting new instance"
          $random_postfix = ([guid]::NewGuid()).ToString().Substring(0,8)
          $server_name = "[$serverRegion][$tickrate-tick]$serverPrefix-$random_postfix".Replace(" ","-") #since spaces do not show properly when passed via command line
          Write-Host "Searching for open TCP port in range $($TCPPortList[0]) - $($TCPPortList[$TCPPortList.Length-1])"
          $portTCP = $(availiablePortInRange -Protocol tcp -PortList $TCPPortList)
          if ($portTCP -eq -1) {
            Write-Warning "No available TCP ports in range $TCPPortList"
            Start-Sleep -Seconds 10
            continue
          }
          Write-Host "Searching for open UDP port in range $($UDPPortList[0]) - $($UDPPortList[$UDPPortList.Length-1])"
          $portUDP = $(availiablePortInRange -Protocol udp -PortList $UDPPortList)
          if ($portUDP -eq -1) {
            Write-Warning "No available UDP ports in range $UDPPortList"
            Start-Sleep -Seconds 10
            continue
          }
          Write-Host "Running Following Command:"
          $cpuMode = if ($softwared3d11) { "-softwared3d11" } else { "" }


          Write-Host "./NorthstarLauncher.exe $dedicated $cpuMode -multiple -port $portUDP +setplaylist private_match +ns_player_auth_port $portTCP +ns_server_name $server_name +sv_updaterate_mp $sv_updaterate_mp +cl_updaterate_mp $cl_updaterate_mp +cl_cmdrate $cl_cmdrate +sv_minupdaterate $sv_minupdaterate +base_tickinterval_mp $base_tickinterval_mp +sv_max_snapshots_multiplayer $sv_max_snapshots_multiplayer +ns_auth_allow_insecure $([int]$ns_auth_allow_insecure.ToBool()) $password"
          ./NorthstarLauncher.exe $dedicated $cpuMode -multiple -Port $portUDP +setplaylist private_match +ns_player_auth_port $portTCP +ns_server_name $server_name +sv_updaterate_mp $sv_updaterate_mp +cl_updaterate_mp $cl_updaterate_mp +cl_cmdrate $cl_cmdrate +sv_minupdaterate $sv_minupdaterate +base_tickinterval_mp $base_tickinterval_mp +sv_max_snapshots_multiplayer $sv_max_snapshots_multiplayer +ns_auth_allow_insecure $([int]$ns_auth_allow_insecure.ToBool()) $password +PID $PID
          Start-Sleep -Seconds 5 #wait for child process to start
          Get-Process | Where-Object { $_.ProcessName -eq $ProcessName -and $_.PriorityClass -notlike $processPriority } | ForEach-Object {
            $PriorityClass = 128
            if ($processPriority -eq 'Normal') {
              $PriorityClass = 32
            } elseif ($processPriority -eq 'RealTime') {
              $PriorityClass = 256
            }
            Get-CimInstance Win32_Process -Filter "ProcessId = '$($_.Id)'" | Invoke-CimMethod -Name SetPriority -Arguments @{ Priority = $PriorityClass }
            Write-Host "Priority of $($_.Id) set to $processPriority"
          }

          while ($true) {
            Start-Sleep -Seconds 5
            if ($(Get-NetworkStatistics -Port $portUDP -Protocol udp).count -ne 0 -and $(Get-NetworkStatistics -Port $portTCP -Protocol tcp).count -ne 0) {
              Write-Host "Server $server_name is running"
              break
            } else {
              Write-Host "Waiting for port to become availiable"
            }
          }

          continue
        }
        Write-Host "Enough instances running, waiting for next check"
        Start-Sleep -Seconds 10
      }
    }
    finally {
      Stop-Process -Id $process.id
    }

  }


}



# function LaunchSingleNorthstar {
#     param(
#         [Parameter(
#             Mandatory=$false,
#             ValueFromRemainingArguments=$true,
#             Position = 0
#         )][string[]]
#         $listArgs
#     )
#     $line = 0
#     #check if northstar is already running
#     if (Get-TitanfallProcessCount){
#          "Northstar is already running, watching for latest log file"
#     } else {
#         #start northstar
#         Start-Process -FilePath "NorthstarLauncher.exe" -ArgumentList $listArgs -Wait
#          "Northstar started"
#     }   
#     Start-Sleep -Seconds 5 
#     do {
#         $output = [Linq.Enumerable]::Skip([System.IO.File]::ReadLines((Get-ChildItem .\R2Northstar\logs\ | sort -Property LastWriteTime -Descending -Top 1).FullName), $line)
#         $line += $output.GetCount($null)
#          -NoNewline $output
#     } while (Get-TitanfallProcessCount)
# }
