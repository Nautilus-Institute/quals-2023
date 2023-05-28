### Challenge Description:

Hello Special Agent. We've gained access to a network, the password is
defcon2023. We set up a proxy for you on a.b.c.d port yyyy

####
Possible Hint: You might want to bridge in the connection to some kind of network simulator.

### Task Details:

ap.py is running a scapy wifi network with a fake IP stack. Users have to connect.
They can bridge macsim and scapy with the tcp port, to solve more easily. Or they
will go and fix the wpa2 protocol

1.  The very first network has the ssid/password of defcon2023.

2. Once they connect, they can DHCP to get an IP address. From there,
they will need to scan the network for a host. The 10.10.x.y machines (where y is the boat ip),
10.10.x.1 will respond to ping.

When a TCP packet is sent, the network responds with an ICMP protocol not found.
When a UDP packet is sent, the network ensures the boat IP is chosen, or responds that the
host is not found or the port is not found.

The BSSs will also query connected stations on port 2422, as a further hint,
or they can do a udp port scan to try to find it.

3. There's several commands
```
BOATHELP = """BLYAT!
    HELP - This help file
    INFO - Info about the Yacht
    ANTENNA - Activate antenna
    POSITION - Show current Position
    DETONATE -
    CODE - Show code
```

4. Users should run CODE which shows them the GOST function for calculating hashes.
This code is used to calculate a PSK from an SSID name.

When 'ANTENNA' is run, a new BSSID is activated.

When "DETONATE" is run -- the BSSID is destroyed. When the last boat is destroyed,
the flag is printed.


#### Testing:

running ap:
```bash
socat exec:./ap.py tcp-listen:4444
```
running solve:
```bash
socat exec:./solve.py tcp-connect:localhost:4444
```
