# IPssrr
An application that uses raw sockets to 'walk' an ordered list of nodes in a similar fashion to SSRR. The application also incorporates an implementation of ARP protocol(without cache timeout mechanisms) for discovering physical address of Next Hop in the route. The modules make use of IP_HDRINCL ip options to craft raw ethernet and ip frame headers along with custom Protocol IDs to prevent the Virtual SSRR network to interfere with rest of network traffic.

The application needs both the modules running on the virtual machines. The modules are: arp.c and icmp.c
```
To compile the modules:

$> make arp
$> make icmp
```

Copy the binaries to the vms and run the icmp module preceded by the arp on every node. After the end of tour, the source node sends a UDP broadcast message to every node to stop pinging the preceding node in the tour. (A periodic ICMP ping request is triggered to start sending Ping requests to the preceding node everytime the tour visits the node for the first time.)
