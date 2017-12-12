# IPssrr
An application that uses raw sockets to 'walk' an ordered list of nodes in a similar fashion to SSRR

The application needs both the modules running on the vm6
The modules are: arp.c and icmp.c
to compile both the modules:

$> make arp
$> make icmp

And copy both the binaries to the vms.
After that first run the arp module in all the vms to be tested, 
then the non source nodes and finally the source nodes
