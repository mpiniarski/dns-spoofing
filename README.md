# Building and running
### Compiling program
Go to `src` directory and run:
```commandLine
gcc -Wall ./dnspoof.c -o dnspoof -lnet -pthread -lpcap
```
or use using `CMakeLists.txt` (under main project path):
```commandLine
cmake .
make
```

### Running program
```commandLine
sudo ./bin/dns_spoofing
```

### Configuration file usage
Configuration file should appear in main project directory (next to executable file or one level higher than `dnspoof.cpp` file) 
under `config.cfg` name.

Every line that starts with `#` is considered as comment.
Don't use spaces in no comment lines.

On the left side of `=`: questioned (original) site.

On the right side of `=`: spoof site.

Example:
```
# this is a comment
www.want-to-go-to-this-site.com=www.but-going-here.com
www.other-attacked-site.com=www.spoof-site.pl
```

# Files descriptions
### Main

* `src/dnspoof.cpp`

Main file (with `main()` function) where two threads are called: first responsible for arp spoofing and second for dns spoofing.

* `src/helper.cpp`

File with functions needed to properly read configuration file.


### ARP spoofing
* `src/arp_spoofer/arp_spoofer.cpp`

Function `arp_spoof()` is responsible for sending arp messages (continuously) with information about fake gateway's ip. This is the function that runs in the first thread (in `main()` function).
Funtion `libnet_build_arp_spoof()` is used for building proper arp message. 

### DNS spoofing
* `src/forwarder_and_dns_spoofer/forwarder_and_dns_spoofer.cpp`

`forward_and_dns_spoof()` is the function that is called in the second thread. It initiates *pcap* library and filters received messages. At the end of function it calles `pcap_loop()` function.

Function `trap` is the one which is called every time filtered packet arrives. It decides whether packet should be send forward to real gateway or swapped with spoof message.

* `src/forwarder_and_dns_spoofer/filter.cpp`

It constains all functions responsible for packet filtering used in pcap initialization.

* `src/forwarder_and_dns_spoofer/dns_spoofer.cpp`

`getSpoofedAddressForThisSite()` is a function responsible for getting ip of spoof address (corresponding to originally questioned site, based on configuration file).

`handle_dns_spoofing()` is a function called in `trap()`. It is responsible for sending dns response with fake address.

`libnet_build_dns_spoof()` is used to create dns response.

* `src/forwarder_and_dns_spoofer/forwarder.cpp`
