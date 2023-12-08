# libmyradclient: a simple client library for radius protocol

@author: qudreams

# Note:

The library is from [www.freeradius.org](http://www.freeradius.org).<br>
The library supports the following authentication methods: PAP,CHAP,MSCHAP,MSCHAPV2,EAPMD5

# Usage:

## Build

### Clone

```
$ git clone https://github.com/ten0s/libmyradclient.git
```

### Compile library:

```

$ cd libmyradclient
$ make
```

You can find a file that named `libmyradclient.a`;
this is a static library of radius client library,
you can link it into your radius program.

### Compile example:

There is a example in the source file `example.c`, to build it run:

```
$ make example
```

### Run example:

```
$ ./example
Usage: ./example [options...]
    [-H <host>]    radius server host, default: 127.0.0.1
    [-P <port>]    radius server port, default: 1812
    [-S <secret>]  radius client shared secret, default: testing123
     -u <username> username
     -p <password> password
    [-a <auth>]    auth type (PAP|CHAP|MSCHAP|MSCHAPV2|EAPMD5), default: PAP
    [-d <path>]    dictionary path (for human-readable output)
    [-h]           help
```

Run without dictionary:

```
$ ./example -H 172.10.0.10 -S SECRET -u bob -p hello
Sending Access-Request packet to host 172.10.0.10 port 1812, id=122, length=67
	Attr-1 = "bob"
	Attr-2 = "hello"
	Attr-6 = 8
	Attr-80 = 0x00000000000000000000000000000000
Received Access-Accept packet from host 172.10.0.10 port 1812, id=122, length=32
	Attr-18 = 0x48656c6c6f2c20626f62
```

Run with dictionary:

```
$ ./example -H 172.10.0.10 -S SECRET -u bob -p hello -d ./raddb/
Sending Access-Request packet to host 172.10.0.10 port 1812, id=233, length=67
	User-Name = "bob"
	User-Password = "hello"
	Service-Type = Authenticate-Only
	Message-Authenticator = 0x00000000000000000000000000000000
Received Access-Accept packet from host 172.10.0.10 port 1812, id=233, length=32
	Reply-Message = "Hello, bob"
```
