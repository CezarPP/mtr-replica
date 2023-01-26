# mtr-replica

UNI Networks project - a program similar to mtr/traceroute using the C Sockets API

The program consists of a concurrent server and a client.

The client uses the `curses` library to display text similar to the `mtr` command and to accept user keystrokes.

The server accepts connections from clients via TCP and sends them the data to print.

The client gives an IP to the server, which, in turn, provides the client with a traceroute that is constantly updated.