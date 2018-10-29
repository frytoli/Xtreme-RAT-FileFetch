# Xtreme RAT File Fetch

Mimics an infected host phoning home to an Xtreme RAT C2 Server and attempts to authenticate itself and download specified files.
This is currently written in Python 2.7 and will be updated to 3.0 soon.

Olivia Fryt - olivia@secchur.ro

### Requires

```
StringIO
string
struct
socket
time
zlib
sys
os
```

### File Downloads

Only successfully downloads files with an absolute path. By default, this code attempts to download three files that are common among Xtreme RAT instances: "user.info", "senha.txt", and "Settings.ini". Additional files can be added manually within the code. Note that Xtreme RAT C2 Software runs on Windows OS.

### To Run

Run As:
```
python Xtreme_FF.py 127.0.0.1
```

Where 127.0.0.1 is the IP address of the Xtreme RAT C2


### Server-Client Communication

Xtreme RAT uses a reverse-connecting architecture: the C2 acts as the client while the infected hosts act as servers. Communication between the C2 and hosts are encoded and sometimes compressed.

To begin communication, the infected host initiates a connection with the C2 by sending the string "myverion" + pipe + the version number to the C2. Testing showed that the Xtreme RAT C2 does not confirm or check the version number. The code uses version 3.6 for every connection. IE:
```
myversion|3.6
```

If the C2 in question is indeed running Xtreme RAT and the communication is successful, the C2 then responds to the infected host. The C2 begins every message it sends to the infected host with the string:
```
X\r\n
```
This message (or acknowledgement) is sent in unicode. Sometime this message is received as an individual response or appended to the next message (a connection header). The code accounts for this.


The connection header includes a communication password + null byte + the size of the following message + null byte. IE:
```
0123456789NUL130NUL
```
This header is little endian encoded.


The C2 then sends the infected host the "maininfo" message. This message is made up of the string "maininfo" + Xtreme RAT's universal delimiter + a connection ID. This Connection ID is necessary for further successful communication. The  IE:
```
maininfo??????###?" a?" a?"aR539sw21zjXF4Cqotm7EUNMYPhGAHfcDlBLZxQiSadrTVbu8n0pgykJ6WeK
```
This message is zlib compressed and little endian encoded.


After this communication, the infected host then can send a command to the C2. At this time the infected host (us) will put together the following message: "newconnection" command followed by a pipe character, the previously transmitted Connection ID, the previously transmitted Xtreme RAT delimiter, and any additional commands necessary. In this case, we will be telling the C2 to update our local server with the command "updateserverlocal" followed by the previously transmitted Xtreme RAT delimiter followed by an absolute path to a file we would like the C2 to send to us. This message will look like this:
```
newconnection|LoWr63EgauwjTyl40NPxmbX7U15si2BKFkRH9SdphJnGQVDzCMqfA8cZeYt###"a"a"aupdateserverlocal###"a"a"afile.txt
```
This message needs to be zlib compressed and little endian encoded before being sent.


Like the C2, the infected host (us) preceeds the "updateserverlocal" command with a connection header in the same style as described above. IE:
```
0123456789NUL256NUL
```
The code sends this connection header to the C2 followed by the actual compressed and encoded message.


If this transmission is successful, the C2 responds with the "X" string followed by a connection header. Sometimes the "X" string and connection header come together as one message and sometimes they don't - the code accounts for this. The C2 then sends a separate message made up of the string "updateserverlocal" + the Xtreme RAT delimiter + the size of the file to be downloaded. IE:
```
updateserverlocal###"a"a"a10984
```
This message is little endian enocded and zlib compressed.


The C2 then transmits the file.

The Code automates all communication and file transmission.
