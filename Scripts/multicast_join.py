#!/bin/python3

from struct import *
import socket
import re

test = MulticastMgr(switch_ip='192.168.10.1')
test.join('239.4.20.1')

def ip_is_local(ip_string):
	"""
	Uses a regex to determine if the input ip is on a local network. Returns a boolean.
	It's safe here, but never use a regex for IP verification if from a potentially dangerous source.
	"""
	combined_regex = "(^10\.)|(^172\.1[6-9]\.)|(^172\.2[0-9]\.)|(^172\.3[0-1]\.)|(^192\.168\.)"
	
	return re.match(combined_regex, ip_string) is not None # convert to a boolean

def print_stream_info(my_socket):

	# Data waits on socket buffer until we retrieve it.
	# NOTE: Normally, you would want to compare the incoming data's source address to your own, and filter it out
	#       if it came from the current machine. Everything you send gets echoed back at you if your socket is
	#       subscribed to the multicast group.

	packet = my_socket.recvfrom(2624)

	# packet tuple to string
	packet = packet[0]

	#Take first 20 characters as IP header
	ip_header = packet[0:20]
 
	iph = unpack('!BBHHHBBH4s4s' , ip_header)

	version_ihl = iph[0]
	version = version_ihl >> 4
	ihl = version_ihl & 0xF
	iph_length = ihl * 4
	protocol = iph[6]

	u = iph_length
	udph_length = 8
	udp_header = packet[u:u+8]
 
	#now unpack them :)
	udph = unpack('!HHHH' , udp_header)

	source_port = udph[0]
	dest_port = udph[1]

	if protocol == 17:
		protocol = 'UDP'

	src_addr = socket.inet_ntoa(iph[8]);
	dst_addr = socket.inet_ntoa(iph[9]);

	if dst_addr == multicast_ip:
		print('\nMulticast stream detected!')
		print('\nProtocol: \t\t', protocol)
		print('Source Port: \t\t', source_port, '\nDestination Port: \t', dest_port)
		print('Source Address: \t', src_addr, '\nDestination Address: \t', dst_addr)
		print('\nCheck wireshark to ensure the correct packets are reaching your NIC\n')
		return True

	else:
		print('No Multicast stream present at: ', multicast_ip)
		return False

if __name__ == '__main__':

	# if print_stream_info(sock):
	#     input('Press Enter to deregister interest and close socket: ')
	#     sock.close()
	#     print('\nSocket closed, \nMulticast packets will stop when your machine recieves the next IGMP Membership Query\n')
	#     input('Press Enter to Exit')
	#
	# else:
	#     sock.close()
	#     print('\nSocket closed')
	#     input('Press Enter to Exit')
