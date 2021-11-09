#!/bin/python3

import socket
import re
import sys
from struct import *

class MulticastMgr:

	def __init__(self, switch_ip=None):

		if not switch_ip: print("Switch IP address is missing... initialise using \"switch_ip=0.0.0.0\"")
		
		# Create a temp socket and use that to connect to the switch. This will identify to correct NIC to use for comms
		# to the switch and get the address information needed
		temp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

		try:
			temp_socket.connect((switch_ip, 9))
			# Get the interface used by the socket.
			self.local_ip = temp_socket.getsockname()[0]
		except socket.error:
			# Only return 127.0.0.1 if nothing else has been found.
			self.local_ip = "127.0.0.1"
		finally:
			temp_socket.close()

		self.sock = create_socket(self.local_ip, 9989)
		print(f'Using interface: {self.local_ip}')
		print(f'Created UDP socket: {self.sock}')

		# set multicast interface to local_ip
		self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(self.local_ip))

		# Set multicast time-to-live to 2...should keep our multicast packets from escaping the local network
		self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)

	def join(self, multicast_ip):

		# Construct a membership request...
		membership_request = socket.inet_aton(multicast_ip) + socket.inet_aton(self.local_ip)

		# Send add membership request to socket
		# See http://www.tldp.org/HOWTO/Multicast-HOWTO-6.html for explanation of sockopts
		self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, membership_request)

		try:
			print(f'Multicast JOIN has been sent {multicast_ip}. Entering while loop... Ctrl+C to exit and close socket.')
			while True:
				pass
		except KeyboardInterrupt:
			self.leave(multicast_ip)

	def leave(self, multicast_ip):

		# Construct a membership request...
		membership_request = socket.inet_aton(multicast_ip) + socket.inet_aton(self.local_ip)
		self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_DROP_MEMBERSHIP, membership_request)


def create_socket(ip, port):
	"""
	Returns an open socket, bound to the switch facing network port returned from :func:`get_local_ip()`
	@port is the port that is bound with the local ip address to create the socket
	"""

	# create UDP socket
	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

	# allow reuse of addresses
	sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

	# If you bind to a specific interface on the Mac, no multicast data will arrive.
	# If you try to bind to all interfaces on Windows, no multicast data will arrive.
	# Hence the following.
	if sys.platform.startswith("darwin"):
		sock.bind(('0.0.0.0', port))
	else:
		sock.bind((ip, port))

	return sock


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

	test = MulticastMgr(switch_ip='192.168.10.1')
	test.join('239.4.20.1')

	# switch_ip = input('Enter the address of the network switch being used: ')

	# multicast_ip = str(input('Enter the multicast stream you wish to send the IGMP join to: '))
	# port = int(input('Enter the port: '))
	#
	# # Get the address data for port connected to switch
	# local_ip = get_local_ip(switch_ip)
	#
	# # Create a RAW UDP socket which is bound to interface + port
	# sock = create_socket(local_ip, port)
	#
	# # Build the IGMP join request based on information provided
	# reg_multicast(local_ip, sock, multicast_ip)
	#
	# try:
	# 	print('Multicast JOIN has been sent. Entering while loop... Ctrl+C to exit and close socket.')
	# 	while True:
	# 		pass
	# except KeyboardInterrupt:
	# 	sock.close()

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
