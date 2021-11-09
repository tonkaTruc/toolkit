import socket
import sys
import struct
# import time
# import numpy as np

class SimpleServer:
	
	def __init__(self, HOST, PORT):
		self.HOST = HOST
		self.PORT = PORT

		self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

		try:
			self.s.bind((self.HOST, self.PORT))
		except socket.error as err:
			print(f"Could not bind {self.HOST}:{self.PORT}")
			print(err)

			print("USAGE:\n\t- python3 simple_socket.py <host> <port>")
			print("\t- python3 simple_socket.py \"127.0.0.1\" 20200 ")

			sys.exit()

		print(f"Successfully bound {self.HOST}:{self.PORT}")

	def server(self, number_of_connections=1, timeout=60):
		self.s.listen(number_of_connections)
		self.s.settimeout(timeout)
		print("Socket is listening on %s:%s" % (self.HOST, self.PORT))

		conn, addr = self.s.accept()
		print("[!!!] Connection from {}:{}".format(addr[0], addr[1]))

		try:
			while True:
				data = conn.recv(1024)
				reply = b". " + data
				if not data:
					break
				conn.sendall(reply)
				conn.close()
		except OSError.Exception.socket.timeout:
			print("Nothing received within timeout")


class MulticastMgr:
	
	def __init__(self, MCAST_GRP, MCAST_PORT):
		self.MCAST_GRP = MCAST_GRP
		self.MCAST_PORT = int(MCAST_PORT)
		self.ALL_GROUPS = False

		self.INTERFACE_IP = get_interface_ip(("10.0.0.254", 23))

		self.s = self.create_socket(10000)
		print(self.INTERFACE_IP)
		if self.ALL_GROUPS:
			# on this port, receive ALL multicast groups
			self.s.bind(("", self.MCAST_PORT))
		else:
			# on this port, listen to only the specified port
			self.s.bind((self.MCAST_GRP, self.MCAST_PORT))

		request = struct.pack("4sl", socket.inet_aton(self.MCAST_GRP), socket.INADDR_ANY)

		self.s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, request)
		self.s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, request)
		print(f"Successfully join multicast group {self.MCAST_GRP}")

	def create_socket(self, port):

		# Create raw socket and allow resuse of the address
		s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
		s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

		# Bind socket to an interface
		# 	Apple OS cannot receive multicast when socket is bound to a SPECIFIC interface
		# 	Windows cannot receive multicast when bound to ALL ports
		s.bind(('0.0.0.0', port)) if sys.platform.startswith("darwin") else s.bind((self.INTERFACE_IP, port))
		
	
	def display_grp_traffic(self):
		while True:
			print(self.s.recv(1024))


def get_interface_ip(gateway_info=None):
	"""Will return the IP address of NIC used to connect to a specified gateway.

		:args gateway_info
		:value tuple (<gateway_ip>, (known_open_port_on_gateway))

	"""

	if gateway_info:
		print("Gateway info supplied: %s:%s" % gateway_info)

		if len(gateway_info) != 2:
			print("Incorrect gateway info when getting interface ip\n (<gateway_ip>, <open_port_on_gatway>)")
			quit()

		s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

		try:
			s.connect((gateway_info[0], gateway_info[1]))
			interface_ip = s.getsockname()[0]
		except socket.error.Exception as err:
			print(err)
		finally:
			s.close()
			return interface_ip
	else:
		print("You still need to implement get ip address from NIC name!")


# def join_multicast(s, multicast_addr):


if __name__ == "__main__":

	# gw_ip = input("Eneter your gatway's ip address: ")
	gw_ip = "10.0.0.254"
	gw_port = 23
	

#	host = sys.argv[1]
#	port = int(sys.argv[2])
#
#	print("Attempting to create server on: %s : %s" % (host, port))
#	user_socket = SimpleServer(host, port)
#
#	user_socket.server()

	multicast_addr = sys.argv[1]
	port = sys.argv[2]

	print("Joining multicast group %s" % multicast_addr)

	try:
		mcast_grp_1 = MulticastMgr(multicast_addr, port)
		mcast_grp_1.display_grp_traffic()
	except KeyboardInterrupt:
		quit()
