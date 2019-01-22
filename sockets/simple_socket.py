import socket
import sys
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
			print("Could not bind %s:%s" % (self.HOST, self.PORT))
			print(err)

			sys.exit()

		print("Successfully bound %s:%s" % (self.HOST, self.PORT))

	def server(self, number_of_connections=1, timeout=5):
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
			
			
if __name__ == "__main__":

	host = sys.argv[1]
	port = int(sys.argv[2])

	print("Attempting to create server on: %s : %s" % (host, port))
	user_socket = SimpleServer(host, port)

	user_socket.server()
