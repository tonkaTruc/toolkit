import socket
import sys
import time
import numpy as np

HOST = sys.argv[1]
PORT = sys.argv[2]

class SimpleSocket:
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

	def listener(self, toggle=False, number_of_connections=1):
		self.s.listen(number_of_connections)
		print("Socket is listening on %s:%s" % (self.HOST, self.PORT))

		if toggle is not False:
			conn, addr = self.s.accept()
			print("[!!!] Connection from {}:{}".format(addr[0], addr[1]))

			while True:
				data = conn.recv(1024)
				reply = b". " + data
				if not data:
					break
				conn.sendall(reply)

			conn.close()

		elif toggle is not True:
			self.s.close()
			print("Socket has been closed")
		else:
			print("Some shit!")

	def send(self, payload):
		print("HEY")

if __name__ == "__main__":

	host = sys.argv[1]
	port = int(sys.argv[2])

	print("Attempting to create socket with: %s : %s" % (host, port))
	user_socket = SimpleSocket(host, port)

	user_socket.listener(True)

	user_socket.listener(False)
