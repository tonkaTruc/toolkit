import socket
import sys

class SimpleServer:
	
	def __init__(self, host, port):
		self.host = host
		self.port = int(port)

		self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

		try:
			self.s.bind((self.host, self.port))
		except socket.error as err:
			print(f"Could not bind {self.host}:{self.port}")
			sys.exit()

		print(f"Successfully bound {self.host}:{self.port}")

	def	serve(self, number_of_connections=1, timeout=60):
		self.s.listen(number_of_connections)
		self.s.settimeout(timeout)
		print(f"Socket is listening on {self.host}:{self.port}")

		conn, addr = self.s.accept()
		print(f"[!!!] Connection from {addr[0]}:{addr[1]}")

		try:
			while True:
				data = conn.recv(1024)
				reply = b". " + data
				if not data:
					break
				conn.sendall(reply)
				conn.close()
		except socket.timeout:
			print("Nothing received within timeout")

