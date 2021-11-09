import socket

def get_best_interface_for(addr):
	"""Create a temp socket and use that to connect to an endpoint. Return the local nic IP address that made the connection"""
	
	tmp_s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

	try:
		tmp_s.connect((addr, 9))
		# Get the interface used by the socket.
		local_ip = tmp_s.getsockname()[0]
	except socket.error:
		# Only return 127.0.0.1 if nothing else has been found.
		local_ip = "127.0.0.1"
	finally:
		tmp_s.close()
	
	return local_ip