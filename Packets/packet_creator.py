# from scapy.all import *
from scapy.layers.inet import *
import json

# # print(json.dumps(dir(scapy.packet), indent=4))
# a = PacketListField
# print(a)
# a = IP()/UDP()
# print(a)

class construct_packet:

	def __init__(self, **kwargs):
		"""
		eg a = construct_class(layers = [ ( "IP",  ) ])


		:param kwargs:
		"""
		print("Set Ether layer using fields derived from self.selected interface")
		p = Ether()
		p[Ether].src = "00:00:00:00:00:00"
		p[Ether].dst = "00:00:00:00:00:00"

		# Add layers to packet as specified in call
		if kwargs.get("layers") == "Ether":
			print("Adding Ethernet layer to packet")

		for layer in kwargs.get("layers"):

			if layer == "IP":
				p = p / IP()
				print("Adding IP layer to packet")

			if layer == "UDP":
				p = p / UDP()
				print("Adding UDP layer to packet")

			if layer == "RTP":
				print("Adding RTP layer to packet")

			if layer == "PTPv2":
				print("Adding PTPv2 layer to packet")

		print(" ")
		print(p.show())
		print(type(p))


def build(pkt):

	try:
		return pkt.raw()
	except:
		print("Failed to build packet")


if __name__ == "__main__":

	test = construct_packet(layers=["IP", "UDP"])