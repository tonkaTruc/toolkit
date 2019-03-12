from scapy.all import *
import socket
import psutil
import json
import os
import netifaces

import subprocess
import time

packet_counter = 0
current_rtp_time = 0
rtp_stamps = []

class pkt_craft:

	def __init__(self, interface=None):

		# Configure the host network adapter to use
		self.selected_interface = configure_interface(interface)
		# logging.debug(self.selected_interface)
		# DEBUG print("Selected interface = %s" % self.selected_interface)

		# Obtain IP address of host network adapter.
		# (try except for formatting of win / unix nic data structure))
		try:
			self.ip = netifaces.ifaddresses(self.selected_interface["guid"])
		except KeyError:
			self.ip = netifaces.ifaddresses(self.selected_interface)

		# Get hostname
		self.hostname = socket.gethostname()

		self.current_pcap = None

		print("\nHost info:")
		print("Hostname: \t\t\t\t\t{}".format(self.hostname))
		print("Currently assigned NIC: \t{}".format(self.selected_interface))
		print("Ip address: {}".format(json.dumps(self.ip, indent=4)))
		print(130*"-")

	def capture(self, interface, pkt_count=None):

		global packet_counter
		packet_counter = 0

		def count_capture(pkt):
			global packet_counter
			packet_counter += 1

			return "%s %s" % (packet_counter, pkt.summary())

		# cap = sniff(iface=interface, count=int(pkt_count), prn= lambda x: x.nsummary())
		# cap = sniff(iface=interface, count=int(pkt_count), prn=count_capture)
		# cap = sniff(iface=interface, count=int(pkt_count), prn=self.on_rx)
		try:
			cap = sniff(iface=interface, count=int(pkt_count), prn=count_capture)
		except KeyboardInterrupt:
			return False

		self.current_pcap = cap

		return cap

	def decode_as_rtp(self, pkt):
		print("Some good stuff in here!")
		"""
		previous = 0
		total_stamp = 0
		delta = 0
		for stamp in rtp_stamps:
			total_stamp = total_stamp + stamp
			delta = stamp
			delta = delta - previous
			previous = stamp

		print("Delta (average) = %s" % delta)
		print("Total RTP time stamps = %s" % total_stamp)
		print("Mean = %s" % (total_stamp / len(rtp_stamps)))

		----------------------

		if pkt.haslayer(UDP):
			udp = pkt[UDP]

		if pkt.haslayer(TCP):
			tcp = pkt[TCP]

		"""

	def on_rx(self, pkt):
		global packet_counter
		packet_counter += 1
		
		global current_rtp_time
		global rtp_stamps

		
		# print(pkt.show())
		# print("\n" + str(pkt[Raw]))
		if IP in pkt:
			pkt[IP].src = "0.0.0.0"
			pkt[IP].dst = "0.0.0.0"
		
		# Force UDP payload to be interpreted as RTP
		if UDP in pkt:
			pkt[UDP].payload = RTP(pkt[Raw].load)
				
		if RTP in pkt:
			pkt[RTP].payload_type = 97
			# print(pkt[RTP].timestamp)
			
			if pkt[RTP].timestamp != current_rtp_time:
				print(pkt[RTP].timestamp)
				current_rtp_time = pkt[RTP].timestamp
				rtp_stamps.append(pkt[RTP].timestamp)
			else:
				print(".")
				
		return pkt.summary()

	def inspect(self, **kwargs):
		i = None

		if kwargs.get("mode") == "iterate":
			pkt_start_num = input("Enter packet number to start inspection: ")
			for p in self.current_pcap[int(pkt_start_num):]:
				print(90*"-")
				p.show()
				hexdump(p)
				print(90*"-")
				i = input("... ")

				# Escape the loop back to menu
				if i == "exit":
					self.menu()
				elif i == "change":
					self.manipulate(p)
				else:
					continue

	def manipulate(self, pkt):
		print(pkt.summary())
		packet_info = ls(pkt)
		print(type(packet_info))
		print("\n\n")

		print(pkt[Ether])
		print(pkt[IP])

		print(pkt[Ether].hide_defaults())
		print(pkt[IP].hide_defaults())

		manipulation_opt = {
			"1": "Zero all source values"
		}
		for k, v in manipulation_opt.items():
			print(k, v)
		usr_opt = input("Enter manipulation preset: ")

		if usr_opt == "1":

			# Attempt to reset IP and MAC source addresses
			try:
				print("IP src was: {}".format(pkt[IP].src))
				pkt[IP].src = "0.0.0.0"
				print("IP src now: {}".format(pkt[IP].src))
			except IndexError as err:
				logging.warning(err)

			try:
				print("\nMAC src was: {}".format(pkt[Ether].src))
				pkt[Ether].src = "00:00:00:00:00:00"
				print("MAC src now: {}".format(pkt[Ether].src))
			except IndexError as err:
				logging.warning(err)

		print("Layer 2: src {}\t dst {}".format(pkt[Ether].src, pkt[Ether].dst))
		print("Layer 3: src {}\t\t dst {}".format(pkt[IP].src, pkt[IP].dst))
		print(pkt.command())

		print(pkt.summary())

	def export_capture(self, file):

		# Exit to menu if active cap file is empty
		if not self.current_pcap:
			logging.error("Active cap file is empty... nothing to export")
			raise TypeError("Cannot save empty capture variable!")

		print("Exporting current .pcap var: {}".format(self.current_pcap))
		wrpcap(file, self.current_pcap)
		print("File saved as: {}".format(os.path.abspath(file)))

		return file

	def import_capture(self, file=None):
		cap_store_path = os.path.abspath(os.curdir) + "/cap_store/"

		if not file:
			while True:
				print("Listing directory:\t%s\n" % cap_store_path)

				for item in os.listdir(cap_store_path):
					print("\t- %s" % item)

				target_filename = input("\nEnter filename of target capture: ")
				file = os.path.abspath(cap_store_path + target_filename)

				if os.path.exists(file):
					break
				else:
					logging.error("File does not exist: %s " % file)
					pass

		try:
			cap = sniff(offline=file)
		except FileNotFoundError as err:
			print("File supplied for input does not exist: %s" % file)
			return False

		cap.nsummary()

		self.current_pcap = cap

	def menu(self):
		while True:
			print("\nCurrent capture file stats:\t{} ({})".format(self.current_pcap, type(self.current_pcap)))
			print("Selected interface:\t\t\t{} ({})\n".format(self.selected_interface["name"], type(self.selected_interface)))

			"""
			Adding new options to menu: 
				Additional menu options can be added by adding them to <menu_options> list.
				The position in the list is reflected in its corresponding option number for user entry
			"""

			menu_options = [
				"Export current .pcap",
				"Produce new .pcap",
				"Import .pcap from drive",
				"Apply global changes to current capture",
				"Inspect cap file",
				"Filter current .pcap",
				"Replay current .pcap"
			]

			for item, num in zip(menu_options, [x for x in range(0, len(menu_options))]):
				print("\t%s: %s" % (num, item))
			usr_opt = input("\nEnter option number: ")

			# Export current .pcap file
			if usr_opt == "0":
				try:
					self.export_capture(input("Enter filname: "))
				except TypeError as err:
					print("You must import or generate a capture in order to save a capture!")
				continue

			if usr_opt == "1":
				print("Capturing from currently selected interface...")
				count = input("Enter number of packets to capture: ")
				self.capture(self.selected_interface["name"], count)
				continue

			elif usr_opt == "2":
				self.import_capture(input("Enter path or press enter to list default directory: "))
				continue

			elif usr_opt == "3":
				self.inspect(mode="iterate")
				self.menu()

			elif usr_opt == "4":
				print("FILTER")
			elif usr_opt == "5":

				def zero_dst(pkt):
					pkt[Ether].dst = "00:00:00:00:00:00"
					pkt[Ether].src = "00:00:00:00:00:00"

					pkt[IP].src = "10.0.0.66"
					pkt[IP].dst = "239.1.2.3"
					return pkt

				for pkt in self.current_pcap:
					zero_dst(pkt)

				sendp(self.current_pcap, iface=self.selected_interface["name"])

				# for pkt in self.current_pcap:
				# 	print(pkt[Ether].dst)
				# 	# Zero dst MAC address
				# 	pkt[Ether].dst = "00:00:00:00:00:00"
				#
				# 	print(pkt.summary())
				# 	print(pkt[Ether].dst)
				#
				# 	# Send the packet
				# 	# FIXME: This will probably not work for linux... needs testing
				# 	try:
				# 		sendp(pkt, iface=self.selected_interface["name"])
				# 	except ValueError as err:
				# 		logging.error("Cound not send the packet... sendp os: " + str(err))


def configure_interface(interface=None):
	"""Set the self.selected_interface variable. All actions are performed through this nic"""

	if os.name == "nt":
		print("Running Windows")
		nic_info = get_windows_if_list()
		available_interfaces = [name["netid"] for name in nic_info]
	elif os.name == "posix":
		print("Running Linux")
		available_interfaces = get_if_list()

	if not interface:
		print("Available interface list:")
		print(json.dumps(available_interfaces, indent=4))

		interface = input("Enter interface name: ")

	for nic in nic_info:
		try:
			if nic["netid"] == interface:
				# DEBUG print("Nic type is {}".format(type(nic)))
				# DEBUG print(json.dumps(nic_info, indent=4))
				return nic
		except KeyError:
			if interface == nic.keys():
				# DEBUG print("Nic type is {}".format(type(nic)))
				return nic
			else:
				logging.error("Failed to find nic dict")

if __name__ == "__main__":
	krft = pkt_craft("Ethernet 2")
	krft.menu()
