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
		self.selected_interface = self.configure_interface(interface)
		logging.debug(self.selected_interface)
		print("Selected interface = %s" % self.selected_interface)

		# Obtain IP address of host network adapter.
		# (try except for formatting of win / unix nic data structure))
		try:
			self.ip = netifaces.ifaddresses(self.selected_interface["guid"])
		except KeyError:
			self.ip = netifaces.ifaddresses(self.selected_interface)

		# Get hostname
		self.hostname = socket.gethostname()

		self.current_pcap = None

		print(130*"-")
		print("Host info:")
		print("Hostname: {}".format(self.hostname))
		print("Currently assigned NIC: {}".format(self.selected_interface))
		print("Ip address: {}".format(json.dumps(self.ip, indent=4)))
		print(130*"-")

	def configure_interface(self, interface=None):
		"""Set the self.selected_interface variable. All actions are performed through this nic"""

		if os.name == "nt":
			print("Running Windows")
			nic_info = get_windows_if_list()
			available_interfaces = [name["netid"] for name in nic_info]
		elif os.name == "posix":
			print("Running Linux")
			available_interfaces = get_if_list()

		print("Available interface list:")
		print(json.dumps(available_interfaces, indent=4))

		if not interface:
			interface = input("Enter interface name: ")

		for nic in nic_info:
			try:
				if nic["netid"] == interface:
					print("FOUND THE NIC")
					print("Nic type is {}".format(type(nic)))
					print(json.dumps(nic_info, indent=4))
					return nic
			except KeyError:
				if interface == nic.keys():
					print("FOUND THE NIC THIS WAY")
					print("Nic type is {}".format(type(nic)))
					return nic
				else:
					logging.error("Failed to find nic dict")

	def capture(self, interface, pkt_count=None):

		# Reset global counter
		global packet_counter
		packet_counter = 0000

		global rtp_stamps
		
		def count_capture(packet):
			global packet_counter
			packet_counter += 1

			return "{} {}".format(packet_counter-1, packet.summary())

		# cap = sniff(iface=interface, count=int(pkt_count), prn= lambda x: x.nsummary())
		# cap = sniff(iface=interface, count=int(pkt_count), prn=count_capture)
		cap = sniff(iface=interface, count=int(pkt_count), prn=self.on_rx)
		
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
		
		self.current_pcap = cap
		self.menu()

		if pkt.haslayer(UDP):
			udp = pkt[UDP]

		if pkt.haslayer(TCP):
			tcp = pkt[TCP]

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

				
		# if UDP in pkt:
		# 	pkt[UDP].src = "00:00:00:00:00:00"

		#return pkt.summary()

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

	def menu(self):
		print("\nCurrent capture file stats:\t{} ({})".format(self.current_pcap, type(self.current_pcap)))
		print("Selected interface:\t\t\t{} ({})".format(self.selected_interface["name"], type(self.selected_interface)))

		menu_opts = {
			"\n1": "Produce new .pcap",
			"2": "Import .pcap from drive",
			"3": "Inspect cap file",
			"4": "Filter current .pcap",
			"5": "Replay current .pcap",
			"0": "Export current .pcap"
		}
		for opt in menu_opts:
			print(opt, menu_opts[opt])
		usr_opt = input("\nSelect option: ")

		# Export current .pcap file
		if usr_opt == "000":
			print("Exporting current .pcap var: {}".format(self.current_pcap))

			# Exit to menu if active cap file is empty
			if not self.current_pcap:
				logging.error("Active cap file is empty... nothing to export")
				self.menu()

			wrpcap("exported_cap_file.pcap", self.current_pcap)

		if usr_opt == "1":
			count = input("Enter count to terminate sniff: ")
			self.capture(self.selected_interface["name"], count)
		elif usr_opt == "2":
			path = input("Enter full path to target .pcap: ")
			cap = sniff(offline=path, prn=self.zero_src)
			cap.nsummary()

			self.current_pcap = cap
			self.menu()
		elif usr_opt == "3":
			self.inspect(mode="iterate")
			self.menu()

		elif usr_opt == "4":
			print("FILTER")
		elif usr_opt == "5":

			def zero_dst(pkt):
				pkt[Ether].dst = "00:00:00:00:00:00"
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

			self.menu()


if __name__ == "__main__":
	krft = pkt_craft("Monitor port")
	krft.menu()
