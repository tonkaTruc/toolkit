from custom_headers.PTP import *
from custom_headers.erspan import *
from scapy.all import *
import numpy as np
import sys
import matplotlib.pyplot as plt
import json

# ERSPAN timestamp wrapping
erspan_wrap_count = 0
all_erspan_ts = [0]


def check_erspan_wrap(pkt):
	""" Has ERSPAN timestamp wrapped?"""

	global erspan_wrap_count

	if pkt[ERSPAN_III].timestamp < all_erspan_ts[-1]:
		print("\n\n\n\nERSPAN timestamp has wrapped: %s < %s\n\n\n\n" % (pkt[ERSPAN_III].timestamp, all_erspan_ts[-1:][0]))
		erspan_wrap_count += 1

	all_erspan_ts.append(pkt[ERSPAN_III].timestamp)


def get_erpsan_header(pkt):
	"""
	Retrieve values from the ERSPAN_III header of the packet and return 1d numpy array containing:
		- ERSPAN timestamp (ns)
		- ERSPAN linear timestamp (ns)
		- ERSPAN linear offset value (ns)


	:param pkt:
	:return 1d numpy array:
	"""
	# Create temp empty array to store ERSPAN header for packet
	erspan_header_array = np.zeros(3)

	# Store RAW timestamp info in array position 0
	erspan_header_array[0] = pkt[ERSPAN_III].timestamp
	print("Written ERSPAN ts value (%s) to ERSPAN array idx 0" % erspan_header_array[0])

	# Store LINEAR ts value in array position 1
	erspan_header_array[1] = erspan_header_array[0] + erspan_wrap_count * (2 ** 32)
	print("Written ERSPAN linear ts value (%s) to ERSPAN array idx 1" % erspan_header_array[1])

	# TODO: Finish this expression when master array is written to and available: erspan_lin_offset = erspan_ts_linear - erspan_ts_raw[0]
	# Store LINEAR OFFSET ts value in array position 2
	erspan_header_array[2] = erspan_header_array[1]
	print("Written ERSPAN linear offset value (%s) to ERSPAN array idx 2" % erspan_header_array[2])

	return erspan_header_array


def ptp_storage(pkt):
	"""
	Pull timestamp data from ERSPAN header (if exists, idx will be zeros if not)
	Pull desired data from IEEE1588 headers
	Concatanate header info into a single 1d numpy array and return

	[[
		ERSPAN TS raw
		ERSPAN TS linear
		ERSPAN TS linear offset
		packet seqno,
		messageType
		originTimeStamp_ns,
		originTimeStamp_ns offset,
		originTimeStamp_s,
		originTimeStamp_s offset,
		Correction,
		SourcePortID,
		logMessagePeriod
	]]


	:param pkt:
	:return ndarray:
	"""

	if pkt.haslayer(ERSPAN_III):
		# Pull all ERSPAN header in formation and store in relevant numpy array
		erspan_array = get_erpsan_header(pkt)
	else:
		erspan_array = np.zeros(4)

	try:
		# If <SYNC> or <DELAY_REQ> packet
		if pkt[ieee1588].messageType in [0x0, 0x1]:
			"""
			Produce a 1d numpy containing relevant parameter values from a SYNC / DELAY_REQ packet
			
			Returned numpy array shape and contents:
			[[
				packet seqno,
				messageType
				originTimeStamp_ns,
				originTimeStamp_ns offset,
				originTimeStamp_s,
				originTimeStamp_s offset,
				Correction,
				SourcePortID,
				logMessagePeriod
			]]
			"""

			# Create temp empty 2d array to store SYNC header values
			ieee1588_array = np.zeros(9)

			# Sequence number
			ieee1588_array[0] = pkt[ieee1588].sequenceId
			print("Written PTP seqno value (%s) to IEEE1588 array idx 0" % ieee1588_array[0])

			# MessageID
			ieee1588_array[1] = pkt[ieee1588].messageType
			print("Written PTP messageID value (%s) to IEEE1588 array idx 1" % ieee1588_array[1])

			# RAW origin TS (ns)
			ieee1588_array[2] = pkt[ieee1588].originTimestamp_ns
			print("Written PTP timestamp_ns value (%s) to IEEE1588 array idx 2" % ieee1588_array[2])

			# origin TS (ns) offset
			ieee1588_array[3] = pkt[ieee1588].originTimestamp_ns # - origin_ts_ns_raw[0] **Fist sync packet TS ns value in master
			print("Written PTP timestamp_ns offset value (%s) to IEEE1588 array idx 3" % ieee1588_array[3])

			# RAW origin TS (s)
			ieee1588_array[4] = pkt[ieee1588].originTimestamp_s
			print("Written PTP timestamp_s value (%s) to IEEE1588 array idx 4" % ieee1588_array[4])

			# origin TS (s) offset
			ieee1588_array[5] = pkt[ieee1588].originTimestamp_s # - origin_ts_ns_raw[0] **Fist sync packet TS s value in master
			print("Written PTP timestamp_s offset value (%s) to IEEE1588 array idx 5" % ieee1588_array[5])

			# Correction
			ieee1588_array[6] = pkt[ieee1588].correction
			print("Written PTP correction value (%s) to IEEE1588 array idx 6" % ieee1588_array[6])

			# Source port ID
			ieee1588_array[7] = pkt[ieee1588].SourcePortId
			print("Written PTP SourcePortID value (%s) to IEEE1588 array idx 7" % ieee1588_array[7])

			# Log message period
			ieee1588_array[8] = pkt[ieee1588].logMessagePeriod
			print("Written PTP LogMessagePeriod value (%s) to IEEE1588 array idx 8" % ieee1588_array[8])

			# # Join the ERSPAN header array with SYNC
			# return np.concatenate([erspan_header_info, sync_header_array])

		elif pkt[ieee1588].messageType == 0x0:
			"""	Produce a 1d numpy containing relevant parameter values from a FOLLOW_UP packet
			
			Returned numpy array shape and contents:
			[[
				packet seqno,
				messageType
				originTimeStamp_ns,
				originTimeStamp_ns offset,
				originTimeStamp_s,
				originTimeStamp_s offset,
				Correction,
				SourcePortID,
			]]
			"""

			print("FOLOW UP packet!")

		elif pkt[ieee1588].messageType == 0x9:
			print("DELAY RESP")

		elif pkt[ieee1588].messageType == 0xb:
			print("ANNOUNCE")

		elif pkt[ieee1588].messageType == 0xd:
			print("MGMT")
		else:
			print("Not a recognised PTP packet: %s" % pkt.summary())

	except IndexError as err:
		print("\t%s: %s" % (err, pkt.summary()))

	try:
		# Concatanate the ERSPAN header values with the IEEE1588 data
		return np.concatenate([erspan_array, ieee1588_array], axis=0)
	except UnboundLocalError as err:
		print(err)


if __name__ == "__main__":

	cap_mode = input("Process <live> or <offline> capture?: ").lower()

	if cap_mode == "offline":
		# cap = rdpcap("/home/tommys/PHABRIX/toolkit/cap_store/ptp_cap.pcap")
		cap = rdpcap("/home/tommys/PHABRIX/toolkit/cap_store/ERSPAN_PTP_sample.pcap")
		# cap = rdpcap("/home/tommys/PHABRIX/toolkit/cap_store/erspan_multi_flow[reduced].pcap")
		# cap = rdpcap("/home/tommys/PHABRIX/toolkit/cap_store/sync_msgs.pcap")
	elif cap_mode == "live":
		pkt_count = int(input("How many live capture packets?: "))
		cap = sniff(count=int(input("How many live capture packets?: ")), interface=input("Please enter interface to capture from: "))

	print("Capture details: \t%s" % cap.summary)
	full_capture_array = np.zeros((len(cap), 2))

	# # Create storage arrays for packet data
	# print("Creating numpy arrays to store packet data...")
	# sync_follow_up = np.empty((len(cap), 2))
	# print("SYNC / FOLLOW_UP: \t\tSize: %s Dimentions: %s Shape: %s" % (sync_follow_up.size,
	# 																   sync_follow_up.ndim,
	# 																   sync_follow_up.shape))
	# req_resp = np.empty((len(cap), 2))
	# print("DELAY_REQ / DELAY RESP: \tSize: %s Dimentions: %s Shape: %s" % (req_resp.size,
	# 																	   req_resp.ndim,
	# 																	   req_resp.shape))

	for idx, pkt in zip(full_capture_array, cap):
		check_erspan_wrap(pkt)

		if pkt.haslayer(ieee1588):

			# Assign a 1d numpy array containing timstamp + other info for ERSPAN and IEEE1588 layers of single pkt to var
			packet_array = ptp_storage(pkt)


			# Verify the array contains valid data (value will be None if IEEE1588 layer has not been decoded or the
			# layer does not exist)
			if isinstance(packet_array, type(None)):
				print("SHOULD SKIP")
				continue
			elif packet_array[4] in [0x0]:

				plt.xlabel("Sync message sequence number")
				plt.ylabel("Sync message timestamp_ns")
				plt.scatter(packet_array[3], packet_array[5])

			elif packet_array[4] == "fff":
					# TODO: Add this packet data to master packet bucket (ieee1588 seqno value is stored @ idx 3 of the ERSPAN / IEEE1588 concatanated array)
					print("\n\n\n\n\n\n\n\n")

					# packet_array.flatten()
					print(idx)
					print(full_capture_array.size)
					print(full_capture_array.shape)
					print(full_capture_array.ndim)

					# idx[1] = packet_array

					# new_array = np.insert(full_capture_array, 2, packet_array, axis=1)

				# 	print(idx)
				# 	print("idx size after: %s" % idx.size)
				# 	print("idx shape after: %s" % idx.shape)
				# 	print("idx dim after: %s" % idx.ndim)
				#
				# 	print(new_array)
				# 	print("new_array size: %s" % new_array.size)
				# 	print("new_array shape: %s" % new_array.shape)
				# 	print("new_array dim: %s" % new_array.ndim)
				#
				# 	print("Written to index: %s" % idx)
				# 	print("\n\n\n\n\n\n\n\n")
				# 	input("-------- ")
				#
				# print("-------------------- VALID!!!!!!!!")
		else:
			print("No PTP")


	plt.savefig("ptp_seqno_vs_sync_ts_ns.png")

	# print(full_capture_array)
	# for idx in full_capture_array:
	# 	idx[0] = 1
	# 	idx[1] = 2
	#
	# print(full_capture_array)




