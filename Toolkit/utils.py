
def get_best_interface_for(addr):
  """Create a temp socket and use that to connect to an endpoint. Return the local nic IP address that made the connection"""
  
  import socket
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

def get_interface_info(interface=None):
  """Gather list of available network interfaces and return NIC information in dict format"""

  import netifaces
  import os
  import json

  nic_info = {}

  if os.name == "nt":
    from scapy.arch.windows import get_windows_if_list
    
    # Produce a dict of interface names and guid values for all interfaces
    available_interfaces = {name["name"]: name["guid"] for name in get_windows_if_list()}
    
    
    for int_name, int_guid in available_interfaces.items():
      try:
        nic_info[int_name] = netifaces.ifaddresses(int_guid)[netifaces.AF_INET][0]
        nic_info[int_name].update({"guid": int_guid})
        nic_info[int_name].update({"name": int_name})
      except KeyError:
        print(f"No IPv4 address assigned to {int_name}")
      except ValueError as err:
        break
    
  elif os.name == "posix":
    print("Running Linux")
    available_interfaces = [x for x in get_if_list()]

    for int_name in available_interfaces:
      try:
        nic_info[int_name] = netifaces.ifaddresses(int_name)[netifaces.AF_INET][0]
        nic_info[int_name].update({"guid": None})
        nic_info[int_name].update({"name": int_name})
      except KeyError:
        print("No IPv4 address assigned to NIC %s... " % int_name)
  else:
    print(f"Cannot recognise operating system: {os.name}")
    quit()

  if not interface:
    print(json.dumps(nic_info, indent=2))
    interface = input("Enter interface name: ")

  for name, info in nic_info.items():
    try:
      if name == interface: return info	
    except TypeError:
      print(info)
      print("Nic info type is {}".format(type(info)))
      return info
    else:
      raise ValueError(f"Could not recognise the specified interface name: {interface}")