from invoke import task, run
from Toolkit.multicast import MulticastMgr

# Assign a manager by supplying the IP of the target switch device
mgr = MulticastMgr(switch_ip="192.168.0.1")

@task
def multicast_join(c, addr):
  mgr.join(addr)

  try:
    print(f'Multicast JOIN has been sent for {addr}. Entering while loop... Ctrl+C to exit and close socket.')
    while True: pass
  except KeyboardInterrupt:
    mgr.leave(addr)

@task
def sniff(c):
  mgr.sniff_on_interface()  