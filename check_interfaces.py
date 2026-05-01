from scapy.all import get_if_list, get_if_addr

for iface in get_if_list():
    try:
        print(iface, "->", get_if_addr(iface))
    except:
        pass