import scapy.all as scapy

# Broadcasts ARP requests in LAN to obtain MAC address
def scan(ip):
    # Building an ARP request packet with destination IP 
    arp_request = scapy.ARP(pdst=ip)

    # Building an Ether frame with broadcast MAC address
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")

    # Combining both packets Ether and ARP to a single request 
    arp_request_broadcast = broadcast/arp_request

    # Sending and reciving the combined request . srp() was used to include the Ether frame
    reply_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    
    client_lists = []

    for element in reply_list:

        # Crafting a dict from replies for simplifying device data
        client_dict = {

            "ip": element[1].psrc,
            "mac": element[1].hwsrc,
            "source": element[1].psrc,
            "ProtocolType": element[1].hwtype,
            "HardwareType": element[1].ptype
        }
    
        client_lists.append(client_dict)

    return client_lists


# To format results into user readable format
def print_result(result_list):

    print("IP\t\t\tMAC Address\t\t\tSource\n--------------------------------------------------------------------")
    for client in result_list:
        print(client["ip"] + "\t\t" + client["mac"] + "\t\t" + client["source"])






scan_result = scan("192.168.1.1/24")

print_result(scan_result)



