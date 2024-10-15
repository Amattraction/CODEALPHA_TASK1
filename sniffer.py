from scapy.all import sniff

# Function to process each packet
def process_packet(packet):
    print(packet.summary())

# Main function to start sniffing
def main():
    # Sniff packets on the network interface
    sniff(prn=process_packet, store=False)

if __name__ == "__main__":
    main()
