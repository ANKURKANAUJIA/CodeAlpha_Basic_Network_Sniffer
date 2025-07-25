#!/usr/bin/env python3
import sys
from scapy.all import sniff, Ether, IP, TCP, UDP, ICMP

def packet_callback(packet):
    """
    This function is called for each captured packet.
    It analyzes the packet and prints its details.
    """
    # --- Ethernet Layer (Layer 2) ---
    if Ether in packet:
        eth_layer = packet[Ether]
        print(f"\n[+] New Packet: {eth_layer.src} -> {eth_layer.dst}")

    # --- IP Layer (Layer 3) ---
    if IP in packet:
        ip_layer = packet[IP]
        protocol = ip_layer.proto
        protocol_name = ""

        # --- Transport Layer (Layer 4) ---
        if protocol == 6 and TCP in packet: # 6 is the protocol number for TCP
            protocol_name = "TCP"
            tcp_layer = packet[TCP]
            payload = bytes(tcp_layer.payload)
            print(f"    Protocol: {protocol_name} | {ip_layer.src}:{tcp_layer.sport} -> {ip_layer.dst}:{tcp_layer.dport}")
            
            # Displaying payload
            if payload:
                # Try to decode as UTF-8, otherwise show raw bytes
                try:
                    payload_text = payload.decode('utf-8', errors='replace')
                    print(f"    Payload (text):\n---BEGIN---\n{payload_text}\n---END---")
                except Exception:
                    print(f"    Payload (raw bytes): {payload}")


        elif protocol == 17 and UDP in packet: # 17 is the protocol number for UDP
            protocol_name = "UDP"
            udp_layer = packet[UDP]
            payload = bytes(udp_layer.payload)
            print(f"    Protocol: {protocol_name} | {ip_layer.src}:{udp_layer.sport} -> {ip_layer.dst}:{udp_layer.dport}")
            
            # Displaying payload
            if payload:
                try:
                    payload_text = payload.decode('utf-8', errors='replace')
                    print(f"    Payload (text):\n---BEGIN---\n{payload_text}\n---END---")
                except Exception:
                    print(f"    Payload (raw bytes): {payload}")


        elif protocol == 1 and ICMP in packet: # 1 is the protocol number for ICMP
            protocol_name = "ICMP"
            print(f"    Protocol: {protocol_name} | {ip_layer.src} -> {ip_layer.dst}")
        
        else:
            # For other IP protocols or if the transport layer isn't TCP/UDP/ICMP
            protocol_name = f"Other ({protocol})"
            print(f"    Protocol: {protocol_name} | {ip_layer.src} -> {ip_layer.dst}")
            
            # Display raw payload from IP layer if it exists
            payload = bytes(ip_layer.payload)
            if payload:
                 print(f"    Payload (raw bytes): {payload}")

def main():
    """
    Main function to start the sniffer.
    """
    print("Starting network sniffer...")
    print("Press Ctrl+C to stop.")
    
    # The sniff function from scapy does the magic.
    # prn: function to call for each packet
    # store: 0 means we don't keep packets in memory
    # stop_filter: a function that would stop the capture if it returns True
    try:
        sniff(prn=packet_callback, store=0)
    except PermissionError:
        print("\n[!] Error: Permission denied.")
        print("    Please run this script with root/administrator privileges.")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] An unexpected error occurred: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
