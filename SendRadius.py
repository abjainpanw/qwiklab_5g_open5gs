import csv
import argparse
import sys
from scapy.all import *
from decimal import *
from scapy.layers import *
from scapy.contrib import pfcp
import re
import time
import os
from scapy.utils import RawPcapReader, PcapWriter, PcapReader
import shutil
import traceback
import scapy.layers.l2
import scapy.layers.inet
from scapy.all import sniff
import binascii
from pyrad.client import Client
from pyrad.dictionary import Dictionary
import json 
import pyrad.packet


imsilist = {}
seidlist = {}
radius_server = "172.16.10.10"
shared_secret = "open5gslab"
radius_port = 1813  


def TBCD_decode(input):
  #print("TBCD_encode Input value is " + str(input))
  offset = 0
  output = ''
  while offset < len(input):
      if "f" not in input[offset:offset+2]:
          bit = input[offset:offset+2]    #Get two digits at a time
          bit = bit[::-1]                 #Reverse them
          output = output + bit
          offset = offset + 2
      else:   #If f in bit strip it
          bit = input[offset:offset+2]
          output = output + bit[1]
          #print("TBCD_decode output value is " + str(output))
          return output
  return output


def seidhash(ip, seid):
    hashed_seid = str(ip) + "/" + str(seid)
    return hashed_seid


# Define the criteria for the packet to match
def packet_callback(packet):

    if packet.haslayer('PFCP') and packet[pfcp.PFCP].message_type==50:  # Replace with your specific condition
        #print(f"Packet received: {packet.summary()}")
  
        imsi = TBCD_decode(binascii.hexlify(packet.getlayer(pfcp.IE_UserId).imsi).decode('ascii'))
        imei = TBCD_decode(binascii.hexlify(packet.getlayer(pfcp.IE_UserId).imei).decode('ascii'))

        seidlist[seidhash(packet[pfcp.IE_FSEID].ipv4, packet[pfcp.IE_FSEID].seid)] = {}
        seidlist[seidhash(packet[pfcp.IE_FSEID].ipv4, packet[pfcp.IE_FSEID].seid)]['peerseid'] = ""
        seidlist[seidhash(packet[pfcp.IE_FSEID].ipv4, packet[pfcp.IE_FSEID].seid)]['imsi'] = imsi
        if not imsi in imsilist:
            imsilist[imsi] = {}
            imsilist[imsi]['UEIP'] = packet.getlayer(pfcp.IE_UE_IP_Address, 1).ipv4
            imsilist[imsi]['imei'] = imei



    elif packet.haslayer('PFCP') and packet[pfcp.PFCP].message_type==51 and seidhash(packet[IP].dst, packet[pfcp.PFCP].seid) in seidlist:
        #print(f"Packet received: {packet.summary()}")
        imsi = seidlist[seidhash(packet[IP].dst, packet[pfcp.PFCP].seid)]['imsi']
        seidlist[seidhash(packet[pfcp.IE_FSEID].ipv4, packet[pfcp.IE_FSEID].seid)] = {}
        seidlist[seidhash(packet[pfcp.IE_FSEID].ipv4, packet[pfcp.IE_FSEID].seid)]['peerseid'] = seidhash(packet[IP].dst, packet[pfcp.PFCP].seid)
        seidlist[seidhash(packet[pfcp.IE_FSEID].ipv4, packet[pfcp.IE_FSEID].seid)]['imsi'] = imsi
        seidlist[seidhash(packet[IP].dst, packet[pfcp.PFCP].seid)]['peerseid'] = seidhash(packet[pfcp.IE_FSEID].ipv4, packet[pfcp.IE_FSEID].seid)


        #Constructing Radius Packet

        vsa_imsi = RadiusAttr_Vendor_Specific(type=26, vendor_id=10415, vendor_type=1, value=imsi)
        vsa_imei = RadiusAttr_Vendor_Specific(type=26, vendor_id=10415, vendor_type=20, value=imsilist[imsi]['imei'])
        framed_ip = RadiusAttr_Framed_IP_Address(type=8, len=6, value=imsilist[imsi]['UEIP'])
        nas_ip = RadiusAttr_NAS_IP_Address(type=8, len=6, value="172.16.9.10")
        msg_type = RadiusAttr_Acct_Status_Type(type=40, len=6, value=1)
        radius_packet = Radius(code=4, id=1)
        radius_packet.attributes.append(nas_ip)
        radius_packet.attributes.append(vsa_imsi)
        radius_packet.attributes.append(vsa_imei)
        radius_packet.attributes.append(framed_ip)
        radius_packet.attributes.append(msg_type)
        radius_packet.len = len(vsa_imsi) + len(vsa_imei) + len(framed_ip) + len(nas_ip) + len(msg_type) + 20
        radius_packet.authenticator = radius_packet.compute_authenticator(raw(radius_packet), shared_secret.encode())
        send(IP(dst=radius_server)/UDP(sport=RandShort(), dport=radius_port)/radius_packet, verbose=False)


    elif packet.haslayer('PFCP') and packet[pfcp.PFCP].message_type==55 and seidhash(packet[IP].dst, packet[pfcp.PFCP].seid) in seidlist:

        #print(f"Packet received: {packet.summary()}")
        imsi = seidlist[seidhash(packet[IP].dst, packet[pfcp.PFCP].seid)]['imsi']

        vsa_imsi = RadiusAttr_Vendor_Specific(type=26, vendor_id=10415, vendor_type=1, value=imsi)
        vsa_imei = RadiusAttr_Vendor_Specific(type=26, vendor_id=10415, vendor_type=20, value=imsilist[imsi]['imei'])
        framed_ip = RadiusAttr_Framed_IP_Address(type=8, len=6, value=imsilist[imsi]['UEIP'])
        nas_ip = RadiusAttr_NAS_IP_Address(type=8, len=6, value="172.16.9.10")
        msg_type = RadiusAttr_Acct_Status_Type(type=40, len=6, value=2)
        radius_packet = Radius(code=4, id=1)
        radius_packet.attributes.append(nas_ip)
        radius_packet.attributes.append(vsa_imsi)
        radius_packet.attributes.append(vsa_imei)
        radius_packet.attributes.append(framed_ip)
        radius_packet.attributes.append(msg_type)
        radius_packet.len = len(vsa_imsi) + len(vsa_imei) + len(framed_ip) + len(nas_ip) + len(msg_type) + 20
        radius_packet.authenticator = radius_packet.compute_authenticator(raw(radius_packet), shared_secret.encode())
        send(IP(dst=radius_server)/UDP(sport=RandShort(), dport=radius_port)/radius_packet, verbose=False)

        del imsilist[imsi]
        del seidlist[seidlist[seidhash(packet[IP].dst, packet[pfcp.PFCP].seid)]['peerseid']]
        del seidlist[seidhash(packet[IP].dst, packet[pfcp.PFCP].seid)]


    #print(seidlist)
    #print(imsilist)



# Sniff packets on the specified interface
def start_sniffing(interface):
    #print(f"Sniffing on interface {interface}")
    sniff(iface=interface, prn=packet_callback, store=0)

if __name__ == "__main__":
    network_interface = 'ens224'  # Replace with your network interface
    start_sniffing(network_interface)