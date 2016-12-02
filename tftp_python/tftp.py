#! /usr/bin/python

import sys,socket,struct,select

BLOCK_SIZE= 512

OPCODE_RRQ=   1
OPCODE_WRQ=   2
OPCODE_DATA=  3
OPCODE_ACK=   4
OPCODE_ERR=   5

MODE_NETASCII= "netascii"
MODE_OCTET=    "octet"
MODE_MAIL=     "mail"

TFTP_PORT=6969

# Timeout in seconds
TFTP_TIMEOUT= 2
MAX_TRIES = 10

ERROR_CODES = ["Undef",
               "File not found",
               "Access violation",
               "Disk full or allocation exceeded",
               "Illegal TFTP operation",
               "Unknown transfer ID",
               "File already exists",
               "No such user"]

# Internal defines
TFTP_GET = 1
TFTP_PUT = 2

# Debug mode
DEBUG = True


def make_packet_rrq(filename, mode):
    # Note the exclamation mark in the format string to pack(). What is it for?
    s = filename + '\0' + mode + '\0'
    return struct.pack("!H", OPCODE_RRQ) + s.encode('ascii')
# return struct.pack("!HsHsH", OPCODE_RRQ, bytes(filename, 'utf-8'), 0, bytes(mode, 'utf-8'), 0)

def make_packet_wrq(filename, mode):
    s = filename + '\0' + mode + '\0'
    return struct.pack("!H", OPCODE_WRQ) + s.encode('ascii')

def make_packet_data(blocknr, data):
    return struct.pack("!HH", OPCODE_DATA, blocknr) + data

def make_packet_ack(blocknr):
    return struct.pack("!HH", OPCODE_ACK, blocknr)

def make_packet_err(errcode, errmsg):
    s = errcode + errmsg + '\0'
    return struct.pack("!H", OPCODE_ERR) + s.encode('ascii')

def parse_packet(msg):
    """This function parses a recieved packet and returns a tuple where the
        first value is the opcode as an integer and the following values are
        the other parameters of the packets in python data types"""
    opcode = struct.unpack("!H", msg[:2])[0]
    if opcode == OPCODE_RRQ:
        l = msg[2:].split('\0')
        if len(l) != 3:
            return None
        return opcode, l[1], l[2]
    elif opcode == OPCODE_ACK:
        block = struct.unpack("!H", msg[2:4])[0]
        return opcode, block
    elif opcode == OPCODE_WRQ:
        filename = msg[2:].split('\0')
        mode = msg[(2+len(filename)+1):].split('\0')
        return opcode, filename, mode
    elif opcode == OPCODE_DATA:
        recv_msg = msg[4:]
        block = struct.unpack("!H", msg[2:4])[0]
        return opcode, block, recv_msg
    elif opcode == OPCODE_ERR:
        error_code = struct.unpack("!H", msg[2:4])[0]
        error_message = msg[4:]
        # error_message = struct.unpack("!H", msg[4:])[0]
        return opcode, error_code, error_message
    return None

def handle_error(parsed_pack, opcode):
    parsed_pack = parse_packet(parsed_pack[0])
    if parsed_pack[0] != opcode:
        if parsed_pack[0] == OPCODE_ERR:
            print('Error: ' + ERROR_CODES[parsed_pack[1]])
        else:
            print('Error: Unespected opcode')
        return True
    return False
def print_debug(message):
    if(DEBUG):
        print(message)
    return()

def tftp_transfer(fd, hostname, direction):
    addr_info = socket.getaddrinfo(hostname,TFTP_PORT)[0][4]
                
    #fd = file descriptor
    # Implement this function
    
    # Open socket interface
    
    # Check if we are putting a file or getting a file and send
    #  the corresponding request.
    
    # Put or get the file, block by block, in a loop.

    filename = fd.name
    
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(TFTP_TIMEOUT)
    
    if direction == TFTP_GET:
        #receive
        # sent block, the block server sent to us
        # ack block,  the ack we sent to server
                 
        current_packet = make_packet_rrq(filename, MODE_OCTET)
        current_msg_size = BLOCK_SIZE
        ack_block =0
        # as long as it is not the last message
        while current_msg_size >= BLOCK_SIZE:
            tries = 0
            # try receiveing a new packet 1-MAX_TRIES times
            while(tries < MAX_TRIES):
                print_debug("try get")
                try:
                    print_debug("before recv")
                    bytes_sent = s.sendto(current_packet, addr_info)    
                    recv = s.recvfrom(BLOCK_SIZE+4)
                    print_debug("after recv")
                    break
                except socket.timeout:
                    print_debug("timeoutexception get")                        
                    tries += 1
            if handle_error(recv, OPCODE_DATA): # handle unexpected opcode
                return ""
            recv_pack = recv[0]
            addr_info = recv[1]   #upade address
            parsed_pack = parse_packet(recv_pack)
            sent_block = parsed_pack[1]
            
            #if we received a new block of data, save it to a file and make an ack packet
            if sent_block == ack_block +1 : 
                ack_block = sent_block
                fd.write( parsed_pack[2])
                current_msg_size = len(parsed_pack[2])
                current_packet= make_packet_ack(parsed_pack[1])
                
                
            if DEBUG:
                print("Received block: %d"% (ack_block))
        if current_msg_size < BLOCK_SIZE:
            # send last ack
            bytes_sent = s.sendto(current_packet, addr_info)
        return ""
        

    elif direction == TFTP_PUT:
        # sent_block, block number we sent to server
        # ack_block   block number the server have acked(received)
        current_packet = make_packet_wrq(filename, MODE_OCTET)
        sent_block = -1
        ack_block = -1
        current_msg = "start"
        tries = 0
        # as long as we have something to send
        while len(current_msg) != 0 :
            if DEBUG:
                print('Sending block nr: %d'% (ack_block +1))
            # if we are sending data
            if ack_block >= 0:
                # send new data if acked, otherwise send the same data again
                if sent_block == ack_block:
                    current_msg = fd.read(BLOCK_SIZE)
                if len(current_msg) == 0:
                    return ""
                current_packet = make_packet_data(ack_block+1, current_msg)

            # try sending data 1-MAX_TRIES times        
            while(tries < MAX_TRIES):
                print_debug("try put")
                try:
                    bytes_sent = s.sendto(current_packet,  addr_info)
                    recv = s.recvfrom(BLOCK_SIZE)
                    break
                except socket.timeout:
                    print_debug("timeoutexception put")
                    tries += 1
                            
            if handle_error(recv,OPCODE_ACK) or tries>= MAX_TRIES : ## handles unexpected opcode
                return ""
            # success  change the block number to send 
            sent_block  = ack_block +1
            recv_parsed = parse_packet(recv[0])
            ack_block = recv_parsed[1]
            addr_info = recv[1]
            tries = 0
            

        return ""
    #send

    


    # while True:
    # Wait for packet, write the data to the filedescriptor or
    # read the next block from the file. Send new packet to server.
    # Don't forget to deal with timeouts and received error packets.
    # pass

    
def usage():
    """Print the usage on stderr and quit with error code"""
    sys.stderr.write("Usage: %s [-g|-p] FILE HOST\n" % sys.argv[0])
    sys.exit(1)


def main():
    # No need to change this function
    global TFTP_PORT
    direction = TFTP_GET
    if len(sys.argv) == 3:
        filename = sys.argv[1]
        hostname = sys.argv[2]
    elif len(sys.argv) == 4:
        if sys.argv[1] == "-g":
            direction = TFTP_GET
        elif sys.argv[1] == "-p":
            direction = TFTP_PUT
        else:
            usage()
            return
        filename = sys.argv[2]
        hostname = sys.argv[3]
    elif len(sys.argv) ==5:
        if sys.argv[1] == "-g":
            direction = TFTP_GET
        elif sys.argv[1] == "-p":
            direction = TFTP_PUT
        else:
            usage()
            return
        filename = sys.argv[2]
        hostname = sys.argv[3]
        TFTP_PORT = int(sys.argv[4])
        
   
        
    else:
        usage()
        return
    if direction == TFTP_GET:
        print ("Transfer file %s from host %s and port %d" % (filename, hostname,TFTP_PORT))
    else:
        print ("Transfer file %s to host %s and port %d" % (filename, hostname,TFTP_PORT))

    try:
        if direction == TFTP_GET:
            fd = open(filename, "wb")
        else:
            fd = open(filename, "rb")
    except IOError as e:
        sys.stderr.write("File error (%s): %s\n" % (filename, e.strerror))
        sys.exit(2)
    
        
    tftp_transfer(fd, hostname, direction)
    fd.close()

if __name__ == "__main__":
    main()
