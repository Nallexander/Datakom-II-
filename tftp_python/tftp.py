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

def handle_error(parsed_pack):
    parsed_pack = parse_packet(parsed_pack[0])
    if parsed_pack[0] == OPCODE_ERR:
        print('Error: ' + ERROR_CODES[parsed_pack[1]])
        return True
    return False

def tftp_transfer(fd, hostname, direction):
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
        rreq = make_packet_rrq(filename, MODE_OCTET)
        
        # print('rreq sent')
        flag = 1
        while(flag == 1):
            if DEBUG:
                print("try 1")
            try:
                bytes_sent = s.sendto(rreq, (hostname, TFTP_PORT))
                recv = s.recvfrom(BLOCK_SIZE+4)
                flag = 0
            except socket.timeout:
                if DEBUG:
                    print("timeoutexception 1")
                flag = 1
       
        if handle_error(recv):
            return()
        recv_pack = recv[0]
        recv_addr = recv[1]
        
        parsed_pack = parse_packet(recv_pack)
        pack_block = parsed_pack[1]

        current_block = pack_block
        msg = parsed_pack[2]
        
        ack = make_packet_ack(parsed_pack[1])
        #bytes_sent = s.sendto(ack, recv_addr)
        current_msg_size = len(parsed_pack[2])
        
        
        while current_msg_size >= BLOCK_SIZE:
            aflag = 1
            aint =0
            while(aflag == 1):
                if DEBUG:
                    print("try 2")
                try:
                    if DEBUG:
                        print('before recv')
                    bytes_sent = s.sendto(ack, recv_addr)    
                    recv = s.recvfrom(BLOCK_SIZE+4)
                    if DEBUG:
                        print('after recv')
                    aflag = 0
                except socket.timeout:
                    if DEBUG:
                        aint = aint+1;
                        print("timeoutexception2 %d" % (aint))
                    aflag = 1
                    if DEBUG:
                        print("flag2 %d" % (aflag))
            if handle_error(recv):
                return()
            recv_pack = recv[0]
            recv_block = recv[1]
            parsed_pack = parse_packet(recv_pack)
            pack_block = parsed_pack[1]
            if pack_block == current_block:
                #Send ack again
                ack = make_packet_ack(parsed_pack[1])
                bytes_sent = s.sendto(ack, recv_addr)
                if DEBUG:
                    print('Resend ack')
                True
            else:
                #Add msg and block 
                current_block = pack_block
                pack_msg = parsed_pack[2]
                msg = msg + pack_msg
                ack = make_packet_ack(parsed_pack[1])
                bytes_sent = s.sendto(ack, recv_addr)
                current_msg_size = len(parsed_pack[2])
                #Send new ack


            if DEBUG:
                print("Getting block: %d"% (current_block))


        fd.write(msg)

    elif direction == TFTP_PUT:

        wreq = make_packet_wrq(filename, MODE_OCTET)
       
        flag = 1
        while(flag == 1):
            if DEBUG:
                print("try 3")
            try:
                bytes_sent = s.sendto(wreq, (hostname, TFTP_PORT))
                recv = s.recvfrom(100)
                flag = 0
            except socket.timeout:
                if DEBUG:
                    print("timeoutexception 3")
                flag = 1
       
        
        
        if handle_error(recv[0]):
            return()
        recv_addr = recv[1]

        parsed_recv = parse_packet(recv[0])
        if parsed_recv[0] == OPCODE_ACK:
            block_ack = parsed_recv[1]
            block_sent = 0
            current_msg = "start"
            while len(current_msg) != 0:
                if DEBUG:
                    print('Sending block nr: %d'% (block_sent +1))
                current_msg = fd.read(512)
                if len(current_msg) != 0:
                    current_packet = make_packet_data(block_ack+1, current_msg)
                   
                    block_sent = block_ack+1
                    flag = 1
                    while(flag == 1):
                        if DEBUG:
                            print("try 4")
                        try:
                            bytes_sent = s.sendto(current_packet, recv_addr)
                            recv = s.recvfrom(100)
                            flag = 0
                        except socket.timeout:
                            if DEBUG:
                                print("timeoutexception 4")
                            flag = 1
                    
                    if handle_error(recv):
                        return()
                    recv_parsed = parse_packet(recv[0])
                    if recv_parsed[0] == OPCODE_ACK:
                        block_ack = recv_parsed[1]
                    elif recv_parsed[0] == OPCODE_ERR:
                        if DEBUG:
                            print('fail')
                    while block_sent != block_ack:
                        if DEBUG:
                            print('packet loss')
                        
                        flag = 1
                        while(flag == 1):
                            if DEBUG:
                                print("try 5")
                            try:
                                bytes_sent = s.sendto(current_packet, recv_addr)
                                recv = s.recvfrom(100)
                                flag = 0
                            except socket.timeout:
                                if DEBUG:
                                    print("timeoutexception 5")
                                flag = 1
                        if handle_error(recv):
                            return()
                        recv_parsed = parse_packet(recv[0])
                        block_ack = recv_parsed[1]
                


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
