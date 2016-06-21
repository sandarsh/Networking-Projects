"""
--------------------------------------BEGIN-----------------------------------------
"""
""" 
Program Outline
------------------------------------------------------------------------------------
The basic goal of this program is to implement a client program which communicates 
with a server using sockets. The program simulates a simple protocol to receive 
predefined messages from the server and send replies.

Types of messages
------------------------------------------------------------------------------------
HELLO (sent by client)
STATUS (received by server)
SOLUTION (sent by client)
BYE (sent by server)

Function List:
------------------------------------------------------------------------------------
establish_tcp_conn()
establish_ssl_conn()
send_hello_msg()
receive_msg()
process_msg()
verify_status_msg_format()
verify_bye_msg_format()
evaluate_status_msg()
send_solution_msg()
close_tcp_conn()

Design Strategy: COMBINING SIMPLER FUNCTIONS
------------------------------------------------------------------------------------
------------------------------------------------------------------------------------
"""

import socket
import sys
import ssl

"""
FUNCTION DEFINITIONS
------------------------------------------------------------------------------------
; establish_tcp_conn: HOSTNAME(IP/URL) PORTNUM -> SOCKET
; GIVEN: A hostname (IP add or URL) and a port number as an argument
; RETURNS: A socket object with an active TCP session
; PURPOSE: To establish a TCP session with the remote host.
: Examples: 
; establish_tcp_conn('cs5700sp16.ccs.neu.edu', 27993)
; establish_tcp_conn('129.10.113.143', 27993)
"""
def establish_tcp_conn(host, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((host , port))
    except:
        print "Failed to establish TCP connection"
        sys.exit()
    return s
"""
------------------------------------------------------------------------------------
; establish_ssl_conn: HOSTNAME(IP/URL) PORTNUM -> SECURE-SOCKET
; GIVEN: A hostname (IP add or URL) and a port number as an argument
; RETURNS: A socket object with an active TCP session using SSL encryption
; PURPOSE: To establish a TCP session with the remote host over SSL.
: Examples: 
; establish_ssl_conn('cs5700sp16.ccs.neu.edu', 27993)
; establish_ssl_conn('129.10.113.143', 27993)
"""
def establish_ssl_conn(host, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ssl_s = ssl.wrap_socket(s, ssl_version = ssl.PROTOCOL_TLSv1, ciphers = "ALL")
        ssl_s.connect((host , port))
    except:
        print "Failed to establish SSL connection"
        sys.exit()
    return ssl_s
"""
------------------------------------------------------------------------------------
; send_hello_msg: SOCKET-OBJECT STRING -> NULL
; GIVEN: A socket and an NUID (as string) as arguments
; RETURNS: NULL (Performs the function of sending a predefined HELLO message to the host)
; PURPOSE: To send HELLO message to the remote host.
"""
def send_hello_msg(s, nuid):
    hello_msg = 'cs5700spring2016 HELLO {}\n'.format(nuid)
    try:
        s.send(hello_msg)
    except:
        print "Failed to send HELLO message"
        sys.exit()
"""
------------------------------------------------------------------------------------
; receive_msg: SOCKET-OBJECT -> STRING
; GIVEN: A socket as an argument
: RETURNS: The string that was received from the host as reply
; PURPOSE: To receive messages from the remote host
"""
def receive_msg(s):
    try:
        reply = s.recv(256)
    except:
        print "Failed to receive STATUS message"
        sys.exit()
    return reply
"""
------------------------------------------------------------------------------------
; process_msg: SOCKET-OBJECT STRING -> NULL
; GIVEN: A socket and an NUID (string) as an argument
; RETURNS: NULL. 
; PURPOSE: Processes the received message from the remote host:
;          1. To check if the message received was a STATUS or a BYE
;          2. To validate if the received message ends with and has only one instance "\n"
;          3. To split the received message at " ".
;          4. To validate if any misplaced " " have arrived in the message.
;          5. Evaluate and send the solution of the expression received in the STATUS message.
;          6. Close the TCP connection
; FUNCTION CALLS: 
;          1. receive_msg()
;          2. verify_status_message_format()
;          3. evaluate_status_msg()
;          4. send_solution_msg()
;          5. verify_bye_msg_format()
;          6. close_tcp_conn() 
"""
def process_msg(sock, nuid):
    status_msg_flag = True
    while status_msg_flag:
        msg_from_server = receive_msg(sock)
        if msg_from_server.endswith("\n") and msg_from_server.count('\n') == 1:
            msg_split = msg_from_server.split(" ")
            if len(msg_split) == 5 and "" not in msg_split:
                if verify_status_msg_format(msg_split):
                    soln = evaluate_status_msg(msg_split)
                    send_solution_msg(sock, soln)
            elif len(msg_split) == 3 and "" not in msg_split:
                if verify_bye_msg_format(msg_split):
                    print msg_split[1]
                    status_msg_flag = False
            else:
                print "Invalid Message format from server"
                status_msg_flag = False
                close_tcp_conn(sock)
                sys.exit()
        else:
            print "Invalid message format from server"
            status_msg_flag = False
            close_tcp_conn(sock)
            sys.exit()
    close_tcp_conn(sock)
"""
------------------------------------------------------------------------------------
; verify_status_msg_format: STRING-LIST -> BOOLEAN
; GIVEN: The list of strings from STATUS generated when split at the " " character.
: RETURNS: "TRUE" if the STATUS message format matches with the provided format
;          "FALSE" if the STATUS message format does not match with the provided format
; PURPOSE: To check if the the STATUS sent by the remote host is as expected by format
;          and to check for character, operator and operand range errors
"""
def verify_status_msg_format(msg_word_list):
    valid_status_msg_format = False
    start_range = 1
    end_range = 1000
    valid_operator_list = ['+', '-', '*', '/']
    if msg_word_list[0] == 'cs5700spring2016' and msg_word_list[1] == 'STATUS':
    	if start_range <= int(msg_word_list[2]) <= end_range and start_range <= int(msg_word_list[4]) <= end_range:
            if msg_word_list[3] in valid_operator_list:
    			valid_status_msg_format = True
            else:
                print "Error: Invalid Operator"
                sys.exit()
        else:
            print "Error: Invalid Operands"
            sys.exit()
    else:
        print "Error: Invalid Status Message Format"
        sys.exit()
    return valid_status_msg_format
"""
------------------------------------------------------------------------------------
; verify_bye_msg_format: STRING-LIST -> BOOLEAN
; GIVEN: The list of strings from BYE generated when split at the " " character
: RETURNS: "TRUE" if the BYE message format matches with the provided format
;          "FALSE" if the BYE message format does not match with the provided format
; PURPOSE: To check if the the BYE sent by the remote host is as expected by format
"""
def verify_bye_msg_format(msg_word_list):
    valid_bye_msg_format = False
    if msg_word_list[0] == 'cs5700spring2016' and msg_word_list[2] == 'BYE\n':
        valid_bye_msg_format = True
    else:
    	print "Error: Invalid Bye Message Format"
        sys.exit()
    return valid_bye_msg_format
"""
------------------------------------------------------------------------------------
; evaluate_status_msg: STRING-LIST -> REAL
; GIVEN: The list of strings from STATUS generated when it is split at the " " character
; RETURNS: The solution of the expression contained in the STATUS message
; PURPOSE: To calculate the solution of the mathematical expression received
"""
def evaluate_status_msg(msg_word_list):
    math_exp = msg_word_list[2] + msg_word_list[3] + msg_word_list[4]
    soln = eval(math_exp)
    return soln
"""
------------------------------------------------------------------------------------
; send_solution_msg: SOCKET-OBJECT REAL -> NULL
; GIVEN: A socket S and a real number
; RETURNS: NULL
; PURPOSE: To send the solution of the mathematical expression to the remote host in
;          the format provided.
"""
def send_solution_msg(s, soln):
    soln_string = 'cs5700spring2016 {}\n'.format(soln)
    s.send(soln_string)
"""
------------------------------------------------------------------------------------
; close_tcp_conn: SOCKET-OBJECT -> NULL
; GIVEN: A socket object, closes the existing TCP or SSL connection
; PURPOSE: Connection termination
"""
def close_tcp_conn(s):
	s.close()
"""
------------------------------------------------------------------------------------
"""
"""

PROGRAM BODY
------------------------------------------------------------------------------------
------------------------------------------------------------------------------------
"""
"""
VARIABLE DEFINITIONS:
ssl_flag : Indicates if the user has used the "-s" parameter or not.
hostname : Assigned from command line parameter
port     : Can be forced from command line paramater or default
nuid     : Assigned from the command line parameter
sock     : socket object to connect over TCP (both secured and unsecured)
"""
if __name__ == "__main__":
    ssl_flag = 0
    if len(sys.argv) == 6 and sys.argv[1] == '-p' and 0 <= int(sys.argv[2]) <= 65536 and sys.argv[3] == '-s':
        port = int(sys.argv[2])
        hostname = sys.argv[4]
        nuid = sys.argv[5]
        ssl_flag = 1
    elif len(sys.argv) == 5 and sys.argv[1] == '-p' and 0 <= int(sys.argv[2]) <= 65536:
        port = int(sys.argv[2])
        hostname = sys.argv[3]
        nuid = sys.argv[4]
    elif len(sys.argv) == 4 and sys.argv[1] == '-s':
        port = 27994
        hostname = sys.argv[2]
        nuid = sys.argv[3]
        ssl_flag = 1
    elif len(sys.argv) == 3:
        port = 27993
        hostname = sys.argv[1]
        nuid = sys.argv[2]
    else:
        print "Invalid command"
        sys.exit()

if ssl_flag == 0:             
    sock = establish_tcp_conn(hostname, port)
elif ssl_flag ==1:
    sock = establish_ssl_conn(hostname, port)

send_hello_msg(sock, nuid)
process_msg(sock, nuid)
"""
--------------------------------------END-------------------------------------------
"""