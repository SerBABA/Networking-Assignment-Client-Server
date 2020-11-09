import socket
import select
import sys


class Client:
    """
    This is a Client object, which is used to send a DT request packet to the server application.
    The client object then waits for a DT response packet (capped at one second), which is then
    processed and prints all the field in the DT response packet.
    """

    def __init__(self):
        """
        Instantiates all constants needed by the client object. Includes the socket.
        """
        self.IP_ADDRESS = "127.0.0.1"
        self.PORT = 5555
        self.MAGIC_NUMBER = 0x497E
        self.PACKET_TYPE = 0x0001
        self.REQUEST_TYPES = [0x0001, 0x0002]
        self.DATE_REQUEST_TYPE = 0x0001
        self.TIME_REQUEST_TYPE = 0x0002
        self.PORT_UPPER_LIMIT = 64000
        self.PORT_LOWER_LIMIT = 1024

        self.SERVER_PACKET_TYPE = 0x0002
        self.SERVER_LANGUAGE_CODES = [0x0001, 0x0002, 0x0003]
        self.YEAR_UPPER_LIMIT = 2100

        self.sock = None
        self.server_address, self.request_type = self.parse_input()
        self.sock = self.build_socket()

    def display_error(self, message=""):
        """
        Prints out an error message, closes the socket and then exits.

        message - Message to be printed.

        Returns None, as the process is terminated.
        """
        print("ERROR:", message)
        if hasattr(self, "sock"):
            if type(self.sock) == socket.socket:
                self.sock.close()
        exit(-1)

    def build_DT_request(self, request_type=0x0001):
        """
        Given the request type we construct a DT request to be sent to the server application.

        request_type - The type of data you want to get back from the server.

        Returns the DT request packet; Otherwise None.
        """

        max_request_type_length = 16

        if ((request_type in self.REQUEST_TYPES) == False) or (request_type.bit_length() > max_request_type_length):
            self.display_error("Request type is invalid.")
            return None

        raw_bits_packet = f'{self.MAGIC_NUMBER:016b}{self.PACKET_TYPE:016b}{request_type:016b}'
        DT_packet = self.bits_to_byte_array(raw_bits_packet)

        return DT_packet

    def bits_to_byte_array(self, bits=""):
        """
        Given a list of bits. The function packs the bits into bytes, and into a 
        byte array (all in big-endian format).    

        bits - Raw bits in string format.

        Returns a byte array of the bits.
        """
        byte = ""
        base = 2
        bits_per_byte = 8
        byte_count = 0

        number_of_bytes = len(bits) // bits_per_byte
        if len(bits) % bits_per_byte > 0:
            number_of_bytes += 1

        byte_array = bytearray([0] * (number_of_bytes))

        for i in range(len(bits)):
            byte += bits[i]
            if len(byte) >= bits_per_byte:
                byte_array[byte_count] = int(byte, base)
                byte = ""
                byte_count += 1

        if len(byte) > 0:
            final_byte = f'{int(byte, base):08b}'
            byte_array[byte_count+1] = int(final_byte, base)

        return byte_array

    def build_socket(self):
        """
        Builds the socket used to send and receive data from.

        Returns the client socket, which is used for communication with the server; Otherwise None.
        """
        try:
            sock = socket.socket(
                socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.bind((self.IP_ADDRESS, self.PORT))
            sock.settimeout(1)
        except OSError:
            self.display_error(
                "An error occured attempting to build the socket.")
            return None
        return sock

    def parse_input(self):
        """
        Parses the command line arguments given by the user, and makes sure that
        we are given the correct values and types.

        Returns address tuple (ip_address, port) and request type wanted by the user; Otherwise None.
        """
        args = sys.argv
        args.pop(0)

        expected_amount_of_arguments = 3
        request_type_index = 0
        address_index = 1
        port_index = 2

        if type(args) != list:
            self.exit_error(
                "Expected 3 Arguments -> [english_port] [maori_port] [german_port]")
            return None

        if len(args) < expected_amount_of_arguments:
            self.display_error(
                "Expected 3 arguments -> [date/time] [address] [port].")
            return None

        if((args[request_type_index] in ["date", "time"]) == False):
            self.display_error("First argument must be data or time.")
            return None

        if (args[port_index].isnumeric() == False):
            self.display_error("Expected port to be an integer.")
            return None

        serv_port = int(args[port_index])

        if(serv_port < self.PORT_LOWER_LIMIT or serv_port > self.PORT_UPPER_LIMIT):
            self.display_error("Port number must be between 1,024 and 64,000")
            return None

        try:
            socket_data = socket.getaddrinfo(args[address_index], serv_port, proto=socket.IPPROTO_UDP,
                                             family=socket.AF_INET, type=socket.SOCK_DGRAM)
        except socket.gaierror:
            self.display_error("Host given is unknown to this machine.")
            return None

        if args[request_type_index] == "date":
            request_type = self.DATE_REQUEST_TYPE
        elif args[request_type_index] == "time":
            request_type = self.TIME_REQUEST_TYPE
        else:
            self.display_error("First argument must be data or time.")
            return None

        # 0th item is the first item in the list of options
        serv_addr = socket_data[0][4]
        # 4th item is the server address translated.

        return serv_addr, request_type

    def receive_DT_response(self):
        """
        Waits for the DT response to arrive in the socket (if it doesn't arrive within one second we get an error).
        Once it receives the DT response packet, parses it and ensures all the data is correctly given as expected.
        and returns the packet as a dictionary object. Otherwise if any of the steps fails. The function will simply
        display an error and return None. 

        Returns the response object with all the DT response fields; Otherwise None.
        """
        maximum_expected_bytes = 268  # Maximum length a response can be is 13 (header) + 255 (text) -> max of 268 bytes
        minimum_header_size = 13

        try:
            data, addr = self.sock.recvfrom(maximum_expected_bytes)

        except ConnectionResetError:
            self.display_error(
                "An error occured attempting to retrieve the packet, due to a connection reset error.")
            return None
        except socket.timeout:
            self.display_error(
                "Response did not arrive within time constraint of one second.")
            return None
        except OSError:
            self.display_error(
                "An error occured attempting to retrieve packet, due to an OSError.")
            return None

        if len(data) < minimum_header_size:
            self.display_error(
                "Packet received doesn't meet minimum number of bytes requirement.")
            return None

        # Header data retrieval
        received_magic_no = int(f'{data[0]:08b}{data[1]:08b}', 2)
        received_packet_type = int(f'{data[2]:08b}{data[3]:08b}', 2)
        received_language_code = int(f'{data[4]:08b}{data[5]:08b}', 2)
        received_year = int(f'{data[6]:08b}{data[7]:08b}', 2)
        received_month = int(f'{data[8]:08b}', 2)
        received_day = int(f'{data[9]:08b}', 2)
        received_hour = int(f'{data[10]:08b}', 2)
        received_minute = int(f'{data[11]:08b}', 2)
        received_length = int(f'{data[12]:08b}', 2)

        if received_magic_no != self.MAGIC_NUMBER:
            self.display_error(
                "Response packet's magic number doesn't match up with the expected one.")
            return None
        if received_packet_type != self.SERVER_PACKET_TYPE:
            self.display_error(
                "Response packet's type doesn't match expected packet type.")
            return None
        if (received_language_code in self.SERVER_LANGUAGE_CODES) == False:
            self.display_error(
                "Response packet's language code doesn't meet any of the expected values.")
            return None
        if received_year >= self.YEAR_UPPER_LIMIT:
            self.display_error(
                "Response packet's year is above the year limit specified.")
            return None
        if received_month < 1 or received_month > 12:
            self.display_error(
                "Response packet's month is out of the expected bounds 1 and 12.")
            return None
        if received_day < 1 or received_day > 31:
            self.display_error(
                "Response packet's day is out of the expected bounds 1 and 32.")
            return None
        if received_hour < 0 or received_hour > 23:
            self.display_error(
                "Response packet's hour is out of the expected bounds 0 and 23.")
            return None
        if received_minute < 0 or received_minute > 59:
            self.display_error(
                "Response packet's minute is out of the expected bounds 0 and 59.")
            return None
        if(len(data) != received_length + minimum_header_size):
            self.display_error(
                "Response packet's length parameter doesn't add up as expected with the specified length.")
            return None

        response_text = str(data[13:], 'utf-8', 'ignore')

        response_object = {
            "magicNo": received_magic_no,
            "packetType": received_packet_type,
            "languageCode": received_language_code,
            "year": received_year,
            "month": received_month,
            "day": received_day,
            "hour": received_hour,
            "minute": received_minute,
            "length": received_length,
            "text": response_text
        }

        return response_object

    def run(self):
        """
        This is called to initiate the DT transaction between the client
        (this) and a specified server.

        Returns None.
        """
        DT_request_packet = self.build_DT_request(self.request_type)
        self.sock.sendto(DT_request_packet, self.server_address)
        response_object = self.receive_DT_response()
        if response_object != None:
            print(response_object)
        self.sock.close()


if __name__ == "__main__":
    client = Client()
    client.run()
