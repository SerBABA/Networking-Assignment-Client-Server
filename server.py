import socket
import select
import sys
import datetime
import atexit


class Server:
    """
    The server application is given three ports as parameters in the command line, which it uses to open
    three sockets.
    The server is then on stand by until a DT request comes in, and the server handles the request. Then
    builds the correct DT response packet to be sent back to the client.
    """

    def __init__(self):
        """
        Instantiates the constants needed by the server class. This includes retrieving the port numbers
        requested to be opened.
        """
        self.IP_ADDRESS = "127.0.0.1"
        self.MAGIC_NO = 0x497E
        self.PORT_UPPER_LIMIT = 64000
        self.PORT_LOWER_LIMIT = 1024

        self.ports = self.parse_args()

        self.CLIENT_PACKET_TYPE = 0x0001
        self.DT_RESPONSE_PACKET_TYPE = 0x0002
        self.MAX_RESPONSE_BUFFER_SIZE = 268

        self.DATE_REQUEST_TYPE = 0x0001
        self.TIME_REQUEST_TYPE = 0x0002

        self.CLIENT_REQUEST_TYPES = [
            self.DATE_REQUEST_TYPE, self.TIME_REQUEST_TYPE]
        self.ENGLISH_MONTH_NAMES = ["January", "February", "March", "April", "May",
                                    "June", "July", "August", "September", "October", "November", "December"]

        self.MAORI_MONTH_NAMES = ["Kohitātea", "Hui-tanguru", "Poutū-te-rangi", "Paenga-whāwhā",
                                  "Haratua", "Pipiri", "hōngongoi", "Here-turi-kōkā", "Mahuru", "Whiringa-ā-nuku",
                                  "Whiringa-ā-rangi", "Hakihea"]

        self.GERMAN_MONTH_NAMES = ["Januar", "Februar", "März", "April", "Mai", "Juni", "Juli",
                                   "August", "September", "Oktober", "November", "Dezember"]

    def parse_args(self):
        """
        Parses the arguments given in the command line, and extracts the port numbers
        given.

        Returns the ports in a dictionary format; Otherwise None.
        """

        args = sys.argv
        # Removing the script location as the first parameter. Only keeping the arguments.
        args.pop(0)
        english_port_index = 0
        maori_port_index = 1
        german_port_index = 2
        expected_amount_of_arguments = 3

        if type(args) != list:
            self.exit_error(
                "Expected 3 Arguments -> [english_port] [maori_port] [german_port]")
            return None

        if len(args) < expected_amount_of_arguments:
            self.exit_error(
                "Expected 3 Arguments -> [english_port] [maori_port] [german_port]")
            return None

        if args[english_port_index].isnumeric() == False:
            self.exit_error("Argument 1 must be numeric.")
            return None

        if args[maori_port_index].isnumeric() == False:
            self.exit_error("Argument 2 must be numeric.")
            return None

        if args[german_port_index].isnumeric() == False:
            self.exit_error("Argument 3 must be numeric.")
            return None

        english_port = int(args[english_port_index])
        maori_port = int(args[maori_port_index])
        german_port = int(args[german_port_index])

        if english_port < self.PORT_LOWER_LIMIT or english_port > self.PORT_UPPER_LIMIT:
            self.exit_error("Argument 1 must be between 1,024 and 64,000.")
            return None

        if maori_port < self.PORT_LOWER_LIMIT or maori_port > self.PORT_UPPER_LIMIT:
            self.exit_error("Argument 2 must be between 1,024 and 64,000.")
            return None

        if german_port < self.PORT_LOWER_LIMIT or german_port > self.PORT_UPPER_LIMIT:
            self.exit_error("Argument 3 must be between 1,024 and 64,000.")
            return None

        if(english_port == maori_port or english_port == german_port or maori_port == german_port):
            self.exit_error("Ports must be unique.")
            return None

        return {
            "English": english_port,
            "Maori": maori_port,
            "German": german_port
        }

    def exit_error(self, message=""):
        """
        Prints out an error message to the terminal. And then exits the program with error code -1.

        message - The error message you wanted printed to the terminal.

        Returns None.
        """
        print("ERROR:", message)
        exit(-1)
        return None

    def display_error(self, message=""):
        """
        Prints out an error message to the terminal.

        message - The error message you wanted printed to the terminal.

        Returns None.
        """
        print("ERROR:", message)
        return None

    def build_sockets(self):
        """
        Generates a socket for each of the ports given in self.ports.values().

        Returns the socket array of all the created sockets; Otherwise None.
        """

        if hasattr(self, "ports") == False:
            self.exit_error("ports attribute is not set.")
            return None

        self.socks = []
        for port in self.ports.values():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 17)
                sock.bind((self.IP_ADDRESS, port))
                self.socks.append(sock)

            except OSError:
                self.teardown()
                self.exit_error(
                    "An error ocuured attempting to construct sockets.")
                return None

    def get_packet(self, sock):
        """
        Verifies the integrity of the packet, and returns the packet and the client address. Otherwise 
        returns None for the packet and the address, and displays an error message.

        sock - The socket that has data in its buffer, and requires further processing.

        Returns request_type_received and the client_address; Otherwise None, None 
        """

        try:
            data, client_address = sock.recvfrom(6)
            if(len(data) < 6):
                self.display_error(
                    "Packet receieved from {} is smaller then the acceptable length.".format(client_address))
                return None, None

            magic_no_received = int(f"{data[0]:08b}{data[1]:08b}", 2)
            packet_type_received = int(f"{data[2]:08b}{data[3]:08b}", 2)
            request_type_received = int(f"{data[4]:08b}{data[5]:08b}", 2)

            if magic_no_received != self.MAGIC_NO:
                self.display_error(
                    "Magic number recieved from {} is not equal to the expected value.".format(client_address))
                return None, None

            if packet_type_received != self.CLIENT_PACKET_TYPE:
                self.display_error(
                    "Packet type received from {} is not of the expected value.".format(client_address))
                return None, None

            if (request_type_received in self.CLIENT_REQUEST_TYPES) == False:
                self.display_error(
                    "Request type received from {} is not of the expected value.".format(client_address))
                return None, None

            return request_type_received, client_address

        except ConnectionResetError:
            self.display_error(
                "An error occured attempting to retrieve the packet, due to a connection reset error.")
            return None, None
        except OSError:
            self.display_error(
                "Packet receieved from is larger then the acceptable length.")
            return None, None

    def get_packet_text(self, request_type, sock_address, time_data):
        """
        Given the request type and time data. This function constructs the request text DT response field.
        The client requested. But if something goes wrong and error message is shown.

        request_type - The type of request (date or time).
        sock_address - The socket address the data cam in on.
        time_data - The time data used to fill in the voids for the dates and times requested.

        Returns the packet text field filled in with the data; Otherwise None.
        """

        sock_address_port_index = 1

        if (sock_address[sock_address_port_index] in self.ports.values()) == False:
            self.display_error(
                "Unkown port address on given sock address {}.".format(sock_address))
            return None

        if request_type == self.DATE_REQUEST_TYPE:

            if sock_address[sock_address_port_index] == self.ports["English"]:
                return "Today’s date is {} {}, {} ".format(self.ENGLISH_MONTH_NAMES[time_data.month-1], time_data.day, time_data.year)
            elif sock_address[sock_address_port_index] == self.ports["Maori"]:
                return "Ko te ra o tenei ra ko {} {}, {}".format(self.MAORI_MONTH_NAMES[time_data.month-1], time_data.day, time_data.year)
            else:
                return "Heute ist der {}. {} {}".format(time_data.day, self.GERMAN_MONTH_NAMES[time_data.month-1], time_data.year)

        if request_type == self.TIME_REQUEST_TYPE:

            if sock_address[sock_address_port_index] == self.ports["English"]:
                return "The current time is {}:{}".format(time_data.hour, time_data.minute)
            elif sock_address[sock_address_port_index] == self.ports["Maori"]:
                return "Ko te wa o tenei wa {}:{}".format(time_data.hour, time_data.minute)
            else:
                return "Die Uhrzeit ist {}:{}".format(time_data.hour, time_data.minute)

        self.display_error("Unknown request type specified for text request.")
        return None

    def get_language_code(self, port):
        """
        Given the port number the data came in on. The function translates it into a language code that is
        associated with that port.

        port - Port number the request came on.

        Returns the language code, which is associated with the port; Otherwise None.
        """
        if port == self.ports["English"]:
            language_code = 0x0001
        elif port == self.ports["Maori"]:
            language_code = 0x0002
        elif port == self.ports["German"]:
            language_code = 0x0003
        else:
            self.display_error(
                "Unknown port {} given, expected one of the three possible options.".format(port))
            return None

        return language_code

    def build_DT_response(self, request_type_received, sock_address):
        """
        Given the request type and the socket the data came on. The function constructs the the DT response packet
        requested by a client. The packet is a byte array to be sent, which contains all the fields and data a DT
        response packet needs to contain.

        request_type_received - The type of request given by the user. This specifies if it is a date or time request.
        sock_address - The socket address the data came in.

        Returns DT_response_packet which is a byte array; Otherwise None.
        """
        max_bytes_for_text = 255
        minimum_header_length = 13
        time_data = datetime.datetime.now()

        packet_text = self.get_packet_text(
            request_type_received, sock_address, time_data)
        if packet_text == None:
            return None

        packet_text_bytes = bytearray(packet_text.encode('utf-8'))

        if len(packet_text_bytes) > max_bytes_for_text:
            self.display_error(
                "The number of bytes needed to represent the text exceeds the maximum amount of 255.")
            return None

        language_code = self.get_language_code(sock_address[1])
        if language_code == None:
            return None

        header_bits = f'{self.MAGIC_NO:016b}{self.DT_RESPONSE_PACKET_TYPE:016b}{language_code:016b}{time_data.year:016b}'
        header_bits += f'{time_data.month:08b}{time_data.day:08b}{time_data.hour:08b}{time_data.minute:08b}'
        header_bits += f'{len(packet_text_bytes):08b}'

        header_byte_array = self.bits_to_byte_array(header_bits)

        if len(header_byte_array) != minimum_header_length:
            self.display_error("Header size is not 13 bytes, as specified.")
            return None

        buffer_length = len(packet_text_bytes)+len(header_byte_array)
        DT_response_packet = bytearray(buffer_length)

        for i in range(len(header_byte_array)):
            DT_response_packet[i] = header_byte_array[i]

        count = 0
        while count < len(packet_text_bytes):
            DT_response_packet[minimum_header_length +
                               count] = packet_text_bytes[count]
            count += 1

        return DT_response_packet

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

    def teardown(self):
        """
        Tears down the server, and closes all the sockets that are not set to null value.

        Returns None.
        """

        if hasattr(self, "socks"):
            for sock in self.socks:
                if sock != None:
                    sock.close()

    def run(self):
        """
        Runs the whole server and perfroms all the necessary setups and calls to other functions
        as necessary.

        Returns None.
        """
        self.build_sockets()
        print("Server has started and listening for UDP DT request packets...")
        print("On ports:", self.ports)
        while True:
            sockets_with_data, _, exceptional_list = select.select(
                self.socks, [], [])
            if(len(exceptional_list) > 0):
                self.display_error("Some sockets have experienced errors.")
                continue

            for sock in sockets_with_data:

                client_request_type, client_address = self.get_packet(sock)
                if client_request_type == None:
                    continue

                DT_response = self.build_DT_response(
                    client_request_type, sock.getsockname())
                if DT_response == None:
                    continue

                sock.sendto(DT_response, client_address)


if __name__ == "__main__":
    serv = Server()
    atexit.register(serv.teardown)
    serv.run()
