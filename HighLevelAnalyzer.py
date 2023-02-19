# High Level Analyzer
from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame, ChoicesSetting, NumberSetting


def check_bit(value, pos):
    return (value >> (pos - 1)) & 0b1


def is_callbyte(byte):
    return byte >= 256


def to_8bit(byte):
    return byte & 0b11111111


def is_normal_inquiry(byte):
    return ((byte >> 5) & 0b11) == 0b10


def is_request_acknowledgement(byte):
    return ((byte >> 5) & 0b11) == 0b00


def get_address(callbyte):
    return callbyte & 0b11111


def is_broadcast_or_answer(byte):
    return ((byte >> 5) & 0b11) == 0b11


def get_packet_size(header):
    # Add one because of the xor byte
    return (header & 0b1111) + 1


def get_locomotive_address(high_byte, low_byte):
    if high_byte == 0x00:
        return low_byte
    return ((high_byte & 0b00111111) << 8) | low_byte


def get_turnout_state(flags):
    if flags == 0b00:
        return "Not yet controlled"
    elif flags == 0b01:
        return "Turned"
    elif flags == 0b10:
        return "Straight"
    elif flags == 0b11:
        return "Invalid"


def on_off(bit):
    if bit:
        return "ON"
    else:
        return "OFF"

def f_status(bit):
    if bit:
        return "M"
    else:
        return "T"

# High level analyzers must subclass the HighLevelAnalyzer class.
class Hla(HighLevelAnalyzer):
    result_types = {
        # Special packets
        'callbyte': {
            'format': 'Callbyte'
        },
        'unknown': {
            'format': 'Unknown'
        },
        'normal_inquiry': {
            'format': 'Normal inquiry to {{data.address}}'
        },
        'request_acknowledgment': {
            'format': 'Request acknowledgment from {{data.address}}'
        },
        'normal_operation_resumed': {
            'format': 'Normal operation resumed'
        },
        'track_power_off': {
            'format': 'Track power off'
        },
        'short_circuit': {
            'format': 'ROCONET: Short circuit'
        },
        'emergency_stop': {
            'format': 'Emergency Stop'
        },
        'service_mode_entry': {
            'format': 'Service Mode Entry'
        },

        # Device to station packets
        'acknowledgment_response': {
            'format': "Acknowledgment Response"
        },
        'accessory_decoder_information_request': {
            'format': "Accessory Decoder request. Addresses={{data.addresses}}"
        },
        'accessory_decoder_operation_request': {
            'format': "Accessory Operation request. Address={{data.address}}, Output={{data.output}}/{{data.output_state}}"
        },
        'locomotive_speed_and_direction_operation': {
            'format': "Locomotive speed and direction operation. Address={{data.address}}, Steps={{data.steps}}, Speed={{data.speed}}, Direction={{data.direction}}"
        },
        'function_operation_instructions': {
            'format': "Locomotive function operation instructions. Address={{data.address}} Functions={{data.functions}}"
        },
        'generic_request': {
            'format': "Request: {{data.type}}"
        },
        'software_version': {
            'format': "Software-Version: {{data.type}} ID: {{data.extra}}"
        },
        'status': {
            'format': "Status: {{data.extra}}"
        },
        'transfer_error': {
            'format': "Transfer error"
        },
        'command_station_busy': {
            'format': "Command Station busy"
        },
        'instruction_not_supported': {
            'format': "Instruction not supported by Command Station"
        },

        # Station to device packets
        'accessory_decoder_information_response': {
            'format': "Accessory Decoder response. Type={{data.type}} Addresses={{data.addresses}} {{data.extra}}"
        },
    }

    show_inquiry_packets = ChoicesSetting(choices=("Yes", "No"))

    address = 0
    in_packet = False
    has_header = False
    started_with_call_byte = False
    start_time = 0
    end_time = 0
    packet_size = 0

    packet_data = []
    client_header_map = {}
    station_header_map = {}

    def __init__(self):
        self.client_header_map = {
            0x20: self.acknowledgment_response,
            0x21: self.generic_request,
            0x42: self.accessory_decoder_information_request,
            0x52: self.accessory_decoder_operation_request,
            0xE3: self.locomotive_function_instructions,
            0xE4: self.locomotive_instructions,
        }
        self.station_header_map = {
            0x42: self.accessory_decoder_information_response,
            0xE3: self.loco_information,
            0xE4: self.loco_fstatus_information,
            0x61: self.command_station_errors,
            0x62: self.station_status,
            0x63: self.station_software_version,
        }
        pass

    # TODO add checks for parity and xor
    def decode(self, frame: AnalyzerFrame):
        if frame.type != 'data':
            return
        if 'error' in frame.data:
            return
        frame_data: bytes = frame.data["data"]
        # 9bit data
        data_9bit = (frame_data[0] << 8) | frame_data[1]
        # If 9th bit is set this is a call byte
        data = to_8bit(data_9bit)
        if is_callbyte(data_9bit):
            self.address = get_address(data)

            # Handle special cases
            special_case = self.handle_special_case(data, frame)
            if special_case:
                if special_case.type == "normal_inquiry" and self.show_inquiry_packets == "No":
                    return
                return special_case

            # Handle broadcast or answer
            if is_broadcast_or_answer(data):
                self.packet_data = []
                self.in_packet = True
                self.has_header = False
                self.started_with_call_byte = True
                self.start_time = frame.start_time
                # This is a start of a new packet so don't return something
                return

            return AnalyzerFrame("callbyte", frame.start_time, frame.end_time)
        else:
            # A header or callbyte has already been received
            if self.in_packet:
                self.packet_data.append(data)
                # Only a callbyte has received but not a header
                if not self.has_header:
                    # Read header and packet size
                    self.has_header = True
                    self.packet_size = get_packet_size(data)
                    return
                self.packet_size -= 1
                if self.packet_size == 0:
                    # Packet is complete
                    self.has_header = False
                    self.in_packet = False
                    self.end_time = frame.end_time
                    general_broadcast = self.handle_general_broadcast()
                    if general_broadcast:
                        return general_broadcast

                    # Check in client header map
                    # Device to Station packets don't have callbytes
                    if (not self.started_with_call_byte) and self.packet_data[0] in self.client_header_map:
                        # Get and invoke the function
                        packet_fun = self.client_header_map[self.packet_data[0]]
                        packet = packet_fun()
                        # Return the packet if there is some
                        if packet:
                            return packet
                    # Check in station header map
                    # Station to device packets have callbytes
                    elif self.started_with_call_byte and self.packet_data[0] in self.station_header_map:
                        # Get and invoke the function
                        packet_fun = self.station_header_map[self.packet_data[0]]
                        packet = packet_fun()
                        # Return the packet if there is some
                        if packet:
                            return packet

                    return AnalyzerFrame("unknown", self.start_time, frame.end_time)
                else:
                    # Packet is not complete, don't return anything
                    return
            # This should be always a header packet
            else:
                # Clear old packet data
                self.packet_data = []
                # Append the current header
                self.packet_data.append(data)
                self.packet_size = get_packet_size(data)
                self.has_header = True
                self.in_packet = True
                self.started_with_call_byte = False
                self.start_time = frame.start_time
                return

    def handle_special_case(self, data, frame: AnalyzerFrame):
        # There are two special cases that need to be handled
        if is_normal_inquiry(data):
            return AnalyzerFrame("normal_inquiry", frame.start_time, frame.end_time, {"address": self.address})
        elif is_request_acknowledgement(data):
            return AnalyzerFrame("request_acknowledgment", frame.start_time, frame.end_time, {"address": self.address})
        return None

    def handle_general_broadcast(self):
        # General broadcast packet have always three bytes after the call byte
        if self.started_with_call_byte:
            # Normal operation resumed packet
            if self.packet_data[0] == 0x61 and self.packet_data[1] == 0x01:
                return AnalyzerFrame("normal_operation_resumed", self.start_time, self.end_time)
            # Track power off packet
            elif self.packet_data[0] == 0x61 and self.packet_data[1] == 0x00:
                return AnalyzerFrame("track_power_off", self.start_time, self.end_time)
            # ROCONET extension short circuit
            elif self.packet_data[0] == 0x61 and self.packet_data[1] == 0x08:
                return AnalyzerFrame("short_circuit", self.start_time, self.end_time)
            # Emergency stop packet
            elif self.packet_data[0] == 0x81 and self.packet_data[1] == 0x00:
                return AnalyzerFrame("emergency_stop", self.start_time, self.end_time)
            # Service mode entry packet
            elif self.packet_data[0] == 0x61 and self.packet_data[1] == 0x02:
                return AnalyzerFrame("service_mode_entry", self.start_time, self.end_time)

    def acknowledgment_response(self):
        return AnalyzerFrame("acknowledgment_response", self.start_time, self.end_time)

    def accessory_decoder_information_request(self):
        group = self.packet_data[1]
        address_start = group * 4
        nibble = self.packet_data[2] & 0b1

        addresses = str(address_start + 2 * nibble)
        addresses += ","
        addresses += str(address_start + 1 + 2 * nibble)

        return AnalyzerFrame("accessory_decoder_information_request", self.start_time, self.end_time,
                             {"addresses": addresses})

    def accessory_decoder_information_response(self):
        group = self.packet_data[1]
        address_start = group * 4
        nibble = (self.packet_data[2] >> 4) & 0b1

        first_state = self.packet_data[2] & 0b11
        second_state = (self.packet_data[2] >> 2) & 0b11

        addresses = str(address_start + 2 * nibble) + " (" + get_turnout_state(first_state) + ")"
        addresses += ","
        addresses += str(address_start + 1 + 2 * nibble) + " (" + get_turnout_state(second_state) + ")"

        type_id = (self.packet_data[2] >> 5) & 0b11
        type_name = "TBD"
        # TODO handle state of feedback modules

        if type_id == 0b00:
            type_name = "w/o feedback"
        elif type_id == 0b01:
            type_name = "w/ feedback"
        elif type_id == 0b10:
            type_name = "feedback module"

        extra = ""
        if self.packet_data[2] >> 7:
            extra = "(Request has been not completed)"

        return AnalyzerFrame("accessory_decoder_information_response", self.start_time, self.end_time,
                             {"type": type_name, "addresses": addresses, "extra": extra})

    def accessory_decoder_operation_request(self):
        address = (self.packet_data[1] * 4) + ((self.packet_data[2] >> 1) & 0b11)

        output_state = "Deactivate"
        # This is different from the documentation (sec. 2.2.18)
        # because after testing and verifying with other documents it showed that these values must be swapped
        if (self.packet_data[2] >> 3) & 0b1:
            output_state = "Activate"

        output = "1"
        if self.packet_data[2] & 0b1:
            output = "2"

        return AnalyzerFrame("accessory_decoder_operation_request", self.start_time, self.end_time,
                             {"address": address, "output": output, "output_state": output_state})

    def locomotive_instructions(self):
        if self.packet_data[1] == 0x10 or self.packet_data[1] == 0x11 or self.packet_data[1] == 0x12 or self.packet_data[1] == 0x13:
            return self.locomotive_speed_and_direction_operation()
        elif self.packet_data[1] == 0x20 or self.packet_data[1] == 0x21 or self.packet_data[1] == 0x22 or self.packet_data[1] == 0x23:
            return self.locomotive_function_instructions_operation()
        elif self.packet_data[1] == 0x24:
            address = get_locomotive_address(self.packet_data[2], self.packet_data[3])

            functions = ""
            functions += "F0:" + f_status(self.packet_data[4] >> 4) + ", "
            functions += "F1:" + f_status((self.packet_data[4] >> 0) & 0b1) + ", "
            functions += "F2:" + f_status((self.packet_data[4] >> 1) & 0b1) + ", "
            functions += "F3:" + f_status((self.packet_data[4] >> 2) & 0b1) + ", "
            functions += "F4:" + f_status((self.packet_data[4] >> 3) & 0b1)

            return AnalyzerFrame("Set Function F0-F4 Status", self.start_time, self.end_time,
                             {"address": address, "functions": functions})
        elif self.packet_data[1] == 0x25:
            address = get_locomotive_address(self.packet_data[2], self.packet_data[3])

            functions = ""
            functions += "F5:" + f_status(self.packet_data[4] >> 0) + ", "
            functions += "F6:" + f_status((self.packet_data[4] >> 1) & 0b1) + ", "
            functions += "F7:" + f_status((self.packet_data[4] >> 2) & 0b1) + ", "
            functions += "F8:" + f_status((self.packet_data[4] >> 3) & 0b1)
            
            return AnalyzerFrame("Set Function F5-F8 Status", self.start_time, self.end_time,
                             {"address": address, "functions": functions})
        elif self.packet_data[1] == 0x26:
            address = get_locomotive_address(self.packet_data[2], self.packet_data[3])

            functions = ""
            functions += "F9:" + f_status(self.packet_data[4] >> 0) + ", "
            functions += "F10:" + f_status((self.packet_data[4] >> 1) & 0b1) + ", "
            functions += "F11:" + f_status((self.packet_data[4] >> 2) & 0b1) + ", "
            functions += "F12:" + f_status((self.packet_data[4] >> 3) & 0b1)
            
            return AnalyzerFrame("Set Function F9-F12 Status", self.start_time, self.end_time,
                             {"address": address, "functions": functions})
        elif self.packet_data[1] == 0x27:
            address = get_locomotive_address(self.packet_data[2], self.packet_data[3])

            functions = ""
            functions += "F13:" + f_status(self.packet_data[4] >> 0) + ", "
            functions += "F14:" + f_status((self.packet_data[4] >> 1) & 0b1) + ", "
            functions += "F15:" + f_status((self.packet_data[4] >> 2) & 0b1) + ", "
            functions += "F16:" + f_status((self.packet_data[4] >> 3) & 0b1) + ", "
            functions += "F17:" + f_status((self.packet_data[4] >> 4) & 0b1) + ", "
            functions += "F18:" + f_status((self.packet_data[4] >> 5) & 0b1) + ", "
            functions += "F19:" + f_status((self.packet_data[4] >> 6) & 0b1) + ", "
            functions += "F20:" + f_status((self.packet_data[4] >> 7) & 0b1)
            
            return AnalyzerFrame("Set Function F13-F20 Status", self.start_time, self.end_time,
                             {"address": address, "functions": functions})
        elif self.packet_data[1] == 0x2C:
            address = get_locomotive_address(self.packet_data[2], self.packet_data[3])

            functions = ""
            functions += "F21:" + f_status(self.packet_data[4] >> 0) + ", "
            functions += "F22:" + f_status((self.packet_data[4] >> 1) & 0b1) + ", "
            functions += "F23:" + f_status((self.packet_data[4] >> 2) & 0b1) + ", "
            functions += "F24:" + f_status((self.packet_data[4] >> 3) & 0b1) + ", "
            functions += "F25:" + f_status((self.packet_data[4] >> 4) & 0b1) + ", "
            functions += "F26:" + f_status((self.packet_data[4] >> 5) & 0b1) + ", "
            functions += "F27:" + f_status((self.packet_data[4] >> 6) & 0b1) + ", "
            functions += "F28:" + f_status((self.packet_data[4] >> 7) & 0b1)
            
            return AnalyzerFrame("Set Function F21-F28 Status", self.start_time, self.end_time,
                             {"address": address, "functions": functions})


    def locomotive_speed_and_direction_operation(self):
        address = get_locomotive_address(self.packet_data[2], self.packet_data[3])
        steps = 0

        if self.packet_data[1] == 0x10:
            steps = 14
        elif self.packet_data[1] == 0x11:
            steps = 27
        elif self.packet_data[1] == 0x12:
            steps = 28
        elif self.packet_data[1] == 0x13:
            steps = 128

        direction = "Reverse"
        if (self.packet_data[4] >> 7) & 0b1:
            direction = "Forward"

        speed = self.packet_data[4] & 0b1111111

        if speed == 1:
            speed = "Emergency stop"
        elif speed >= 1:
            speed = speed - 1

        # TODO check if speed calculation is correct with other speed steps

        return AnalyzerFrame("locomotive_speed_and_direction_operation", self.start_time, self.end_time,
                             {"address": address, "steps": steps, "direction": direction, "speed": speed})

    def locomotive_function_instructions_operation(self):
        address = get_locomotive_address(self.packet_data[2], self.packet_data[3])

        functions = ""

        if self.packet_data[1] == 0x20:
            functions += "F0:" + on_off(self.packet_data[4] >> 4) + ", "
            functions += "F1:" + on_off((self.packet_data[4] >> 0) & 0b1) + ", "
            functions += "F2:" + on_off((self.packet_data[4] >> 1) & 0b1) + ", "
            functions += "F3:" + on_off((self.packet_data[4] >> 2) & 0b1) + ", "
            functions += "F4:" + on_off((self.packet_data[4] >> 3) & 0b1)
        elif self.packet_data[1] == 0x21:
            functions += "F5:" + on_off((self.packet_data[4] >> 0) & 0b1) + ", "
            functions += "F6:" + on_off((self.packet_data[4] >> 1) & 0b1) + ", "
            functions += "F7." + on_off((self.packet_data[4] >> 2) & 0b1) + ", "
            functions += "F8:" + on_off((self.packet_data[4] >> 3) & 0b1)
        elif self.packet_data[1] == 0x22:
            functions += "F9:" + on_off((self.packet_data[4] >> 0) & 0b1) + ", "
            functions += "F10:" + on_off((self.packet_data[4] >> 1) & 0b1) + ", "
            functions += "F11:" + on_off((self.packet_data[4] >> 2) & 0b1) + ", "
            functions += "F12:" + on_off((self.packet_data[4] >> 3) & 0b1)
        elif self.packet_data[1] == 0x23:
            functions += "F13:" + on_off((self.packet_data[4] >> 0) & 0b1) + ", "
            functions += "F14:" + on_off((self.packet_data[4] >> 1) & 0b1) + ", "
            functions += "F15:" + on_off((self.packet_data[4] >> 2) & 0b1) + ", "
            functions += "F16:" + on_off((self.packet_data[4] >> 3) & 0b1) + ", "
            functions += "F17:" + on_off((self.packet_data[4] >> 4) & 0b1) + ", "
            functions += "F18:" + on_off((self.packet_data[4] >> 5) & 0b1) + ", "
            functions += "F19:" + on_off((self.packet_data[4] >> 6) & 0b1) + ", "
            functions += "F20:" + on_off((self.packet_data[4] >> 7) & 0b1)
        elif self.packet_data[1] == 0x24:
            functions += "F21:" + f_status((self.packet_data[4] >> 0) & 0b1) + ", "
            functions += "F22:" + f_status((self.packet_data[4] >> 1) & 0b1) + ", "
            functions += "F23:" + f_status((self.packet_data[4] >> 2) & 0b1) + ", "
            functions += "F24:" + f_status((self.packet_data[4] >> 3) & 0b1) + ", "
            functions += "F25:" + f_status((self.packet_data[4] >> 4) & 0b1) + ", "
            functions += "F26:" + f_status((self.packet_data[4] >> 5) & 0b1) + ", "
            functions += "F27:" + f_status((self.packet_data[4] >> 6) & 0b1) + ", "
            functions += "F28:" + f_status((self.packet_data[4] >> 7) & 0b1)

        return AnalyzerFrame("function_operation_instructions", self.start_time, self.end_time,
                             {"address": address, "functions": functions})

    def generic_request(self):
        # Resume operation request
        if self.packet_data[1] == 0x81:
            return AnalyzerFrame("generic_request", self.start_time, self.end_time, {"type": "Resume Operations"})
        elif self.packet_data[1] == 0x80:
            return AnalyzerFrame("generic_request", self.start_time, self.end_time, {"type": "Stop Operations (Emergency off)"})
        elif self.packet_data[1] == 0x10:
            return AnalyzerFrame("generic_request", self.start_time, self.end_time, {"type": "Service Mode Results"})
        elif self.packet_data[1] == 0x21:
            return AnalyzerFrame("generic_request", self.start_time, self.end_time, {"type": "Command station software-version"})
        elif self.packet_data[1] == 0x24:
            return AnalyzerFrame("generic_request", self.start_time, self.end_time, {"type": "Command station status"})

    def station_software_version(self):
        if self.packet_data[1] == 0x21:
            major = self.packet_data[2] >> 4
            minor = self.packet_data[2] & 0b1111
            return AnalyzerFrame("software_version", self.start_time, self.end_time,
                                 {"type": str(major) + "." + str(minor), "extra": str(self.packet_data[3])})

    def loco_information(self):
        if self.packet_data[1] == 0x40:
            address = get_locomotive_address(self.packet_data[2], self.packet_data[3])

            return AnalyzerFrame("Loco operated by another device", self.start_time, self.end_time, {"Address": address})
        elif self.packet_data[1] == 0x50:

            functions = ""
            functions += "F0:" +  f_status(self.packet_data[2] >> 4) + ", "
            functions += "F1:" +  f_status((self.packet_data[2] >> 0) & 0b1) + ", "
            functions += "F2:" +  f_status((self.packet_data[2] >> 1) & 0b1) + ", "
            functions += "F3:" +  f_status((self.packet_data[2] >> 2) & 0b1) + ", "
            functions += "F4:" +  f_status((self.packet_data[2] >> 3) & 0b1) + ", "

            functions += "F5:" +  f_status((self.packet_data[3] >> 0) & 0b1) + ", "
            functions += "F6:" +  f_status((self.packet_data[3] >> 1) & 0b1) + ", "
            functions += "F7:" +  f_status((self.packet_data[3] >> 2) & 0b1) + ", "
            functions += "F8:" +  f_status((self.packet_data[3] >> 3) & 0b1) + ", "
            functions += "F9:" +  f_status((self.packet_data[3] >> 4) & 0b1) + ", "
            functions += "F10:" + f_status((self.packet_data[3] >> 5) & 0b1) + ", "
            functions += "F11:" + f_status((self.packet_data[3] >> 6) & 0b1) + ", "
            functions += "F12:" + f_status((self.packet_data[3] >> 7) & 0b1)

            return AnalyzerFrame("Function F0-F12 Status Response", self.start_time, self.end_time,
                                 {"Functions": functions})
        elif self.packet_data[1] == 0x52:

            functions = ""
            functions += "F13:" + on_off((self.packet_data[2] >> 0) & 0b1) + ", "
            functions += "F14:" + on_off((self.packet_data[2] >> 1) & 0b1) + ", "
            functions += "F15:" + on_off((self.packet_data[2] >> 2) & 0b1) + ", "
            functions += "F16:" + on_off((self.packet_data[2] >> 3) & 0b1) + ", "
            functions += "F17:" + on_off((self.packet_data[2] >> 4) & 0b1) + ", "
            functions += "F18:" + on_off((self.packet_data[2] >> 5) & 0b1) + ", "
            functions += "F19:" + on_off((self.packet_data[2] >> 6) & 0b1) + ", "
            functions += "F20:" + on_off((self.packet_data[2] >> 7) & 0b1) + ", "

            functions += "F21:" + on_off((self.packet_data[3] >> 0) & 0b1) + ", "
            functions += "F22:" + on_off((self.packet_data[3] >> 1) & 0b1) + ", "
            functions += "F23:" + on_off((self.packet_data[3] >> 2) & 0b1) + ", "
            functions += "F24:" + on_off((self.packet_data[3] >> 3) & 0b1) + ", "
            functions += "F25:" + on_off((self.packet_data[3] >> 4) & 0b1) + ", "
            functions += "F26:" + on_off((self.packet_data[3] >> 5) & 0b1) + ", "
            functions += "F27:" + on_off((self.packet_data[3] >> 6) & 0b1) + ", "
            functions += "F28:" + on_off((self.packet_data[3] >> 7) & 0b1)

            return AnalyzerFrame("Function F13-F28 Info Response", self.start_time, self.end_time,
                                 {"Functions": functions})

    def loco_fstatus_information(self):
        if self.packet_data[1] == 0x51:

            functions = ""
            functions += "F13:" +  f_status((self.packet_data[2] >> 0) & 0b1) + ", "
            functions += "F14:" +  f_status((self.packet_data[2] >> 1) & 0b1) + ", "
            functions += "F15:" +  f_status((self.packet_data[2] >> 2) & 0b1) + ", "
            functions += "F16:" +  f_status((self.packet_data[2] >> 3) & 0b1) + ", "
            functions += "F17:" +  f_status((self.packet_data[2] >> 4) & 0b1) + ", "
            functions += "F18:" +  f_status((self.packet_data[2] >> 5) & 0b1) + ", "
            functions += "F19:" +  f_status((self.packet_data[2] >> 6) & 0b1) + ", "
            functions += "F20:" +  f_status((self.packet_data[2] >> 7) & 0b1) + ", "

            functions += "F21:" +  f_status((self.packet_data[3] >> 0) & 0b1) + ", "
            functions += "F22:" +  f_status((self.packet_data[3] >> 1) & 0b1) + ", "
            functions += "F23:" +  f_status((self.packet_data[3] >> 2) & 0b1) + ", "
            functions += "F24:" +  f_status((self.packet_data[3] >> 3) & 0b1) + ", "
            functions += "F25:" +  f_status((self.packet_data[3] >> 4) & 0b1) + ", "
            functions += "F26:" + f_status((self.packet_data[3] >> 5) & 0b1) + ", "
            functions += "F27:" + f_status((self.packet_data[3] >> 6) & 0b1) + ", "
            functions += "F28:" + f_status((self.packet_data[3] >> 7) & 0b1)

            return AnalyzerFrame("Function F13-F28 Status Response", self.start_time, self.end_time,
                                 {"Functions": functions, "Refresh-Modus": str(self.packet_data[4])})
        else:
            steps = 0

            if self.packet_data[1] & 0b111 == 0x00:
                steps = 14
            elif self.packet_data[1] & 0b111 == 0x01:
                steps = 27
            elif self.packet_data[1] & 0b111 == 0x02:
                steps = 28
            elif self.packet_data[1] & 0b111 == 0x04:
                steps = 128

            direction = "Reverse"
            if (self.packet_data[2] >> 7) & 0b1:
                direction = "Forward"

            speed = self.packet_data[2] & 0b1111111

            if speed == 1:
                speed = "Emergency stop"
            elif speed >= 1:
                speed = speed - 1

            # TODO check if speed calculation is correct with other speed steps

            functions = ""
            functions += "F0:" + on_off(self.packet_data[3] >> 4) + ", "
            functions += "F1:" + on_off((self.packet_data[3] >> 0) & 0b1) + ", "
            functions += "F2:" + on_off((self.packet_data[3] >> 1) & 0b1) + ", "
            functions += "F3:" + on_off((self.packet_data[3] >> 2) & 0b1) + ", "
            functions += "F4:" + on_off((self.packet_data[3] >> 3) & 0b1) + ", "

            functions += "F5:" + on_off((self.packet_data[4] >> 0) & 0b1) + ", "
            functions += "F6:" + on_off((self.packet_data[4] >> 1) & 0b1) + ", "
            functions += "F7:" + on_off((self.packet_data[4] >> 2) & 0b1) + ", "
            functions += "F8:" + on_off((self.packet_data[4] >> 3) & 0b1) + ", "
            functions += "F9:" + on_off((self.packet_data[4] >> 4) & 0b1) + ", "
            functions += "F10:" + on_off((self.packet_data[4] >> 5) & 0b1) + ", "
            functions += "F11:" + on_off((self.packet_data[4] >> 6) & 0b1) + ", "
            functions += "F12:" + on_off((self.packet_data[4] >> 7) & 0b1)

            return AnalyzerFrame("locomotive Information Response", self.start_time, self.end_time,
                                {"steps": steps, "direction": direction, "speed": speed, "functions": functions})

    def locomotive_function_instructions(self):
        if self.packet_data[1] == 0x00:
            address = get_locomotive_address(self.packet_data[2], self.packet_data[3])
            return AnalyzerFrame("Request Locomotive Information", self.start_time, self.end_time,
                                 {"Adress": address})
        elif self.packet_data[1] == 0x07:
            address = get_locomotive_address(self.packet_data[2], self.packet_data[3])
            return AnalyzerFrame("Request Function F0-F12 Status", self.start_time, self.end_time,
                                 {"Adress": address})
        elif self.packet_data[1] == 0x08:
            address = get_locomotive_address(self.packet_data[2], self.packet_data[3])
            return AnalyzerFrame("Request Function F13-F28 Status", self.start_time, self.end_time,
                                 {"Adress": address})
        elif self.packet_data[1] == 0x09:
            address = get_locomotive_address(self.packet_data[2], self.packet_data[3])
            return AnalyzerFrame("Request Function F13-F28 Information", self.start_time, self.end_time,
                                 {"Adress": address})

    def command_station_errors(self):
        if self.packet_data[1] == 0x80:
            return AnalyzerFrame("transfer_error", self.start_time, self.end_time)
        if self.packet_data[1] == 0x81:
            return AnalyzerFrame("command_station_busy", self.start_time, self.end_time)
        if self.packet_data[1] == 0x82:
            return AnalyzerFrame("instruction_not_supported", self.start_time, self.end_time)

    def station_status(self):
        if self.packet_data[1] == 0x22:
            base = "Info: "
            if check_bit(self.packet_data[2], 8):
                base += "RAM Check error;"
            if check_bit(self.packet_data[2], 7):
                base += "Power up;"
            if check_bit(self.packet_data[2], 4):
                base += "Service Mode;"
            if check_bit(self.packet_data[2], 3):
                base += "Automatic Mode;"
            else:
                base += "Manual Mode;"
            if check_bit(self.packet_data[2], 2):
                base += "Emergency Stop;"
            if check_bit(self.packet_data[2], 1):
                base += "Emergency Off;"

            return AnalyzerFrame("status", self.start_time, self.end_time,
                                 {"extra": base})
