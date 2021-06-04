# High Level Analyzer
from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame


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


# High level analyzers must subclass the HighLevelAnalyzer class.
class Hla(HighLevelAnalyzer):
    result_types = {
        'callbyte': {
            'format': 'Callbyte'
        },
        'non_callbyte': {
            'format': 'Non Callbyte'
        },
        'special': {
            'format': 'Special'
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
        'emergency_stop': {
            'format': 'Emergency Stop'
        },
        'service_mode_entry': {
            'format': 'Service Mode Entry'
        },
    }

    address = 0
    in_packet = False
    has_header = False
    start_time = 0
    packet_size = 0

    packet_data = []

    def __init__(self):
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
                return special_case

            # Handle broadcast or answer
            if is_broadcast_or_answer(data):
                self.packet_data = []
                self.in_packet = True
                self.has_header = False
                self.start_time = frame.start_time

            # TODO handle feedback
            return AnalyzerFrame("callbyte", frame.start_time, frame.end_time)
        else:
            if self.in_packet:
                self.packet_data.append(data)
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
                    general_broadcast = self.handle_general_broadcast(frame)
                    if general_broadcast:
                        return general_broadcast
                    return AnalyzerFrame("special", self.start_time, frame.end_time)

            # Read the header

            # TODO handle device to command station
            return AnalyzerFrame("non_callbyte", frame.start_time, frame.end_time)

    def handle_special_case(self, data, frame: AnalyzerFrame):
        # There are two special cases that need to be handled
        if is_normal_inquiry(data):
            return AnalyzerFrame("normal_inquiry", frame.start_time, frame.end_time, {"address": self.address})
        elif is_request_acknowledgement(data):
            return AnalyzerFrame("request_acknowledgment", frame.start_time, frame.end_time, {"address": self.address})
        return None

    def handle_general_broadcast(self, frame):
        # Normal operation resumed packet
        if self.packet_data[0] == 0x61 and self.packet_data[1] == 0x01:
            return AnalyzerFrame("normal_operation_resumed", self.start_time, frame.end_time)
        # Track power off packet
        elif self.packet_data[0] == 0x61 and self.packet_data[1] == 0x00:
            return AnalyzerFrame("track_power_off", self.start_time, frame.end_time)
        # Emergency stop packet
        elif self.packet_data[0] == 0x81 and self.packet_data[1] == 0x00:
            return AnalyzerFrame("emergency_stop", self.start_time, frame.end_time)
        # Service mode entry packet
        elif self.packet_data[0] == 0x61 and self.packet_data[1] == 0x02:
            return AnalyzerFrame("service_mode_entry", self.start_time, frame.end_time)
