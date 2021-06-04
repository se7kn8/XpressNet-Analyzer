# High Level Analyzer
from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame


def check_bit(value, pos):
    return (value >> (pos - 1)) & 0b1


def get_address(call_byte):
    return call_byte & 0b11111


def is_normal_inquiry(call_byte):
    return ((call_byte >> 5) & 0b11) == 0b10


# High level analyzers must subclass the HighLevelAnalyzer class.
class Hla(HighLevelAnalyzer):
    result_types = {
        'normal_inquiry': {
            'format': 'Normal inquiry: Address={{data.address}}'
        }
    }

    def __init__(self):
        pass

    def decode(self, frame: AnalyzerFrame):
        if frame.type != 'data':
            return
        if 'error' in frame.data:
            return
        frame_data: bytes = frame.data["data"]
        # 9bit data
        data = (frame_data[0] << 8) | frame_data[1]
        # If 9th bit is set this is a call byte with an address
        if check_bit(data, 9):
            # Check if this is a normal inquiry
            print(bin(data >> 5))
            print(bin((data >> 5) & 0b11))
            if is_normal_inquiry(data):
                return AnalyzerFrame('normal_inquiry', frame.start_time, frame.end_time, {
                    'address': get_address(data)
                })
        return
