from Util.protocal import pack_file_name, get_file_name
import struct


class file_load:
    def __init__(self, file_path):
        name = get_file_name(file_path)
        try:
            with open(file_path, "rb") as f:
                file = f.read()
                self.file = pack_file_name(name, file)
                self.size = len(self.file)
        except FileNotFoundError:
            print("File not found")
            exit()

    def get_section(self, base, size):
        end = base + size if base + size < self.size else self.size
        return self.file[base:end]

