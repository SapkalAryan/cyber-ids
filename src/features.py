import hashlib
import math

class BloomFilter:
    def __init__(self, expected_items, false_positive_rate):
        # Calculate optimal size of the bit array (m) and number of hash functions (k)
        self.size = math.ceil((expected_items * math.log(false_positive_rate)) / math.log(1 / (2 ** math.log(2))))
        self.hash_count = math.ceil((self.size / expected_items) * math.log(2))
        self.bit_array = bytearray(self.size)
        
    def _hashes(self, item):
        # Generate k different hash values for the item
        item = item.encode('utf-8')
        hashes = []
        for i in range(self.hash_count):
            # Using md5 and sha256 with a salt to get different hashes
            digest = hashlib.sha256(item + str(i).encode('utf-8')).hexdigest()
            hashes.append(int(digest, 16) % self.size)
        return hashes

    def add(self, item):
        for hash_val in self._hashes(item):
            self.bit_array[hash_val] = 1

    def check(self, item):
        for hash_val in self._hashes(item):
            if self.bit_array[hash_val] == 0:
                return False # Definitely not in the set
        return True # Possibly in the set