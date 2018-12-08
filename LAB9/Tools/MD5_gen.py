import struct
import binascii
import math

lrot = lambda x, n: (x << n) | (x >> (32 - n))


class MD5():

    A, B, C, D = (0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476)

    # r specifies the per-round shift amounts
    r = [7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
         5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
         4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
         6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21]

    # Use binary integer part of the sines of integers (Radians) as constants
    k = [math.floor(abs(math.sin(i + 1)) * (2 ** 32)) for i in range(64)]

    def __init__(self, message):
        if len(message)%64!=0:
            print('error : incomplete block')
        while len(message):
            self._handle(message[:64])
            message = message[64:]

    def _handle(self, chunk):
        w = list(struct.unpack('<' + 'I' * 16, chunk))

        a, b, c, d = self.A, self.B, self.C, self.D

        for i in range(64):
            if i < 16:
                f = (b & c) | ((~b) & d)
                g = i
            elif i < 32:
                f = (d & b) | ((~d) & c)
                g = (5 * i + 1) % 16
            elif i < 48:
                f = b ^ c ^ d
                g = (3 * i + 5) % 16
            else:
                f = c ^ (b | (~d))
                g = (7 * i) % 16

            x = b + lrot((a + f + self.k[i] + w[g]) & 0xffffffff, self.r[i])
            a, b, c, d = d, x & 0xffffffff, b, c

        self.A = (self.A + a) & 0xffffffff
        self.B = (self.B + b) & 0xffffffff
        self.C = (self.C + c) & 0xffffffff
        self.D = (self.D + d) & 0xffffffff

    def get_state(self):
        return ' '.join([hex(self.A),hex(self.B),hex(self.C),hex(self.D)])
