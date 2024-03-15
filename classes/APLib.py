from io import BytesIO

# Implementação do algoritmo de compressão APlib
# Link de Referência: https://github.com/snemes/aplib/blob/master/src/aplib.py

class APLib(object):

    __slots__ = 'source', 'destination', 'tag', 'bitcount', 'strict'

    def __init__(self, source, strict=True):
        self.source = BytesIO(source)
        self.destination = bytearray()
        self.tag = 0
        self.bitcount = 0
        self.strict = bool(strict)

    def getbit(self):
        self.bitcount -= 1
        if self.bitcount < 0:
            self.tag = ord(self.source.read(1))
            self.bitcount = 7

        bit = self.tag >> 7 & 1
        self.tag <<= 1

        return bit

    def getgamma(self):
        result = 1

        while True:
            result = (result << 1) + self.getbit()
            if not self.getbit():
                break

        return result

    def depack(self):
        r0 = -1
        lwm = 0
        done = False

        try:


            self.destination += self.source.read(1)

            while not done:
                if self.getbit():
                    if self.getbit():
                        if self.getbit():
                            offs = 0
                            for _ in range(4):
                                offs = (offs << 1) + self.getbit()

                            if offs:
                                self.destination.append(self.destination[-offs])
                            else:
                                self.destination.append(0)

                            lwm = 0
                        else:
                            offs = ord(self.source.read(1))
                            length = 2 + (offs & 1)
                            offs >>= 1

                            if offs:
                                for _ in range(length):
                                    self.destination.append(self.destination[-offs])
                            else:
                                done = True

                            r0 = offs
                            lwm = 1
                    else:
                        offs = self.getgamma()

                        if lwm == 0 and offs == 2:
                            offs = r0
                            length = self.getgamma()

                            for _ in range(length):
                                self.destination.append(self.destination[-offs])
                        else:
                            if lwm == 0:
                                offs -= 3
                            else:
                                offs -= 2

                            offs <<= 8
                            offs += ord(self.source.read(1))
                            length = self.getgamma()

                            if offs >= 32000:
                                length += 1
                            if offs >= 1280:
                                length += 1
                            if offs < 128:
                                length += 2

                            for _ in range(length):
                                self.destination.append(self.destination[-offs])

                            r0 = offs

                        lwm = 1
                else:
                    self.destination += self.source.read(1)
                    lwm = 0

        except (TypeError, IndexError):
            if self.strict:
                raise RuntimeError('aPLib decompression error')

        return bytes(self.destination)

    def pack(self):
        raise NotImplementedError