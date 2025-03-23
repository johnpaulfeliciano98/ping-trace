# Description:
# This project builds upon a raw socket ICMP ping implementation to create a traceroute tool.
# It sends ICMP echo (type 8) messages with increasing TTL values and processes responses from
# intermediate routers (ICMP type 11) or the destination (ICMP type 0). It also handles error responses
# (e.g., ICMP type 3 for Destination Unreachable) and reports aggregated statistics (min, max, average RTT and
# packet loss percentage).

# Sources and References:
# 1. IANA ICMP Parameters. Retrieved from: https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml
# 2. Networksorcery ICMP Protocol Reference. Retrieved from: http://www.networksorcery.com/enp/protocol/icmp/
# 3. Beej's Guide to Network Programming. Retrieved from: http://beej.us/guide/bgnet/
# 4. Python Socket Programming Documentation. Retrieved from: https://docs.python.org/3/library/socket.html


# #################################################################################################################### #
# Imports                                                                                                              #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
# #################################################################################################################### #
import os
from socket import *
import struct
import time
import select


# #################################################################################################################### #
# Class IcmpHelperLibrary                                                                                              #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
# #################################################################################################################### #
class IcmpHelperLibrary:
    # ################################################################################################################ #
    # Class IcmpPacket                                                                                                 #
    #                                                                                                                  #
    # References:                                                                                                      #
    # https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml                                           #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    class IcmpPacket:
        # ############################################################################################################ #
        # IcmpPacket Class Scope Variables                                                                             #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        __icmpTarget = ""               # Remote Host
        __destinationIpAddress = ""     # Remote Host IP Address
        __header = b''                  # Header after byte packing
        __data = b''                    # Data after encoding
        __dataRaw = ""                  # Raw string data before encoding
        # Valid values are 0-255 (unsigned int, 8 bits)
        __icmpType = 0
        # Valid values are 0-255 (unsigned int, 8 bits)
        __icmpCode = 0
        # Valid values are 0-65535 (unsigned short, 16 bits)
        __packetChecksum = 0
        # Valid values are 0-65535 (unsigned short, 16 bits)
        __packetIdentifier = 0
        # Valid values are 0-65535 (unsigned short, 16 bits)
        __packetSequenceNumber = 0
        __ipTimeout = 30
        __ttl = 255                     # Time to live

        __DEBUG_IcmpPacket = False      # Allows for debug output

        # ############################################################################################################ #
        # IcmpPacket Class Getters                                                                                     #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def getIcmpTarget(self):
            return self.__icmpTarget

        def getDataRaw(self):
            return self.__dataRaw

        def getIcmpType(self):
            return self.__icmpType

        def getIcmpCode(self):
            return self.__icmpCode

        def getPacketChecksum(self):
            return self.__packetChecksum

        def getPacketIdentifier(self):
            return self.__packetIdentifier

        def getPacketSequenceNumber(self):
            return self.__packetSequenceNumber

        def getTtl(self):
            return self.__ttl

        # ############################################################################################################ #
        # IcmpPacket Class Setters                                                                                     #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def setIcmpTarget(self, icmpTarget):
            self.__icmpTarget = icmpTarget

            # Only attempt to get destination address if it is not whitespace
            if len(self.__icmpTarget.strip()) > 0:
                self.__destinationIpAddress = gethostbyname(
                    self.__icmpTarget.strip())

        def setIcmpType(self, icmpType):
            self.__icmpType = icmpType

        def setIcmpCode(self, icmpCode):
            self.__icmpCode = icmpCode

        def setPacketChecksum(self, packetChecksum):
            self.__packetChecksum = packetChecksum

        def setPacketIdentifier(self, packetIdentifier):
            self.__packetIdentifier = packetIdentifier

        def setPacketSequenceNumber(self, sequenceNumber):
            self.__packetSequenceNumber = sequenceNumber

        def setTtl(self, ttl):
            self.__ttl = ttl

        # ############################################################################################################ #
        # IcmpPacket Class Private Functions                                                                           #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def __recalculateChecksum(self):
            print("calculateChecksum Started...") if self.__DEBUG_IcmpPacket else 0
            packetAsByteData = b''.join([self.__header, self.__data])
            checksum = 0

            # This checksum function will work with pairs of values with two separate 16 bit segments. Any remaining
            # 16 bit segment will be handled on the upper end of the 32 bit segment.
            countTo = (len(packetAsByteData) // 2) * 2

            # Calculate checksum for all paired segments
            print(
                f'{"Count":10} {"Value":10} {"Sum":10}') if self.__DEBUG_IcmpPacket else 0
            count = 0
            while count < countTo:
                thisVal = packetAsByteData[count +
                                           1] * 256 + packetAsByteData[count]
                checksum = checksum + thisVal
                checksum = checksum & 0xffffffff        # Capture 16 bit checksum as 32 bit value
                print(
                    f'{count:10} {hex(thisVal):10} {hex(checksum):10}') if self.__DEBUG_IcmpPacket else 0
                count = count + 2

            # Calculate checksum for remaining segment (if there are any)
            if countTo < len(packetAsByteData):
                thisVal = packetAsByteData[len(packetAsByteData) - 1]
                checksum = checksum + thisVal
                checksum = checksum & 0xffffffff        # Capture as 32 bit value
                print(count, "\t", hex(thisVal), "\t", hex(
                    checksum)) if self.__DEBUG_IcmpPacket else 0

            # Add 1's Complement Rotation to original checksum
            # Rotate and add to base 16 bits
            checksum = (checksum >> 16) + (checksum & 0xffff)
            checksum = (checksum >> 16) + \
                checksum              # Rotate and add

            answer = ~checksum                  # Invert bits
            answer = answer & 0xffff            # Trim to 16 bit value
            answer = answer >> 8 | (answer << 8 & 0xff00)
            print("Checksum: ", hex(answer)) if self.__DEBUG_IcmpPacket else 0

            self.setPacketChecksum(answer)

        def __packHeader(self):
            # The following header is based on http://www.networksorcery.com/enp/protocol/icmp/msg8.htm
            # Type = 8 bits
            # Code = 8 bits
            # ICMP Header Checksum = 16 bits
            # Identifier = 16 bits
            # Sequence Number = 16 bits
            self.__header = struct.pack("!BBHHH",
                                        self.getIcmpType(),  # 8 bits / 1 byte  / Format code B
                                        self.getIcmpCode(),  # 8 bits / 1 byte  / Format code B
                                        self.getPacketChecksum(),        # 16 bits / 2 bytes / Format code H
                                        self.getPacketIdentifier(),      # 16 bits / 2 bytes / Format code H
                                        self.getPacketSequenceNumber()   # 16 bits / 2 bytes / Format code H
                                        )

        def __encodeData(self):
            # Used to track overall round trip time
            data_time = struct.pack("d", time.time())
            # time.time() creates a 64 bit value of 8 bytes
            dataRawEncoded = self.getDataRaw().encode("utf-8")

            self.__data = data_time + dataRawEncoded

        def __packAndRecalculateChecksum(self):
            # Checksum is calculated with the following sequence to confirm data in up to date
            # packHeader() and encodeData() transfer data to their respective bit
            self.__packHeader()
            # locations, otherwise, the bit sequences are empty or incorrect.
            self.__encodeData()
            self.__recalculateChecksum()        # Result will set new checksum value
            self.__packHeader()                 # Header is rebuilt to include new checksum value

        def __validateIcmpReplyPacketWithOriginalPingData(self, icmpReplyPacket):
            # Hint: Work through comparing each value and identify if this is a valid response.
            # Set expected values in the reply packet
            icmpReplyPacket.setExpectedIcmpIdentifier(
                self.getPacketIdentifier())
            icmpReplyPacket.setExpectedIcmpSequenceNumber(
                self.getPacketSequenceNumber())
            icmpReplyPacket.setExpectedIcmpData(self.__dataRaw)

            # Validate Identifier
            expectedIdentifier = self.getPacketIdentifier()
            actualIdentifier = icmpReplyPacket.getIcmpIdentifier()
            if expectedIdentifier == actualIdentifier:
                icmpReplyPacket.setIcmpIdentifier_isValid(True)
                print(
                    f"DEBUG: Identifier valid. Expected: {expectedIdentifier}, Actual: {actualIdentifier}")
            else:
                icmpReplyPacket.setIcmpIdentifier_isValid(False)
                print(
                    f"DEBUG: Identifier mismatch. Expected: {expectedIdentifier}, Actual: {actualIdentifier}")

            # Validate Sequence Number
            expectedSeq = self.getPacketSequenceNumber()
            actualSeq = icmpReplyPacket.getIcmpSequenceNumber()
            if expectedSeq == actualSeq:
                icmpReplyPacket.setIcmpSequenceNumber_isValid(True)
                print(
                    f"DEBUG: Sequence Number valid. Expected: {expectedSeq}, Actual: {actualSeq}")
            else:
                icmpReplyPacket.setIcmpSequenceNumber_isValid(False)
                print(
                    f"DEBUG: Sequence Number mismatch. Expected: {expectedSeq}, Actual: {actualSeq}")

            # Validate Data
            expectedData = self.__dataRaw
            actualData = icmpReplyPacket.getIcmpData()
            if expectedData == actualData:
                icmpReplyPacket.setIcmpData_isValid(True)
                print(
                    f"DEBUG: Data valid. Expected: {expectedData}, Actual: {actualData}")
            else:
                icmpReplyPacket.setIcmpData_isValid(False)
                print(
                    f"DEBUG: Data mismatch. Expected: {expectedData}, Actual: {actualData}")

            # Set overall valid flag
            isValid = (icmpReplyPacket.getIcmpIdentifier_isValid() and
                       icmpReplyPacket.getIcmpSequenceNumber_isValid() and
                       icmpReplyPacket.getIcmpData_isValid())
            icmpReplyPacket.setIsValidResponse(isValid)

        # ############################################################################################################ #
        # IcmpPacket Class Public Functions                                                                            #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def buildPacket_echoRequest(self, packetIdentifier, packetSequenceNumber):
            self.setIcmpType(8)
            self.setIcmpCode(0)
            self.setPacketIdentifier(packetIdentifier)
            self.setPacketSequenceNumber(packetSequenceNumber)
            self.__dataRaw = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
            self.__packAndRecalculateChecksum()

        def sendEchoRequest(self):
            if len(self.__icmpTarget.strip()) <= 0 or len(self.__destinationIpAddress.strip()) <= 0:
                self.setIcmpTarget("127.0.0.1")

            print("Pinging (" + self.__icmpTarget + ") " +
                  self.__destinationIpAddress)

            mySocket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)
            mySocket.settimeout(self.__ipTimeout)
            mySocket.bind(("", 0))
            mySocket.setsockopt(IPPROTO_IP, IP_TTL, struct.pack(
                'I', self.getTtl()))  # Unsigned int - 4 bytes
            try:
                mySocket.sendto(
                    b''.join([self.__header, self.__data]), (self.__destinationIpAddress, 0))
                timeLeft = 30
                pingStartTime = time.time()
                startedSelect = time.time()
                whatReady = select.select([mySocket], [], [], timeLeft)
                endSelect = time.time()
                howLongInSelect = (endSelect - startedSelect)
                if whatReady[0] == []:  # Timeout
                    print(
                        "  *        *        *        *        *    Request timed out.")
                # recvPacket - bytes object representing data received
                recvPacket, addr = mySocket.recvfrom(1024)
                # addr  - address of socket sending data
                timeReceived = time.time()
                timeLeft = timeLeft - howLongInSelect
                if timeLeft <= 0:
                    print(
                        "  *        *        *        *        *    Request timed out (By no remaining time left).")

                else:
                    # Fetch the ICMP type and code from the received packet
                    icmpType, icmpCode = recvPacket[20:22]

                    if icmpType == 11:                          # Time Exceeded
                        print("  TTL=%d    RTT=%.0f ms    Type=%d    Code=%d    %s" %
                              (
                                  self.getTtl(),
                                  (timeReceived - pingStartTime) * 1000,
                                  icmpType,
                                  icmpCode,
                                  addr[0]
                              )
                              )
                    elif icmpType == 3:  # Destination Unreachable
                        errorMessage = {
                            0: "Destination Network Unreachable",
                            1: "Destination Host Unreachable",
                            2: "Destination Protocol Unreachable",
                            3: "Destination Port Unreachable",
                            4: "Fragmentation Needed and DF set",
                            5: "Source Route Failed"
                        }.get(icmpCode, "Unknown Error")
                        print("  TTL=%d    RTT=%.0f ms    Type=%d    Code=%d (%s)    %s" %
                              (
                                  self.getTtl(),
                                  (timeReceived - pingStartTime) * 1000,
                                  icmpType,
                                  icmpCode,
                                  errorMessage,
                                  addr[0]
                              )
                              )

                    elif icmpType == 0:                         # Echo Reply
                        icmpReplyPacket = IcmpHelperLibrary.IcmpPacket_EchoReply(
                            recvPacket)
                        self.__validateIcmpReplyPacketWithOriginalPingData(
                            icmpReplyPacket)
                        icmpReplyPacket.printResultToConsole(
                            self.getTtl(), timeReceived, addr)
                        return      # Echo reply is the end and therefore should return

                    else:
                        print("error")
            except timeout:
                print(
                    "  *        *        *        *        *    Request timed out (By Exception).")
            finally:
                mySocket.close()

        def printIcmpPacketHeader_hex(self):
            print("Header Size: ", len(self.__header))
            for i in range(len(self.__header)):
                print("i=", i, " --> ", self.__header[i:i+1].hex())

        def printIcmpPacketData_hex(self):
            print("Data Size: ", len(self.__data))
            for i in range(len(self.__data)):
                print("i=", i, " --> ", self.__data[i:i + 1].hex())

        def printIcmpPacket_hex(self):
            print("Printing packet in hex...")
            self.printIcmpPacketHeader_hex()
            self.printIcmpPacketData_hex()

    # ################################################################################################################ #
    # Class IcmpPacket_EchoReply                                                                                       #
    #                                                                                                                  #
    # References:                                                                                                      #
    # http://www.networksorcery.com/enp/protocol/icmp/msg0.htm                                                         #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    class IcmpPacket_EchoReply:
        # ############################################################################################################ #
        # IcmpPacket_EchoReply Class Scope Variables                                                                   #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        __recvPacket = b''
        __isValidResponse = False
        __icmpIdentifier_isValid = False
        __icmpSequenceNumber_isValid = False
        __icmpData_isValid = False
        __expectedIcmpIdentifier = None
        __expectedIcmpSequenceNumber = None
        __expectedIcmpData = None

        # ############################################################################################################ #
        # IcmpPacket_EchoReply Constructors                                                                            #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def __init__(self, recvPacket):
            self.__recvPacket = recvPacket

        # ############################################################################################################ #
        # IcmpPacket_EchoReply Getters                                                                                 #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def getIcmpType(self):
            # Method 1
            # bytes = struct.calcsize("B")        # Format code B is 1 byte
            # return struct.unpack("!B", self.__recvPacket[20:20 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("B", 20)

        def getIcmpCode(self):
            # Method 1
            # bytes = struct.calcsize("B")        # Format code B is 1 byte
            # return struct.unpack("!B", self.__recvPacket[21:21 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("B", 21)

        def getIcmpHeaderChecksum(self):
            # Method 1
            # bytes = struct.calcsize("H")        # Format code H is 2 bytes
            # return struct.unpack("!H", self.__recvPacket[22:22 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("H", 22)

        def getIcmpIdentifier(self):
            # Method 1
            # bytes = struct.calcsize("H")        # Format code H is 2 bytes
            # return struct.unpack("!H", self.__recvPacket[24:24 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("H", 24)

        def getIcmpSequenceNumber(self):
            # Method 1
            # bytes = struct.calcsize("H")        # Format code H is 2 bytes
            # return struct.unpack("!H", self.__recvPacket[26:26 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("H", 26)

        def getDateTimeSent(self):
            # This accounts for bytes 28 through 35 = 64 bits
            # Used to track overall round trip time
            return self.__unpackByFormatAndPosition("d", 28)
            # time.time() creates a 64 bit value of 8 bytes

        def getIcmpData(self):
            # This accounts for bytes 36 to the end of the packet.
            return self.__recvPacket[36:].decode('utf-8')

        def isValidResponse(self):
            return self.__isValidResponse

        def getIcmpIdentifier_isValid(self):
            return self.__icmpIdentifier_isValid

        def getIcmpSequenceNumber_isValid(self):
            return self.__icmpSequenceNumber_isValid

        def getIcmpData_isValid(self):
            return self.__icmpData_isValid

        def getExpectedIcmpIdentifier(self):
            return self.__expectedIcmpIdentifier

        def getExpectedIcmpSequenceNumber(self):
            return self.__expectedIcmpSequenceNumber

        def getExpectedIcmpData(self):
            return self.__expectedIcmpData

        # ############################################################################################################ #
        # IcmpPacket_EchoReply Setters                                                                                 #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def setIsValidResponse(self, booleanValue):
            self.__isValidResponse = booleanValue

        def setIcmpIdentifier_isValid(self, value):
            self.__icmpIdentifier_isValid = value

        def setIcmpSequenceNumber_isValid(self, value):
            self.__icmpSequenceNumber_isValid = value

        def setIcmpData_isValid(self, value):
            self.__icmpData_isValid = value

        def setExpectedIcmpIdentifier(self, value):
            self.__expectedIcmpIdentifier = value

        def setExpectedIcmpSequenceNumber(self, value):
            self.__expectedIcmpSequenceNumber = value

        def setExpectedIcmpData(self, value):
            self.__expectedIcmpData = value
        # ############################################################################################################ #
        # IcmpPacket_EchoReply Private Functions                                                                       #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #

        def __unpackByFormatAndPosition(self, formatCode, basePosition):
            numberOfbytes = struct.calcsize(formatCode)
            return struct.unpack("!" + formatCode, self.__recvPacket[basePosition:basePosition + numberOfbytes])[0]

        # ############################################################################################################ #
        # IcmpPacket_EchoReply Public Functions                                                                        #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def printResultToConsole(self, ttl, timeReceived, addr):
            bytes = struct.calcsize("d")
            timeSent = struct.unpack("d", self.__recvPacket[28:28 + bytes])[0]
            print("  TTL=%d    RTT=%.0f ms    Type=%d    Code=%d        Identifier=%d    Sequence Number=%d    %s" %
                  (
                      ttl,
                      (timeReceived - timeSent) * 1000,
                      self.getIcmpType(),
                      self.getIcmpCode(),
                      self.getIcmpIdentifier(),
                      self.getIcmpSequenceNumber(),
                      addr[0]
                  )
                  )
            if not self.__isValidResponse:
                if not self.__icmpIdentifier_isValid:
                    print(
                        f"ERROR: Identifier mismatch. Expected: {self.__expectedIcmpIdentifier}, Received: {self.getIcmpIdentifier()}")
            if not self.__icmpSequenceNumber_isValid:
                print(
                    f"ERROR: Sequence Number mismatch. Expected: {self.__expectedIcmpSequenceNumber}, Received: {self.getIcmpSequenceNumber()}")
            if not self.__icmpData_isValid:
                print(
                    f"ERROR: Data mismatch. Expected: {self.__expectedIcmpData}, Received: {self.getIcmpData()}")

    # ################################################################################################################ #
    # Class IcmpHelperLibrary                                                                                          #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #

    # ################################################################################################################ #
    # IcmpHelperLibrary Class Scope Variables                                                                          #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    __DEBUG_IcmpHelperLibrary = False                  # Allows for debug output

    # ################################################################################################################ #
    # IcmpHelperLibrary Private Functions                                                                              #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    def __sendIcmpEchoRequest(self, host):
        print("sendIcmpEchoRequest Started...") if self.__DEBUG_IcmpHelperLibrary else 0
        rtt_list = []
        sent_packets = 0
        received_packets = 0
        for i in range(4):
            try:
                sent_packets += 1
                # Build packet
                icmpPacket = IcmpHelperLibrary.IcmpPacket()
                randomIdentifier = (os.getpid() & 0xffff)
                packetIdentifier = randomIdentifier
                packetSequenceNumber = i
                icmpPacket.buildPacket_echoRequest(
                    packetIdentifier, packetSequenceNumber)
                icmpPacket.setIcmpTarget(host)
                # Send the echo request and capture the RTT (if received)
                rtt = icmpPacket.sendEchoRequest()
                if rtt is not None:
                    rtt_list.append(rtt)
                    received_packets += 1
                if self.__DEBUG_IcmpHelperLibrary:
                    icmpPacket.printIcmpPacketHeader_hex()
                    icmpPacket.printIcmpPacket_hex()
            except Exception as e:
                print("Exception in ping loop:", e)
        # Calculate statistics only if any packets were sent
        if sent_packets > 0:
            packet_loss = ((sent_packets - received_packets) /
                           sent_packets) * 100
        else:
            packet_loss = 0

        if rtt_list:
            min_rtt = min(rtt_list)
            max_rtt = max(rtt_list)
            avg_rtt = sum(rtt_list) / len(rtt_list)
        else:
            min_rtt = max_rtt = avg_rtt = 0

        # Print aggregated ping statistics
        print("\n--- Ping Statistics ---")
        print(
            f"Packets: Sent = {sent_packets}, Received = {received_packets}, Lost = {sent_packets - received_packets} ({packet_loss:.0f}% loss)")
        if received_packets > 0:
            print(
                f"RTT: Minimum = {min_rtt:.0f} ms, Maximum = {max_rtt:.0f} ms, Average = {avg_rtt:.0f} ms")

    def __sendIcmpTraceRoute(self, host):
        print("sendIcmpTraceRoute Started...") if self.__DEBUG_IcmpHelperLibrary else 0
        # Build code for trace route here
        max_ttl = 30
        reached = False
        ttl = 1
        while not reached and ttl <= max_ttl:
            icmpPacket = IcmpHelperLibrary.IcmpPacket()
            icmpPacket.setTtl(ttl)
            randomIdentifier = (os.getpid() & 0xffff)
            packetIdentifier = randomIdentifier
            packetSequenceNumber = ttl  # Using TTL as sequence number for uniqueness
            icmpPacket.buildPacket_echoRequest(
                packetIdentifier, packetSequenceNumber)
            icmpPacket.setIcmpTarget(host)
            print(f"Tracing route with TTL={ttl}...")
            rtt = icmpPacket.sendEchoRequest()
            # If an Echo Reply is received, destination is reached
            if rtt is not None:
                reached = True
            ttl += 1
        if not reached:
            print("Traceroute did not reach the destination within max TTL.")

    # ################################################################################################################ #
    # IcmpHelperLibrary Public Functions                                                                               #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    def sendPing(self, targetHost):
        print("ping Started...") if self.__DEBUG_IcmpHelperLibrary else 0
        self.__sendIcmpEchoRequest(targetHost)

    def traceRoute(self, targetHost):
        print("traceRoute Started...") if self.__DEBUG_IcmpHelperLibrary else 0
        self.__sendIcmpTraceRoute(targetHost)


# #################################################################################################################### #
# main()                                                                                                               #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
# #################################################################################################################### #
def main():
    icmpHelperPing = IcmpHelperLibrary()

    # Choose one of the following by uncommenting out the line
    # icmpHelperPing.sendPing("209.233.126.254")
    # icmpHelperPing.sendPing("www.google.com")
    # icmpHelperPing.sendPing("gaia.cs.umass.edu")
    # icmpHelperPing.traceRoute("164.151.129.20")
    # icmpHelperPing.traceRoute("122.56.99.243")


if __name__ == "__main__":
    main()
