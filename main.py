import asyncio


def BSD_checksum(packet: bytes):
    # Initialize checksum and bitmask
    checksum = 0
    bitmask = 0xFF

    # Perform iterations
    for byte in packet:
        checksum = checksum >> 1
        checksum += int.from_bytes(byte.to_bytes(1, byteorder="big"), byteorder="big")
        checksum &= bitmask

    # Ensure the checksum is limited to one byte
    return checksum.to_bytes(1, byteorder="big")


# Set global constants
ACK = b"\x47\x44\x00" + BSD_checksum(b"\x47\x44\x00")
NACK = b"\x47\x44\x01" + BSD_checksum(b"\x47\x44\x01")


class SerialDriver:
    """
    Base class representing a high-level serial driver.
    """

    def __init__(self):
        self.kill_status = False # Kill initially set to False
        self.response = None # Set response
        self.timer = asyncio.get_event_loop().call_later(1, self.kill) # Set timer task
        self.thrusters = { # Initialize thrusters to 0
            0: 0,
            1: 0,
            2: 0,
            3: 0,
            4: 0,
            5: 0,
            6: 0,
            7: 0
        }

    async def send(self, data: bytes) -> None:
        # Reset response
        self.response = None

        # Ensure start bits, size, and checksum are correct
        if (data[:2] == b"\x47\x44") and (len(data) >= 4) and (BSD_checksum(data[:-1]) == bytes([data[-1]])):
            identifier = data[2]
            # ACK
            if identifier == 0:
                self.response = NACK
            # NACK
            elif identifier == 1:
                self.response = NACK
            # Get Kill Status
            elif identifier == 2:
                # If kill was set, payload x01
                if self.kill_status:
                    self.response = b"\x47\x44\x03\x01" + BSD_checksum(b"\x47\x44\x03\x01")
                # If kill was not set, payload x00
                else:
                    self.response = b"\x47\x44\x03" + BSD_checksum(b"\x47\x44\x03")
            # Heart Beat
            elif identifier == 4:
                # Reset timer
                self.reset_heartbeat_timer()
            # Kill
            elif identifier == 5:
                # If kill was set, return NACK 
                if self.kill_status:
                    self.response = NACK
                # If kill was not set, return ACK
                else:
                    self.response = ACK
                self.kill()
            # Unkill
            elif identifier == 6:
                # If kill was set, return ACK 
                if self.kill_status:
                    self.response = ACK
                # If kill was not set, return NACK
                else:
                    self.response = NACK
                self.kill_status = False
            # Set Thrust
            elif identifier == 7:
                # Check for correct length
                if len(data) == 9:
                    # Check that kill is off
                    if self.kill_status == False:
                        thruster_id = data[3]
                        thrust_bytes = data[4:8]
                        thrust_value = float(int.from_bytes(thrust_bytes, byteorder="little"))
                        # Check for valid thruster id and thrust value
                        if (0 <= thruster_id <= 7) and (0 <= thrust_value <= 1):
                            self.thrusters[thruster_id] = thrust_value
                            self.response = ACK
                        # If invalid thruster id or thrust value, return NACK
                        else:
                            self.response = NACK
                    # If kill is set, return ACK
                    else:
                        self.response = ACK
                # If incorrect length, discard packet
                else:
                    return
            # Invalid identifier
            else:
                return
        # Invalid packet start bits, size, or checksum
        else:
            return

    async def receive(self) -> bytes:
        # Return response
        return self.response

    def kill(self):
        # Kill
        self.kill_status = True

        # Reset thrust
        for i in range(8):
            self.thrusters[i] = 0

    def reset_heartbeat_timer(self):
        # Unkill
        self.kill_status = False

        # Cancel timer and restart it
        self.timer.cancel()
        self.timer = asyncio.create_task(self.timer())


async def main():
    driver = SerialDriver()

    # Example 1: Successful get kill status
    # 0x4744 - start of packet
    # 0x02 - packet type
    # 0x35 - checksum
    kill_status_packet = b"\x47\x44\x02\x35"
    await driver.send(kill_status_packet)

    # Return kill status packet
    # 0x4744 - start of packet
    # 0x03 - packet type
    # 0x00 - kill status (not set yet, we have not set it)
    # 0x36 - checksum
    assert await driver.receive() == b"\x47\x44\x03\x36"

    # Wait 1 second (kill will automatically trigger because no heartbeat was
    #               sent)
    await asyncio.sleep(1)

    # Example 2: Successful get kill status
    # 0x4744 - start of packet
    # 0x02 - packet type
    # 0x35 - checksum
    kill_status_packet = b"\x47\x44\x02\x35"
    await driver.send(kill_status_packet)

    # Return kill status packet
    # 0x4744 - start of packet
    # 0x03 - packet type
    # 0x01 - kill status (set because we were not sending heartbeat)
    # 0x1C - checksum
    assert await driver.receive() == b"\x47\x44\x03\x01\x1C"

    # Example 3: Successful thrust set packet
    # 0x4744 - start of packet
    # 0x07 - packet type
    # payload:
    # 0x04 - random thruster value
    # struct.pack("f", 0.31415) --> four bytes, speed packed as a float
    # 0x45 - byte 1 of speed
    # 0xD8 - byte 2 of speed
    # 0xA0 - byte 3 of speed
    # 0x3E - byte 4 of speed
    # 0x8E - checksum
    kill_status_packet = b"\x47\x44\x07\x04\x45\xD8\xA0\x3E\x8E"
    await driver.send(kill_status_packet)

    # Return ACK (kill is still set)
    # 0x4744 - start of packet
    # 0x00 - packet type
    # 0x33 - checksum
    assert await driver.receive() == b"\x47\x44\x00\x33"

    # Example 4: Finally, we can send a heartbeat! :)
    # In reality, you may want to modify this code to send heartbeats automatically,
    # so that your driver does not kill all the time. There are ways to run
    # code periodically in Python using asyncio, many of which are publicly documented
    # and in use at MIL.
    # Anyways...
    # 0x4744 - start of packet
    # 0x04 - packet type
    # 0x1B - checksum
    await driver.send(b"\x47\x44\x04\x1B")


if __name__ == "__main__":
    asyncio.run(main())
