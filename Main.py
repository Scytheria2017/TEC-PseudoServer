import asyncio
import logging
import os
import struct
import subprocess

DEBUG = True
TEC_PATH = 'd://Desktop/The Eternal Crusade/TEC.exe'

ACCOUNT = {"username": "Eternal", "password": "Crusade", "salt": b'\x01\x02\x03\x04\x05' + b'\x00'*27}

if DEBUG:
    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('Server.log', mode='w'),
            logging.StreamHandler()
        ]
    )
else:
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler()
        ]
    )

LOGON_CHALLENGE = 0x00
LOGON_PROOF = 0x01
RECONNECT_PROOF = 0x02
LOGON_SUCCESS = 0x03

C_REALM_LIST = 0x01
C_CHAR_ENUM = 0x037
C_PLAYER_LOGIN = 0x003D

S_REALM_LIST = 0x10
S_CHAR_ENUM = 0x003B

sessions = {}
wow_process = None
realmlist_path = None

logging.info("======================================")
logging.info("The Eternal Crusade Pseudo-Server v1.0")
logging.info("======================================")


async def launch_client(wow_path):
    global wow_process
    if not os.path.exists(wow_path):
        raise FileNotFoundError(f"ERROR - TEC client not found at {wow_path}")
    wow_process = subprocess.Popen([wow_path])
    logging.info(f"Launched TEC client (PID: {wow_process.pid})")


async def handle_login_client(reader, writer):
    try:
        client_addr = writer.get_extra_info('peername')
        logging.info(f"Login client connected: {client_addr}")

        while True:
            data = await reader.read(1024)
            if not data:
                break
            logging.info(f"Received data: {data.hex()}")

            username_len = data[33]
            username = data[34:34+username_len].decode('ascii', 'ignore')
            logging.info(f"Auth attempt from: {username}")

            opcode = struct.unpack('<H', data[:2])[0]

            if opcode == LOGON_CHALLENGE:
                # Generate some kind of proof
                response = struct.pack('<HBB32s32s16s',
                    LOGON_PROOF,
                    0,
                    32,
                    ACCOUNT["salt"],
                    b'\x11'*32,  # Replace with real hash
                    b'\x22'*16   # Replace with real proof
                )
                writer.transport.set_write_buffer_limits(high=0)
                writer.write(response)
                logging.info(f"Sent LOGON_PROOF response: {response.hex()}")
                await writer.drain()

                proof_data = await reader.read(75)
                if not proof_data:
                    break
                logging.info(f"Received proof: {proof_data.hex()}")

                success_packet = struct.pack('<HBBIBI', LOGON_SUCCESS, 0x00, 0x00, 0x00000000, 0x00, 0x00000000) + b'\x00' + b'127.0.0.1:8085\x00'
                writer.transport.set_write_buffer_limits(high=0)
                writer.write(success_packet)
                logging.info(f"Sent LOGON_SUCCESS with redirect: {success_packet.hex()}")
                await writer.drain()
                logging.info("Logon successful")

            elif opcode == C_REALM_LIST:
                realm_packet = struct.pack('<HBBHBBBBBB', S_REALM_LIST, 1, 0, 0, 1, 0, 0, 0, 0) + b'The Eternal Crusade\x00' + b'127.0.0.1:8085\x00'
                writer.write(realm_packet)
                logging.info(f"Sent realm packet: {realm_packet.hex()}")
                writer.transport.set_write_buffer_limits(high=0)
                await writer.drain()
                logging.info("Realm established")
    except Exception as e:
        logging.error(f"ERROR - handling login client: {str(e)}", exc_info=DEBUG)
    finally:
        writer.close()


async def handle_world_client(reader, writer):
    try:
        client_addr = writer.get_extra_info('peername')
        logging.info(f"World client connected: {client_addr}")

        while True:
            data = await reader.read(1024)
            if not data:
                break
            logging.info(f"Received data: {data.hex()}")

            opcode = struct.unpack('<H', data[:2])[0]

            if opcode == C_PLAYER_LOGIN:
                char_packet = struct.pack('<HHB', S_CHAR_ENUM, 1, 0)
                writer.write(char_packet)
                logging.info(f"Sent char packet: {char_packet.hex()}")
                writer.transport.set_write_buffer_limits(high=0)
                await writer.drain()
                logging.info("Characters loaded")
    except Exception as e:
        logging.error(f"ERROR - handling world client: {str(e)}", exc_info=DEBUG)
    finally:
        logging.info(f"Client disconnected: {client_addr}")
        writer.close()


asyncio.streams._DEFAULT_LIMIT = 1024 * 1024


async def run_server():
    login_server = await asyncio.start_server(handle_login_client, '0.0.0.0', 3724)
    world_server = await asyncio.start_server(handle_world_client, '0.0.0.0', 8085)

    logging.info(f"Login server running on 0.0.0.0:3724")
    logging.info(f"World server running on 0.0.0.0:8085")

    await asyncio.gather(login_server.serve_forever(), world_server.serve_forever())


def cleanup():
    global wow_process
    if wow_process and wow_process.poll() is None:
        wow_process.terminate()
        logging.info("Terminated TEC client process")


async def main():
    try:
        await launch_client(TEC_PATH)
        await run_server()
    except Exception as e:
        logging.error(f"ERROR - {str(e)}", exc_info=DEBUG)
    finally:
        cleanup()


if __name__ == "__main__":
    asyncio.run(main())
