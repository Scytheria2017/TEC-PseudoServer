import asyncio
import logging
import os
import struct
import subprocess

# -------------------
# Debug (development)
# -------------------

DEBUG                   = True
TEC_PATH                = 'd://Desktop/The Eternal Crusade/TEC.exe'


# ------------------
# Hard-coded account
# ------------------

ACCOUNT = {"username": "Eternal", "password": "Crusade", "salt": b'\x01\x02\x03\x04\x05' + b'\x00'*27}


# -----------------
# Configure logging
# -----------------

if DEBUG:
    logging.basicConfig(
        level=logging.INFO,
        format=' %(message)s',
        handlers=[
            logging.FileHandler('Server.log', mode='w'),
            logging.StreamHandler()
        ]
    )
else:
    logging.basicConfig(
        level=logging.INFO,
        format=' %(message)s',
        handlers=[
            logging.StreamHandler()
        ]
    ) 


def debug_logging(text):
    if DEBUG:
        logging.info(f" DEBUG: {text}")


# -------------------
# Auth Packet Opcodes
# -------------------

LOGON_CHALLENGE =               0x00
LOGON_PROOF =                   0x01
LOGON_SUCCESS =                 0x03


# --------------------
# World Packet Opcodes
# --------------------
    
C_REALM_LIST =                  0x01
C_PLAYER_LOGIN =                0x003D

S_REALM_LIST =                  0x10
S_CHAR_ENUM =                   0x003B


# ----------------
# TEC PseudoServer
# ----------------

sessions = {}
wow_process = None
realmlist_path = None

logging.info(f"")
logging.info(f" ======================================")
logging.info(f" --------------------------------------")
logging.info(f" The Eternal Crusade Pseudo-Server v1.0")
logging.info(f" --------------------------------------")
logging.info(f" ======================================")
logging.info(f"")


# -------------
# Launch Client
# -------------

async def launch_client(wow_path):
    global wow_process
    if not os.path.exists(wow_path):
        raise FileNotFoundError(f" ERROR - TEC client not found at {wow_path}")
    wow_process = subprocess.Popen([wow_path])
    logging.info(f" Launched TEC client (PID: {wow_process.pid})")


# -------------------
# Handle login client
# -------------------

async def handle_login_client(reader, writer):
    client_addr = writer.get_extra_info('peername')
    logging.info(f" Login client connected: {client_addr}")
    logging.info(f"")

    while True:
        try:

            data = await reader.read(1024)
            if not data:
                break
            debug_logging(data)

            opcode = struct.unpack('<H', data[:2])[0]
    
            if opcode == LOGON_CHALLENGE:
            
                response = struct.pack('<HBB32s32s16s',
                    LOGON_PROOF,
                    0,
                    32,
                    ACCOUNT["salt"],
                    b'\x11'*32,
                    b'\x22'*16
                )

                writer.write(response)
                debug_logging(response)
                await writer.drain()

                proof_data = await reader.read(75)
                if not proof_data:
                    break
                debug_logging(proof_data)

                success_packet = struct.pack('<HBBIBI',
                    LOGON_SUCCESS,
                    0x00,
                    0x00,
                    0x00000000,
                    0x00,
                    0x00000000
                ) + b'\x00' + b'127.0.0.1:8085\x00'

                writer.write(success_packet)
                debug_logging(success_packet)
                await writer.drain()
                logging.info(f" Logon Successful")

            elif opcode == C_REALM_LIST:

                realm_packet = struct.pack(
                    '<HBBHBBBBBB',
                    S_REALM_LIST,
                    1,              # Realm count
                    0,              # Padding
                    0,              # Realm type
                    1,              # Realm flags (1 = online)
                    0,              # Locked (0 = unlocked)
                    0,              # Timezone
                    0,              # Population
                    0               # Unknown
                ) + b'The Eternal Crusade\x00' + b'127.0.0.1:8085\x00'

                writer.write(realm_packet)
                debug_logging(success_packet)
                await writer.drain()
                logging.info(f" Realm established")

        except ConnectionResetError:
            break

        except Exception as e:
            logging.error(f" ERROR - handling login client: {e}")
            break


# -------------------
# Handle world client
# -------------------

async def handle_world_client(reader, writer):
    client_addr = writer.get_extra_info('peername')
    logging.info(f" World client connected: {client_addr}")
    logging.info(f"")

    while True:
        try:

            data = await reader.read(1024)
            if not data:
                break
            debug_logging(data)

            opcode = struct.unpack('<H', data[:2])[0]

            if opcode == C_PLAYER_LOGIN:

                char_packet = struct.pack(
                    '<HHB',
                    S_CHAR_ENUM,
                    1,       # Size byte
                    0        # 0 characters
                )

                writer.write(char_packet)
                debug_logging(char_packet)
                await writer.drain()
                logging.info(f" Characters loaded")

        except ConnectionResetError:
            break

        except Exception as e:
            logging.error(f" ERROR - handling client: {e}")
            break

    logging.info(f" Client disconnected: {client_addr}")
    writer.close()
  

async def run_server():
    login_server = await asyncio.start_server(
        handle_login_client, '0.0.0.0', 3724)
    world_server = await asyncio.start_server(
        handle_world_client, '0.0.0.0', 8085)

    logging.info(f"Login server running on 0.0.0.0:3724")
    logging.info(f"World server running on 0.0.0.0:8085")
   
    await asyncio.gather(
        login_server.serve_forever(),
        world_server.serve_forever()
    )

def cleanup():
    global wow_process
    if wow_process and wow_process.poll() is None:
        wow_process.terminate()
        logging.info(" Terminated TEC client process")

async def main():
    try:
        await launch_client(TEC_PATH)
        await run_server()
       
    except Exception as e:
        logging.error(f" ERROR - {e}")

    finally:
        cleanup()

if __name__ == "__main__":
    asyncio.run(main())