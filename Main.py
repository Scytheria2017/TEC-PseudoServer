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
            logging.FileHandler('wow_server.log', mode='w'),
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


# -----------
# Game Phases
# -----------

PHASE_LOGON =                   0
PHASE_REALM =                   1
PHASE_LOBBY =                   2
PHASE_WORLD =                   3


# -------------------
# Auth Packet Opcodes
# -------------------

LOGON_CHALLENGE =               0x00
LOGON_PROOF =                   0x01
LOGON_SUCCESS =                 0x03


# ----------------------------
# Client/Server Packet Opcodes
# ----------------------------
    
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


# -------------
# Handle Client
# -------------

async def handle_client(reader, writer):
    client_addr = writer.get_extra_info('peername')
    logging.info(f" Client connected: {client_addr}")
    logging.info(f"")

    phase = PHASE_LOGON

    while True:
        try:

            data = await reader.read(1024)
            if not data:
                return
            debug_logging(data)

            # -----------
            # Logon phase
            # -----------

            if phase == PHASE_LOGON:

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
                    )

                    writer.write(success_packet)
                    debug_logging(success_packet)
                    await writer.drain()
                    logging.info(f" Logon Successful")
                    phase = PHASE_REALM

            # -----------
            # Realm phase
            # -----------

            elif phase == PHASE_REALM:
               
                opcode = struct.unpack('<H', data[:2])[0]

                if opcode == C_REALM_LIST:

                    realm_packet = struct.pack(
                        '<HBBHBBBBBB',
                        S_REALM_LIST,    
                        1,
                        0,
                        0,
                        1,
                        0,
                        1,
                        0,
                        0,
                        0
                    ) + b'The Eternal Crusade\x00' + b'127.0.0.1:8085\x00'

                    writer.write(realm_packet)
                    debug_logging(success_packet)
                    await writer.drain()
                    logging.info(f" Realm established")
                    phase = PHASE_LOBBY

            # -----------
            # Lobby phase
            # -----------

            elif phase == PHASE_LOBBY:

                opcode = struct.unpack('<H', data[:2])[0]

                if opcode == C_PLAYER_LOGIN:

                    char_packet = struct.pack(
                        '<HHB',
                        S_CHAR_ENUM,
                        1,
                        0
                    )
                    writer.write(char_packet)
                    debug_logging(char_packet)
                    await writer.drain()
                    logging.info(f" Characters loaded")


            # -----------
            # World phase
            # -----------

            if phase == PHASE_WORLD:
                pass


        except ConnectionResetError:
            break

        except Exception as e:
            logging.error(f" ERROR - handling client: {e}")
            break

    logging.info(f" Client disconnected: {client_addr}")
    writer.close()
  

async def run_server():
    server = await asyncio.start_server(
        handle_client, '0.0.0.0', 3724)

    addr = server.sockets[0].getsockname()
    logging.info(f" Server running on {addr[0]}:{addr[1]}")
   
    async with server:
        await server.serve_forever()

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