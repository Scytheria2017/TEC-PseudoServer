from Components.Jabberwocky import jw
from Components.Verifier import verify, make_key

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


# -----------------
# Configure logging
# -----------------

logging.basicConfig(
    level=logging.INFO,
    format=' %(message)s',
    handlers=[
        logging.FileHandler('wow_server.log'),
        logging.StreamHandler()
    ]
)

def debug_logging(text):
    if DEBUG:
        logging.info(f" DEBUG: {text}")


# -------------------
# Auth Packet Opcodes
# -------------------

AUTH_LOGON_CHALLENGE =          0x00
AUTH_LOGON_PROOF =              0x01
AUTH_LOGON_SUCCESS =            0x03

AUTH_RECONNECT_CHALLENGE =      0x02
AUTH_RECONNECT_PROOF =          0x03

REALM_LIST =                    0x10

XFER_INITIATE =                 0x30
XFER_DATA =                     0x31
XFER_ACCEPT =                   0x32
XFER_RESUME =                   0x33
XFER_CANCEL =                   0x34


# ---------------------
# Client Packet Opcodes
# ---------------------
    

# ---------------------
# Server Packet Opcodes
# ---------------------



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

async def launch_wow_client(wow_path):
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

    # ----------
    # AUTH Phase
    # ----------

    authenticated = False
    r_logon_challenge = False
    r_logon_proof = False

    while not authenticated:

        auth_data = await reader.read(1024)
        if not auth_data:
            return
        debug_logging(auth_data)
        opcode = auth_data[0]
   
        if opcode == AUTH_LOGON_CHALLENGE and not r_logon_challenge:
            
            # Fudge - Accounts are all "ACCOUNT#" where # is 1 to 9
            # -----------------------------------------------------
            account = "ACCOUNT" + str(auth_data[len(auth_data)-1]-48)
            logging.info(f" Received login challenge for {account}")

            if account not in ("ACCOUNT1", 
                                "ACCOUNT2", 
                                "ACCOUNT3", 
                                "ACCOUNT4", 
                                "ACCOUNT5",
                                "ACCOUNT6",
                                "ACCOUNT7",
                                "ACCOUNT8",
                                "ACCOUNT9"):
                logging.info(f" Invalid account name")
                writer.write(b'\x00\x00')  # Failed
                await writer.drain()
                break

            key = make_key(verify(account))

            response = struct.pack(
                '<HBB32s32s16s',
                AUTH_LOGON_PROOF,
                0,
                32,
                os.urandom(32),
                key.to_bytes(32, 'big'),
                os.urandom(16)
            )

            logging.info(f" Sending login response")
            writer.write(response)
            await writer.drain()
            r_logon_challenge = True

        if opcode == AUTH_LOGON_PROOF and not r_logon_proof:
            logging.info(f" Received login proof")
            redirect = struct.pack('<H', AUTH_LOGON_SUCCESS) + b'\x01\x02\x03...'
            writer.write(redirect)
            await writer.drain()
            r_logon_proof = True

        authenticated = r_logon_challenge and r_logon_proof


    # WORLD Phase
    # -----------
    logging.info(" Client authenticated, switching to world protocol")
    while True:
        try:
            data = await reader.read(1024)
            if not data:
                break

            # Parse packet header
            # -------------------
            opcode, size = struct.unpack('<HH', data[:4])
            payload = data[4:4+size]
            logging.info(f" Received opcode: {hex(opcode)}, size: {size}, payload: {payload.hex()}")

            # Handle common world packets
            # ---------------------------
            if opcode == CMSG_PLAYER_LOGIN:
                logging.info(" Player login request")

                # Respond with empty character list
                # ---------------------------------
                response = struct.pack('<HH', SMSG_CHAR_ENUM, 0) + b'\x00'
                writer.write(response)
                await writer.drain()

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
        await launch_wow_client(TEC_PATH)
        await run_server()
       
    except Exception as e:
        logging.error(f" ERROR - {e}")

    finally:
        cleanup()

if __name__ == "__main__":
    asyncio.run(main())