import TEC-Database
import TEC-Jabberwocky
import TEC-Logging
import TEC-Opcodes

import asyncio
import logging
import os
import struct
import subprocess


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

    authenticated = False

    # AUTH Phase
    # ----------
    while not authenticated:
        try:
            auth_data = await reader.read(1024)
            if not auth_data:
                return
            debug_logging(auth_data)

            opcode = auth_data[0]
   
            if opcode == Opcode.AUTH_LOGON_CHALLENGE:
                logging.info(f" Received login challenge")
                response = struct.pack('<H', Opcode.AUTH_LOGON_PROOF) + b'\x00\x0000000000000000000000000000000000000000\x00000000\x00000000\x0000'
                logging.info(f" Sending login response")
                writer.write(response)
                await writer.drain()

            if opcode == Opcode.AUTH_LOGON_PROOF:
                logging.info(f" Received login proof")
                redirect = struct.pack('<H', Opcode.AUTH_LOGON_SUCCESS) + b'\x01\x02\x03...'
                writer.write(redirect)
                await writer.drain()
                authenticated = True

        except Exception as e:
            logging.error(f" ERROR - {e}")

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
            if opcode == Opcode.CMSG_PLAYER_LOGIN:
                logging.info(" Player login request")

                # Respond with empty character list
                # ---------------------------------
                response = struct.pack('<HH', Opcode.SMSG_CHAR_ENUM, 0) + b'\x00'
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
        logging.info(" Terminated WoW client process")

async def main():
    try:
        wow_path = 'd://Desktop/The Eternal Crusade/TEC.exe'
        await launch_wow_client(wow_path)
        await run_server()
       
    except Exception as e:
        logging.error(f" ERROR - {e}")

    finally:
        cleanup()

if __name__ == "__main__":
    asyncio.run(main())