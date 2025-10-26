import asyncio
import logging
import os
import struct
import subprocess
import hashlib
import random
from typing import Dict, Optional

DEBUG = True
TEC_PATH = 'd://Desktop/The Eternal Crusade/TEC.exe'

# WoW SRP6 constants
N = int((
    "894B645E89E1535BBDAD5B8B290650530801B18EBFBF5E8FAB3C82872A3E9BB7"
    "D714BE3DACD361896B6C39A0A5F0EF248B7F1B7B5B8CC9DC186248847531C84D"
), 16)
g = 7
k = 3

ACCOUNT = {
    "username": "ETERNAL",
    "password": "CRUSADE",
    "salt": os.urandom(32),
    "verifier": None
}

def int_to_bytes(value: int, length: int) -> bytes:
    """Convert a large integer to a byte string of specified length"""
    hex_str = format(value, 'x')
    # Ensure even length for hex conversion
    if len(hex_str) % 2 != 0:
        hex_str = '0' + hex_str
    byte_data = bytes.fromhex(hex_str)
    # Pad or truncate to desired length
    if len(byte_data) > length:
        return byte_data[-length:]
    else:
        return byte_data.rjust(length, b'\x00')

def calculate_srp_verifier():
    username = ACCOUNT["username"].upper()
    password = ACCOUNT["password"].upper()
    salt = ACCOUNT["salt"]
    
    # Calculate x = H(salt || H(username || ":" || password))
    hash_user_pass = hashlib.sha1(f"{username}:{password}".encode('ascii')).digest()
    x = hashlib.sha1(salt + hash_user_pass).digest()
    x = int.from_bytes(x, 'little')
    
    # v = g^x % N
    v = pow(g, x, N)
    
    # Convert to bytes
    ACCOUNT["verifier"] = int_to_bytes(v, 32)

calculate_srp_verifier()

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

# Opcodes
LOGON_CHALLENGE = 0x00
LOGON_PROOF = 0x01
RECONNECT_PROOF = 0x02
LOGON_SUCCESS = 0x03

C_REALM_LIST = 0x01
C_CHAR_ENUM = 0x037
C_PLAYER_LOGIN = 0x003D

S_REALM_LIST = 0x10
S_CHAR_ENUM = 0x003B

sessions: Dict[str, dict] = {}
wow_process: Optional[subprocess.Popen] = None

logging.info("======================================")
logging.info("The Eternal Crusade Pseudo-Server v1.0")
logging.info("======================================")

async def launch_client(wow_path: str):
    global wow_process
    if not os.path.exists(wow_path):
        raise FileNotFoundError(f"ERROR - TEC client not found at {wow_path}")
    wow_process = subprocess.Popen([wow_path])
    logging.info(f"Launched TEC client (PID: {wow_process.pid})")

def calculate_proofs(session: dict, A: bytes, client_proof: bytes) -> bool:
    """Verify client proof and calculate server proof"""
    try:
        username = session["username"].upper()
        salt = session["salt"]
        B = session["B"]
        K = session["K"]
        
        # Calculate M1 = H(H(N) xor H(g), H(username), salt, A, B, K)
        hN = hashlib.sha1(int_to_bytes(N, 32)).digest()
        hg = hashlib.sha1(int_to_bytes(g, 1)).digest()
        hNg = bytes([hN[i] ^ hg[i] for i in range(len(hN))])
        
        M1 = hashlib.sha1()
        M1.update(hNg)
        M1.update(hashlib.sha1(username.encode('ascii')).digest())
        M1.update(salt)
        M1.update(A)
        M1.update(B)
        M1.update(K)
        M1 = M1.digest()
        
        # Verify client proof matches
        if M1 != client_proof:
            logging.error("Client proof verification failed")
            return False
        
        # Calculate server proof M2 = H(A, M1, K)
        M2 = hashlib.sha1()
        M2.update(A)
        M2.update(M1)
        M2.update(K)
        session["M2"] = M2.digest()
        
        return True
    except Exception as e:
        logging.error(f"Error in calculate_proofs: {str(e)}")
        return False

async def handle_login_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    try:
        client_addr = writer.get_extra_info('peername')
        logging.info(f"Login client connected: {client_addr}")
        writer.transport.set_write_buffer_limits(high=0)  # Disable write buffering

        while True:
            # Read initial packet data with timeout
            try:
                data = await asyncio.wait_for(reader.read(1024), timeout=5.0)
                if not data:
                    logging.info("Client disconnected")
                    break
            except asyncio.TimeoutError:
                logging.warning("Timeout waiting for initial data")
                break
            
            logging.debug(f"Received initial data: {data.hex()}")
            
            # Parse opcode (big-endian for auth server)
            if len(data) < 1:
                logging.error("Packet too small for opcode")
                continue
                
            opcode = data[0]  # First byte is opcode
            logging.debug(f"Opcode: {opcode}")

            if opcode == LOGON_CHALLENGE:
                # Minimum size for LOGON_CHALLENGE header is 34 bytes
                if len(data) < 34:
                    logging.error("LOGON_CHALLENGE packet too small for header")
                    continue
                
                # Parse fixed header fields
                gamename = data[3:7].decode('ascii')
                version = struct.unpack('>BBB', data[7:10])
                build = struct.unpack('>H', data[10:12])[0]
                username_len = data[33]
                
                # Calculate total expected packet size
                # Header (34) + username + A (32)
                expected_size = 34 + username_len + 32
                
                # If we don't have the full packet, read more data with timeout
                if len(data) < expected_size:
                    remaining_bytes = expected_size - len(data)
                    logging.debug(f"Need {remaining_bytes} more bytes for complete packet")
                    try:
                        more_data = await asyncio.wait_for(reader.read(remaining_bytes), timeout=5.0)
                        if not more_data:
                            logging.error("Client disconnected while reading remaining data")
                            break
                        data += more_data
                        logging.debug(f"Complete packet: {data.hex()}")
                    except asyncio.TimeoutError:
                        logging.warning("Timeout waiting for remaining packet data")
                        break
                
                # Verify we have complete packet
                if len(data) < expected_size:
                    logging.error(f"Incomplete packet (got {len(data)}, expected {expected_size})")
                    continue
                
                # Extract username and A value
                username = data[34:34+username_len].decode('ascii', 'ignore').upper()
                a_start = 34 + username_len
                A = data[a_start:a_start+32]
                
                logging.info(f"Auth attempt from: {username} (Build: {build}, Game: {gamename})")
                logging.debug(f"Client A value: {A.hex()}")
                
                if username != ACCOUNT["username"]:
                    logging.warning(f"Unknown account: {username}")
                    response = struct.pack('>BB', LOGON_PROOF, 4)  # Unknown account error
                    writer.write(response)
                    await writer.drain()
                    continue
                
                # Generate session key and get verifier
                session_key = os.urandom(40)
                salt = ACCOUNT["salt"]
                verifier = ACCOUNT["verifier"]
                
                # Store session data
                session_id = os.urandom(16).hex()
                sessions[session_id] = {
                    "username": username,
                    "salt": salt,
                    "B": verifier,
                    "K": session_key,
                    "A": A
                }
                
                # Build and send challenge response
                # Structure: [opcode:1][error:1][B:32][g_len:1][g:1][N_len:1][N:32][salt:32][unk:16]
                response = struct.pack('>BB32sB1sB32s32s16s',
                    LOGON_PROOF,
                    0,            # Error code
                    verifier,     # B
                    1,            # g_len
                    g.to_bytes(1, 'big'),  # g
                    32,           # N_len
                    int_to_bytes(N, 32),  # N
                    salt,         # salt
                    session_key[:16]  # Session key (first half)
                )
                
                writer.write(response)
                await writer.drain()
                logging.debug(f"Sent LOGON_PROOF response: {response.hex()}")

                # Wait for client proof with timeout
                try:
                    proof_data = await asyncio.wait_for(reader.read(75), timeout=5.0)
                    if not proof_data:
                        logging.warning("No proof data received")
                        break
                    
                    logging.debug(f"Received proof: {proof_data.hex()}")
                    
                    if len(proof_data) < 36:
                        logging.error("Proof packet too small")
                        continue
                        
                    client_proof = proof_data[16:36]  # M1 is 20 bytes
                    
                    if not calculate_proofs(sessions[session_id], A, client_proof):
                        logging.warning("Invalid client proof")
                        response = struct.pack('>BB', LOGON_PROOF, 3)  # Invalid proof error
                        writer.write(response)
                        await writer.drain()
                        continue

                    # Send success with redirect
                    success_packet = struct.pack('>BBIBI', 
                        LOGON_SUCCESS,
                        0x00,  # Error code
                        0x00,  # Survey ID
                        0x00000000,  # Login flags
                        0x00,  # Unused
                        0x00000000  # Unused
                    ) + b'\x00' + b'127.0.0.1:8085\x00'
                    
                    writer.write(success_packet)
                    await writer.drain()
                    logging.info("Logon successful")

                except asyncio.TimeoutError:
                    logging.warning("Timeout waiting for client proof")
                    break

            elif opcode == C_REALM_LIST:
                logging.info("Sending realm list")
                realm_name = b'The Eternal Crusade\x00'
                realm_address = b'127.0.0.1:8085\x00'
                
                # Build realm packet
                realm_packet = struct.pack('<HBBHBBBBBB', 
                    S_REALM_LIST,
                    0,  # Placeholder for size
                    0,  # Padding
                    1,  # Realm count
                    0,  # Realm type (normal)
                    0,  # Is locked
                    0,  # Flags
                    0,  # Character count
                    0,  # Timezone
                    1   # Realm ID
                ) + realm_name + realm_address
                
                # Update size field (excluding opcode)
                size = len(realm_packet) - 3  # Exclude opcode and size fields
                realm_packet = realm_packet[:1] + struct.pack('>H', size) + realm_packet[3:]
                
                writer.write(realm_packet)
                await writer.drain()
                logging.info("Realm list sent")
                
    except Exception as e:
        logging.error(f"ERROR - handling login client: {str(e)}", exc_info=DEBUG)
    finally:
        writer.close()

async def handle_world_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
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
                # Build character enumeration packet
                char_packet = struct.pack('<H', S_CHAR_ENUM)
                
                # Character count (0 for empty list)
                char_packet += struct.pack('<B', 0)
                
                # If you wanted to add a character, you would add structures like:
                # for each character:
                # char_packet += struct.pack('<Q', guid)          # Character GUID
                # char_packet += name.encode('ascii') + b'\x00'   # Name
                # char_packet += struct.pack('<B', race)          # Race
                # char_packet += struct.pack('<B', class_)       # Class
                # char_packet += struct.pack('<B', gender)       # Gender
                # char_packet += struct.pack('<B', skin)         # Skin
                # char_packet += struct.pack('<B', face)         # Face
                # char_packet += struct.pack('<B', hair_style)   # Hair Style
                # char_packet += struct.pack('<B', hair_color)   # Hair Color
                # char_packet += struct.pack('<B', facial_hair)  # Facial Hair
                # char_packet += struct.pack('<B', level)        # Level
                # char_packet += struct.pack('<f', zone)         # Zone
                # char_packet += struct.pack('<f', x)            # X position
                # char_packet += struct.pack('<f', y)            # Y position
                # char_packet += struct.pack('<f', z)            # Z position
                # char_packet += struct.pack('<I', guild_id)     # Guild ID
                # char_packet += struct.pack('<I', flags)        # Character flags
                # char_packet += struct.pack('<I', customize)    # Customization flags
                # char_packet += struct.pack('<B', first_login)  # First login
                # char_packet += struct.pack('<I', pet_display) # Pet display ID
                # char_packet += struct.pack('<I', pet_level)    # Pet level
                # char_packet += struct.pack('<I', pet_family)   # Pet family
                
                writer.write(char_packet)
                await writer.drain()
                logging.info("Sent character list")
                
            # Add handling for other world opcodes as needed
                
    except Exception as e:
        logging.error(f"ERROR - handling world client: {str(e)}", exc_info=DEBUG)
    finally:
        logging.info(f"Client disconnected: {client_addr}")
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
        world_server.serve_forever())

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


