import asyncio
import logging
import os
import struct
import subprocess

# Configuration
DEBUG = True
TEC_PATH = 'd://Desktop/The Eternal Crusade/TEC.exe'
ACCOUNT = {"username": "Eternal", "salt": b'\x01'*32}

# Opcodes
LOGON_CHALLENGE = 0x00
LOGON_PROOF = 0x01
LOGON_SUCCESS = 0x03
C_REALM_LIST = 0x01
C_PLAYER_LOGIN = 0x003D
S_REALM_LIST = 0x10
S_CHAR_ENUM = 0x003B

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(message)s',
    handlers=[
        logging.FileHandler('Server.log', mode='w'),
        logging.StreamHandler()
    ]
)

async def handle_auth(reader, writer):
    """Handles authentication on port 3724"""
    try:
        # Read auth challenge
        data = await reader.read(1024)
        if len(data) < 5:
            return
            
        # Check opcode (first 2 bytes)
        opcode, = struct.unpack('<H', data[:2])
        
        if opcode == LOGON_CHALLENGE:
            # Extract username (byte 33 to 33+username_len)
            username_len = data[32]
            username = data[33:33+username_len].decode('ascii')
            
            if username.upper() != ACCOUNT["username"].upper():
                logging.error("Invalid username")
                return

            # Send auth challenge response
            response = struct.pack(
                '<HBB32s32s16s',
                LOGON_PROOF,    # Opcode
                0x00,           # Error
                32,             # Salt size
                ACCOUNT["salt"], # Salt
                b'\x11'*32,     # Server public key (B)
                b'\x22'*16      # Generator
            )
            writer.write(response)
            await writer.drain()

            # Wait for client proof
            proof_data = await reader.read(75)
            if len(proof_data) < 75:
                return

            # Send success with redirect
            success_packet = struct.pack(
                '<HBBIBI',
                LOGON_SUCCESS,
                0x00,          # Error
                0x00,          # Billing flags
                0x00000000,    # Billing time
                0x00,          # Billing type
                0x00000000     # Billing time
            ) + b'\x00' + b'127.0.0.1:8085\x00'
            
            writer.write(success_packet)
            await writer.drain()
            logging.info("Auth successful - redirect sent")

    finally:
        writer.close()

async def handle_world(reader, writer):
    """Handles world server on port 8085"""
    try:
        # First packet should be realm list request
        data = await reader.read(1024)
        if not data:
            return
            
        opcode, = struct.unpack('<H', data[:2])
        
        if opcode == C_REALM_LIST:
            # Send realm list (1 realm)
            realm_packet = struct.pack(
                '<HBBHBBBBBB',
                S_REALM_LIST,   # Opcode
                1,              # Realm count
                0,              # Padding
                0,              # Realm type (normal)
                1,              # Flags (1 = online)
                0,              # Locked (0 = unlocked)
                0,              # Timezone
                0,              # Population
                0               # Unknown
            ) + b'The Eternal Crusade\x00' + b'127.0.0.1:8085\x00'
            
            writer.write(realm_packet)
            await writer.drain()
            logging.info("Sent realm list")

            # Next packet should be player login
            data = await reader.read(1024)
            if not data:
                return
                
            opcode, = struct.unpack('<H', data[:2])
            
            if opcode == C_PLAYER_LOGIN:
                # Send empty character list
                char_packet = struct.pack(
                    '<HHB',
                    S_CHAR_ENUM,
                    1,      # Size byte
                    0       # 0 characters
                )
                writer.write(char_packet)
                await writer.drain()
                logging.info("Sent empty character list")

    except Exception as e:
        logging.error(f"World error: {e}")
    finally:
        writer.close()

async def run_servers():
    # Start both servers
    auth_server = await asyncio.start_server(
        handle_auth, '0.0.0.0', 3724)
    world_server = await asyncio.start_server(
        handle_world, '0.0.0.0', 8085)

    logging.info("Servers running:")
    logging.info(f"- Auth: 0.0.0.0:3724")
    logging.info(f"- World: 0.0.0.0:8085")
    
    async with auth_server, world_server:
        await asyncio.gather(
            auth_server.serve_forever(),
            world_server.serve_forever()
        )

async def main():
    # Launch client
    if os.path.exists(TEC_PATH):
        subprocess.Popen([TEC_PATH])
    
    # Run servers
    await run_servers()

if __name__ == "__main__":
    asyncio.run(main())
