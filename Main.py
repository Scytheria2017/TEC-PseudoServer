import asyncio
import logging
import os
import struct
import subprocess
from hashlib import sha1

# Configuration
DEBUG = True
CLIENT_PATH = "d://Desktop/The Eternal Crusade/TEC.exe"
ACCOUNT = {"username": "Eternal", "password": "Crusade"}

# Opcodes (from 3.3.5a)
AUTH_LOGON_CHALLENGE = 0x00
AUTH_LOGON_PROOF = 0x01
REALM_LIST = 0x10
CHAR_ENUM = 0x003B
PLAYER_LOGIN = 0x003D

# Setup logging
logging.basicConfig(
    level=logging.DEBUG if DEBUG else logging.INFO,
    format='%(asctime)s - %(message)s',
    handlers=[
        logging.FileHandler('Server.log', mode='w'),
        logging.StreamHandler()
    ]
)

async def handle_auth(reader, writer):
    """Simplified authentication handler"""
    try:
        # Read auth challenge
        data = await reader.read(1024)
        if len(data) < 5:
            return
            
        # Parse header (size + opcode)
        size = struct.unpack('<H', data[:2])[0]
        opcode = data[2]
        
        if opcode == AUTH_LOGON_CHALLENGE:
            # Extract username (byte 5 to 5+username_len)
            username_len = data[4]
            username = data[5:5+username_len].decode('ascii')
            
            if username.upper() != ACCOUNT["username"].upper():
                logging.error("Invalid username")
                return

            # Send auth challenge response (simplified SRP6)
            response = struct.pack(
                '<HBB',
                1 + 1 + 32 + 32 + 16 + 1,  # Size
                AUTH_LOGON_CHALLENGE,      # Opcode
                0x00                       # Error (success)
            ) + b'\x11'*32 + b'\x22'*32 + b'\x33'*16 + b'\x00'  # Fake SRP data
            
            writer.write(response)
            await writer.drain()

            # Wait for client proof (we don't actually verify it)
            proof_data = await reader.read(1024)
            if len(proof_data) < 75:
                return

            # Send success with redirect
            success_packet = struct.pack(
                '<HBBIBI',
                1 + 1 + 4 + 1 + 4,  # Size
                AUTH_LOGON_PROOF,    # Opcode
                0x00,               # Error (success)
                0x00,               # Billing flags
                0x00000000,         # Billing time
                0x00,               # Billing type
                0x00000000          # Billing time
            ) + b'\x00' + b'127.0.0.1:8085\x00'
            
            writer.write(success_packet)
            await writer.drain()
            logging.info("Auth successful - redirect sent")

    except Exception as e:
        logging.error(f"Auth error: {e}")
    finally:
        writer.close()

async def handle_world(reader, writer):
    """World server handler"""
    try:
        # First packet should be realm list request
        data = await reader.read(1024)
        if not data:
            return
            
        size = struct.unpack('<H', data[:2])[0]
        opcode = data[2]
        
        if opcode == REALM_LIST:
            # Send realm list (1 realm)
            realm_packet = struct.pack(
                '<HBBHBBBBBB',
                1 + 1 + 2 + 1 + 1 + 1 + 1 + 1 + 1,  # Size
                REALM_LIST,         # Opcode
                1,                  # Realm count
                0,                  # Padding
                0,                  # Realm type (normal)
                1,                  # Flags (1 = online)
                0,                  # Locked (0 = unlocked)
                0,                  # Timezone
                0,                  # Population
                0                   # Unknown
            ) + b'The Eternal Crusade\x00' + b'127.0.0.1:8085\x00'
            
            writer.write(realm_packet)
            await writer.drain()
            logging.info("Sent realm list")

            # Next packet should be player login
            data = await reader.read(1024)
            if not data:
                return
                
            size = struct.unpack('<H', data[:2])[0]
            opcode = struct.unpack('<H', data[2:4])[0]
            
            if opcode == PLAYER_LOGIN:
                # Send empty character list
                char_packet = struct.pack(
                    '<HHB',
                    1 + 2 + 1,  # Size
                    CHAR_ENUM,  # Opcode
                    0           # Character count
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
    if os.path.exists(CLIENT_PATH):
        subprocess.Popen([CLIENT_PATH])
    
    # Run servers
    await run_servers()

if __name__ == "__main__":
    asyncio.run(main())
