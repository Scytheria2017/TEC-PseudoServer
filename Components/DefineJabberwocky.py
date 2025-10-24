import inspect
import json
import struct


# ========================================
# jabberwocky - data encryption/decryption
# ========================================

# Receives a variable, data, of any type
# Encrypts/decrypts data (using XOR method)
# key is text of "Jabberwocky" fronted by the
# variable's actual name

# Example
# -------
# ItemName = "Sword of Chaos"               
# print(ItemName)                       ---> Sword of Chaos
# ItemName = jabberwocky(ItemName)
# print(ItemName)                       ---> !@#$%^&*@!#@+? (garbage)
# ItemName = jabberwocky(ItemName)
# print(ItemName)                       ---> Sword of Chaos


def jabberwocky(data):
    key =  "TwasbrilligandtheslithytovesDidgyreandgimbleinthewabeAllmimsyweretheborogovesAndthemomerathsoutgrabe"
    key += "BewaretheJabberwockmysonThejawsthatbitetheclawsthatcatchBewaretheJubjubbirdandshunThefrumiousBandersnatch"
    key += "HetookhisvorpalswordinhandLongtimethemanxomefoehesoughtSorestedhebytheTumtumtreeAndstoodawhileinthought"
    key += "AndasinuffishthoughthestoodTheJabberwockwitheyesofflameCamewhifflingthroughthetulgeywoodAndburbledasitcame"
    key += "OnetwoOnetwoAndthroughandthroughThevorpalbladewentsnickersnackHeleftitdeadandwithitsheadHewentgalumphingback"
    key += "AndhastthouslaintheJabberwockCometomyarmsmybeamishboyOfrabjousdayCalloohCallayHechortledinhisjoy"

    frame = inspect.currentframe()
    try:
        for name, value in frame.f_back.f_locals.items():
            if value is data:
                name = name.upper()
                name = name.replace("A", "0")
                name = name.replace("B", "12")
                name = name.replace("C", "345")
                name = name.replace("D", "6789")
                name = name.replace("E", "1")
                name = name.replace("F", "23")
                name = name.replace("G", "456")
                name = name.replace("H", "7890")
                name = name.replace("I", "2")
                name = name.replace("J", "34")
                name = name.replace("K", "567")
                name = name.replace("L", "8901")
                name = name.replace("M", "3")
                name = name.replace("N", "45")
                name = name.replace("O", "678")
                name = name.replace("P", "9012")
                name = name.replace("Q", "4")
                name = name.replace("R", "56")
                name = name.replace("S", "789")                
                name = name.replace("T", "0123")
                name = name.replace("U", "5")
                name = name.replace("V", "67")
                name = name.replace("W", "890")
                name = name.replace("X", "1234")
                name = name.replace("Y", "6")
                name = name.replace("Z", "78")
                spliced = []
                for a, b in zip(name, key):
                    spliced.append(a)
                    spliced.append(b)
                spliced.append(key[len(name):])
                key = ''.join(spliced)
                print(key)
                break
    finally:
        del frame

    key_bytes = key.encode('utf-8')
    if not key_bytes:
        return data

    def xor_bytes(input_bytes):
        result = bytearray()
        for i in range(len(input_bytes)):
            key_byte = key_bytes[i % len(key_bytes)]
            result.append(input_bytes[i] ^ key_byte)
        return bytes(result)

    if isinstance(data, (str, bytes, bytearray)):
        if isinstance(data, str):
            scrambled = xor_bytes(data.encode('utf-8')).decode('latin-1')
        else:
            scrambled = xor_bytes(bytes(data))
        return scrambled
   
    elif isinstance(data, (int, float, bool)):
        if isinstance(data, int):
            try:
                packed = struct.pack('q', data)
            except struct.error:
                packed = data.to_bytes((data.bit_length() + 7) // 8, 'big')
            scrambled_bytes = xor_bytes(packed)
            try:
                return struct.unpack('q', scrambled_bytes)[0]
            except struct.error:
                return int.from_bytes(scrambled_bytes, 'big')
        elif isinstance(data, float):
            packed = struct.pack('d', data)
            scrambled_bytes = xor_bytes(packed)
            return struct.unpack('d', scrambled_bytes)[0]
        elif isinstance(data, bool):
            return not data if xor_bytes(bytes([data]))[0] else data
   
    elif isinstance(data, (list, tuple, set)):
        scrambled = [jabberwocky(item) for item in data]
        return type(data)(scrambled)
   
    elif isinstance(data, dict):
        return {jabberwocky(k): jabberwocky(v) for k, v in data.items()}
   
    elif data is None:
        return None
   
    else:
        try:
            json_str = json.dumps(data)
            scrambled_bytes = xor_bytes(json_str.encode('utf-8'))
            return json.loads(scrambled_bytes.decode('latin-1'))
        except (TypeError, json.JSONDecodeError):
            return data




ItemName = "Sword of Chaos"               
print(ItemName)                       
ItemName = jabberwocky(ItemName)
print(ItemName)                       
ItemName = jabberwocky(ItemName)
print(ItemName)                       