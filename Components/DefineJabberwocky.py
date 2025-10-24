import inspect
import json
import struct


# ================================
# jab - data encryption/decryption
# ================================

# Receives a variable, data, of any type
# Encrypts/decrypts data (using XOR method)
# 


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
                key = name + str(len(name)) + key
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