import struct
import sys

FIELD_TYPE_STRING = 0x1
FIELD_TYPE_INTEGER = 0x2
FIELD_TYPE_ADDRESS = 0x3
FIELD_TYPE_BYTES = 0x4
FIELD_TYPE_FLAG = 0x5

# [FIELD_NAME, FIELD_TYPE, OFFSET, SIZE, IS_ENCRYPTED, KEY, IS_DOUBLE_ENCRYPTED, SECOND_KEY]
CONFIG_MAP = [
    ['Mutex Name',        FIELD_TYPE_STRING,  0x014, 0x028, True,  0x77, False, 0x00],
    ['C2',                FIELD_TYPE_ADDRESS, 0x03C, 0x0DC, True,  0xCE, False, 0x00], 
    ['Service Name',      FIELD_TYPE_STRING,  0x120, 0x028, True,  0xF7, False, 0x00],
    ['Loader DLL Name',   FIELD_TYPE_STRING,  0x148, 0x028, True,  0x02, False, 0x00],
    ['Sleep Time',        FIELD_TYPE_INTEGER, 0x170, 0x004, True,  0x89, False, 0x00],  
    ['Unused (A)',        FIELD_TYPE_BYTES,   0x175, 0x104, True,  0x0B, True,  0xF5],
    ['Unknown File Name', FIELD_TYPE_STRING,  0x279, 0x028, True,  0x0B, False, 0x00],
    ['Data File Key',     FIELD_TYPE_BYTES,   0x2A1, 0x001, False, 0x00, False, 0x00],
    ['Unused (B)',        FIELD_TYPE_BYTES,   0x2A3, 0x104, True,  0xCE, False, 0x00],
    ['Data File Name',    FIELD_TYPE_STRING,  0x3A7, 0x028, True,  0xCE, False, 0x00],
    ['Proxy Setting',     FIELD_TYPE_FLAG,    0x3CF, 0x001, False, 0x00, False, 0x00],
    ['Proxy Info',        FIELD_TYPE_ADDRESS, 0x3D0, 0x02C, True,  0xBB, False, 0x00],
    ['Proxy Username',    FIELD_TYPE_STRING,  0x3FC, 0x018, True,  0xBB, True,  0xBB],
    ['Proxy Password',    FIELD_TYPE_STRING,  0x414, 0x018, False, 0x00, False, 0x00],
]

CONFIG_OFFSET = 0x2200
CONFIG_SIZE = 0x42C


def custom_rc4(enc_text, key, value):
    S = [0] * 256
    dec_text = bytearray(len(enc_text))

    for i in range(256):
        S[i] = i

    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 0xFF
        tmp = S[i]
        S[i] = S[j]
        S[j] = tmp

    rbp = 0
    for i in range(len(enc_text)):
        tmp1 = S[(i + 1) & 0xFF]
        tmp2 = S[(tmp1 + rbp) & 0xFF]
        
        S[(i + 1) & 0xFF] = tmp2
        S[(tmp1 + rbp) & 0xFF] = tmp1
        
        rbp = (tmp1 + rbp) & 0xFF
        result = S[(S[(i + 1) & 0xFF] + tmp1) & 0xFF]
        
        if (value & 0x80) != 0:
            dec_text[i] = (value + (enc_text[i] ^ result)) & 0xFF
        else:
            dec_text[i] = result ^ ((enc_text[i] + value) & 0xFF)
    
    return dec_text


def parse_address_object(buf):
    addresses = []
    for i in range(0, len(buf), 0x2C):
        addr = buf[i:i+0x2C]
        host = addr[:0x28].rstrip(b'\x00').decode()
        port = struct.unpack('<I', addr[0x28:])[0]
        addresses.append((host, port))
    
    return addresses


def main():
    if len(sys.argv) != 2:
        print(f'[-] Usage: python {sys.argv[0]} [KIVARS_LOADER_FILE]')
        exit(1)
    
    print(f'[*] Decrypting Kivars config in "{sys.argv[1]}" ...')
    
    # Read config from Kivars Loader file
    with open(sys.argv[1], 'rb') as loader_file:
        loader_file.seek(CONFIG_OFFSET)
        config_blob = loader_file.read(CONFIG_SIZE)
    
    # Calculate RC4 key based on first 20-bytes of blob
    key = custom_rc4(config_blob[0x004:0x014], config_blob[0x000:0x004], 223)
    print(f'[+] Custom RC4 Key: {key.hex()}')
    
    # Parse config fields in the blob
    for field_info in CONFIG_MAP:
        enc = config_blob[field_info[2]:field_info[2]+field_info[3]]
        if field_info[1] == FIELD_TYPE_FLAG:
            if enc == b'\x00':
                dec = 'NO_PROXY_DIRECT_CONNECT'
            elif enc == b'\x01':
                dec = 'USE_PROXY_INFO_IN_REGISTRY'
            elif enc == b'\x02':
                dec = 'USE_PROXY_INFO_IN_CONFIG'
        else:
            if field_info[4]:
                dec = custom_rc4(enc, key, field_info[5])
            else:
                dec = enc
            
            if field_info[6]:
                dec = custom_rc4(dec, key, field_info[7])
            
            if field_info[1] == FIELD_TYPE_STRING:
                dec = "'" + dec.rstrip(b'\x00').decode() + "'"
            elif field_info[1] == FIELD_TYPE_ADDRESS:
                dec = parse_address_object(dec)
            elif field_info[1] == FIELD_TYPE_INTEGER:
                dec = struct.unpack('<I', dec)[0]
            elif field_info[1] == FIELD_TYPE_BYTES:
                dec = dec.hex()
        
        print(f'[+] {field_info[0]} : {dec}')


if __name__ == '__main__':
    main()
