"""
per runnare " python3 decrypt_ecb_final.py ecb-out.txt " nel terminale
"""

import sys #legge riga di comando

######## CIPHER_TABLE e la sua sua inversa ########

CIPHER_TABLE = {
    0b0000: 0b1110,
    0b0001: 0b0100,
    0b0010: 0b1101,
    0b0011: 0b0001,
    0b0100: 0b0010,
    0b0101: 0b1111,
    0b0110: 0b1011,
    0b0111: 0b1000,
    0b1000: 0b0011,
    0b1001: 0b1010,
    0b1010: 0b0110,
    0b1011: 0b1100,
    0b1100: 0b0101,
    0b1101: 0b1001,
    0b1110: 0b0000,
    0b1111: 0b0111,
}


INV_SBOX = {v: k for k, v in CIPHER_TABLE.items()} 

#print(CIPHER_TABLE)
#print(INV_SBOX)

######## Funzioni #########

def read_cipher_nibbles(filename):
    """
    legge un file binario in blocchi di 8 bit, li converte in stringa '0/1',
    poi estrae nibble da 4 bit in lista di interi 0-15 #nibble significa mezzo byte (4 bit)
    """
    data = open(filename, "rb").read()

    bits = ""
    for byte in data:
        binary = format(byte, "08b")  # converte il byte in stringa binaria a 8 bit
        bits += binary
        
    out = []
    for i in range(0, len(bits), 4):
        gruppo = bits[i:i+4]         # 4 bit alla volta
        numero = int(gruppo, 2)      # da binario a intero
        out.append(numero)       
    return out

#print("output: ->", read_cipher_nibbles("ecb-out.txt"), "fine")

def nibbles_to_bytes(nibbles):
    """
    ricompone coppie di nibble in bytes
    """
    if len(nibbles) % 2 != 0:
        raise ValueError("Numero dispari di nibble")
    out = bytearray()
    for i in range(0, len(nibbles), 2):
        out.append((nibbles[i] << 4) | nibbles[i+1])
    return bytes(out)



def decrypt_ecb(nibbles, key):
    """
    Decrittazione ECB:
      per ogni nibble cifrato c: p = INV_SBOX[c ^ key]
    """
    pt = []
    for i in nibbles:
        xor_val = i ^ key                   # XOR tra nibble cifrato e chiave
        plain_nibble = INV_SBOX[xor_val]     # cerca nella tabella inversa
        pt.append(plain_nibble)
    return pt

######## Main ########

def main():
    filename = sys.argv[1]  # file dalla riga di comando 

    cipher_nibbles = read_cipher_nibbles(filename)  # legge i nibble cifrati dal file
    risultati = []

    # prova tutte le chiavi possibili (da 0 a 15)
    for key in range(16):
        pt_nibbles = decrypt_ecb(cipher_nibbles, key)
        pt_bytes = nibbles_to_bytes(pt_nibbles)             # converte i nibble decriptati in byte
        pt_text = pt_bytes.decode("iso-8859-15", errors="replace")      # trasfroma in testo

        # salva il risultato per quella chiave
        risultati.append((key, pt_text))

    # mostra i risultati
    print("=== Possibili plaintext ===")
    for e in risultati:
        chiave = e[0]
        testo = e[1]
        print("")
        print("-- Chiave:", chiave)
        print(testo)


if __name__ == "__main__":
    main()