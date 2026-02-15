class RC4:
    def __init__(self,key):
        self.S = list(range(256))#Crée le tableau d'état S avec les valeurs [0,1,2,...,155]
        self.i = 0
        self.j = 0
        self.key_schedule(key)

    #KSA
    def key_schedule(self, key):
        j = 0
        key = [ord(c) for c in key]
        for i in range (256):
            j = (j + self.S[i] + key[i % len(key)]) % 256
            self.S[i], self.S[j] = self.S[j], self.S[i]

    # PRGA
    def generate(self, n):
        output = bytearray()
        for _ in range(n):
            self.i = (self.i + 1) % 256
            self.j = (self.j + self.S[self.i]) % 256
            self.S[self.i], self.S[self.j] = self.S[self.j], self.S[self.i]
            K = self.S[(self.S[self.i] + self.S[self.j]) % 256]
            output.append(K)
        return bytes(output)

# Génération de 1000 octets pseudo-aléatoires
rc4 = RC4("secretkey")
keystream = rc4.generate(100000) # 100k bytes = 800k bits


with open("rc4.bin", "wb") as f:
    f.write(keystream)

print("Fichier rc4.bin généré :", len(keystream), "octets")