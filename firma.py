# Firma digital usando RSA
# JCS

# Importar librerias

import Crypto.Util.number
import hashlib

# Para "e" usaremos el número 4 de Fermat
e = 65537

# Calculamos las llave publica de Alice
pA = Crypto.Util.number.getPrime(1024, randfunc=Crypto.Random.get_random_bytes)
qA = Crypto.Util.number.getPrime(1024, randfunc=Crypto.Random.get_random_bytes)

nA = pA * qA
print("\n", "RSA de Alice: ", nA)

pB = Crypto.Util.number.getPrime(1024, randfunc=Crypto.Random.get_random_bytes)
qB = Crypto.Util.number.getPrime(1024, randfunc=Crypto.Random.get_random_bytes)

nB = pB * qB
print("\n", "RSA de Bob: ", nB)

# Calcular llave privada de Alice:
phiA = (pA - 1 ) * (qA -1)

dA=Crypto.Util.number.inverse(e, phiA)
print("\n", "RSA Llave privada de Alice dA: ", dA)

# Calcular llave privada de Bob:
phiB= (pB - 1) * (qB - 1)

dB=Crypto.Util.number.inverse(e, phiB)
print("\n", "RSA Llave privada de Bob dB: ", dB)

mensaje= ("Hola mundo")
print(mensaje)

# Generar el hash del mensaje
hM= int.from_bytes(hashlib.sha256(mensaje.encode('utf-8')).digest(),byteorder='big')
print("\n" "Hash de hM: ", hM)

# Firmamos el hash usando la llave privada de Alice
sA = pow(hM, dA, nA)
print("\n", "Fimar: ", sA)

# Bob verifica la firma con la llave publica de Alice
hM1 = pow(sA, e, nA)
print("\n", "Fimar: ", hex(hM1))

# Verificar
print("\n", "Fimar valida: ", hM == hM1, "\n")