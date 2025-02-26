import Crypto.Util.number
import hashlib
import Crypto.Random

# Se utiliza el número 4 de Fermat 
e = 65537

# Generar claves RSA de Alice
pA = Crypto.Util.number.getPrime(1024, randfunc=Crypto.Random.get_random_bytes)
qA = Crypto.Util.number.getPrime(1024, randfunc=Crypto.Random.get_random_bytes)
nA = pA * qA
phiA = (pA - 1) * (qA - 1)
dA = Crypto.Util.number.inverse(e, phiA)

# Generar claves RSA de Bob
pB = Crypto.Util.number.getPrime(1024, randfunc=Crypto.Random.get_random_bytes)
qB = Crypto.Util.number.getPrime(1024, randfunc=Crypto.Random.get_random_bytes)
nB = pB * qB
phiB = (pB - 1) * (qB - 1)
dB = Crypto.Util.number.inverse(e, phiB)

# Aprox 1050 caracteres
mensaje = "Hola, este es un mensaje cifrado con RSA. " * 89  # 12Char * 89 = 1.068Char 
print("Mensaje original:", mensaje)

# Generar el hash del mensaje original
hM = int.from_bytes(hashlib.sha256(mensaje.encode()).digest(), byteorder='big')
print("\nHash original h(M):", hM)

# Se divide el mensaje en fragmentos de 128 caracteres
fragmentos = [mensaje[i:i + 128] for i in range(0, len(mensaje), 128)]
mensajes_cifrados = []

# Cifrado y desifrado en loop for
# Alice cifra con la clave pública de Bob
for fragmento in fragmentos:
    m_int = int.from_bytes(fragmento.encode(), byteorder='big')
    c = pow(m_int, e, nB)
    mensajes_cifrados.append(c)

print("\nMensajes cifrados enviados a Bob:", mensajes_cifrados)

# Bob descifra con su clave privada
mensajes_descifrados = []
for c in mensajes_cifrados:
    m_int = pow(c, dB, nB)
    fragmento_descifrado = m_int.to_bytes((m_int.bit_length() + 7) // 8, byteorder='big').decode()
    mensajes_descifrados.append(fragmento_descifrado)

# Reconstruir el mensaje completo
mensaje_reconstruido = ''.join(mensajes_descifrados)
print("\nMensaje reconstruido:", mensaje_reconstruido)

# Generar hash del mensaje reconstruido para comparar con el hash anterior
hM1 = int.from_bytes(hashlib.sha256(mensaje_reconstruido.encode()).digest(), byteorder='big')

print("\nHash del mensaje recibido h(M):", hM1)
print("\nHash original h(M):", hM)

# Verificación de integridad
print("\n¿El mensaje es igual?", hM == hM1)
