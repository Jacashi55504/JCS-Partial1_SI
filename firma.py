import Crypto.Util.number
import hashlib
import Crypto.Random
import PyPDF2

# Parámetro de exponenciación pública (Número de Fermat)
e = 65537  

# Generar claves para Alice
pA = Crypto.Util.number.getPrime(1024, randfunc=Crypto.Random.get_random_bytes)
qA = Crypto.Util.number.getPrime(1024, randfunc=Crypto.Random.get_random_bytes)
nA = pA * qA
phiA = (pA - 1) * (qA - 1)
dA = Crypto.Util.number.inverse(e, phiA)

# Generar claves para la Autoridad Certificadora (AC)
pAC = Crypto.Util.number.getPrime(1024, randfunc=Crypto.Random.get_random_bytes)
qAC = Crypto.Util.number.getPrime(1024, randfunc=Crypto.Random.get_random_bytes)
nAC = pAC * qAC
phiAC = (pAC - 1) * (qAC - 1)
dAC = Crypto.Util.number.inverse(e, phiAC)

# Cargar el archivo PDF y generar su hash
pdf_path = "NDA.pdf"  # Ruta del archivo
with open(pdf_path, "rb") as pdf_file:
    contenido = pdf_file.read()
    hM = int.from_bytes(hashlib.sha256(contenido).digest(), byteorder='big')

print("Hash del documento h(M):", hM)

# Alice firma el documento con clave hash con su clave privada
firma_Alice = pow(hM, dA, nA)
print("\nFirma de Alice:", firma_Alice)

# La Autoridad Certificadora verifica la firma de Alice
hM_verificado = pow(firma_Alice, e, nA)
print("\n¿Firma de Alice válida?:", hM == hM_verificado)

# La autoridad firma el documento
firma_AC = pow(hM, dAC, nAC)
print("\nFirma de la AC:", firma_AC)

# Bob verifica la firma de la autoridad
hM_verificado_AC = pow(firma_AC, e, nAC)
print("\n¿Firma de la AC válida?:", hM == hM_verificado_AC, "\n")
