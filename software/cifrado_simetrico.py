import base64
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256

class cifradoSimetrico:

    @staticmethod
    def derivar_clave(password: str, sal: bytes, dkLen: int = 32) -> bytes:
        # Esta es la lógica que estaba en Control_usuarios, ahora centralizada.
        return PBKDF2(password, sal, dkLen=dkLen, count=1000000, hmac_hash_module=SHA256)

    @staticmethod
    def cifrar(texto, clave):
        # Cifrado del .json con AES_GCM_128
        if isinstance(texto, str):
            datos = texto.encode("utf-8")

        # Semilla de cifrado
        nonce = get_random_bytes(12)  
        # Objeto de cifrado                             
        cipher = AES.new(clave, AES.MODE_GCM, nonce=nonce) 
        # Mensaje cifrado y tag de autenticidad   
        ciphertext, tag = cipher.encrypt_and_digest(datos)  
        # Se junta todo en un bloque de datos de bytes        
        bloque_datos = nonce + tag + ciphertext 
        return base64.b64encode(bloque_datos).decode('utf-8')

    @staticmethod
    def descifrar(texto_cifrado, clave):
        # Descifrado del .json
        try:
            # Se realiza el descifrado
            bloque_datos = base64.b64decode(texto_cifrado)
            # Recoge los bytes de cada parte del texto cifrado
            nonce = bloque_datos[:12]
            tag = bloque_datos[12:28]
            ciphertext = bloque_datos[28:]
            cipher = AES.new(clave, AES.MODE_GCM, nonce=nonce)
            # Desencripta y autentica el texto para así descifrarlo
            datos = cipher.decrypt_and_verify(ciphertext, tag)
            return datos.decode("utf-8")
        except:
            return None
