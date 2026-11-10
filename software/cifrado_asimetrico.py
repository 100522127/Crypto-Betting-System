import json
import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
import base64
from .firma_certificados import FirmaCertificados

class cifradoAsimetrico:

    def __init__(self):
        self.base_dir = "Practica"
        self.carpeta_llaves = os.path.join(self.base_dir, "llaves")
        self.carpeta_resguardos = os.path.join(self.base_dir, "resguardos")
        os.makedirs(self.carpeta_llaves, exist_ok=True)
        os.makedirs(self.carpeta_resguardos, exist_ok=True)
        self.gestor_certificados = FirmaCertificados()
    
    def generar_claves_usuario(self, nombre_jugador, password):
        # Genera un par de claves RSA (2048 bits) para el usuario si no existen y usa la CA para firmar su certificado
        carpeta_usuario = os.path.join(self.carpeta_llaves, nombre_jugador)
        os.makedirs(carpeta_usuario, exist_ok=True)

        ruta_privada = os.path.join(carpeta_usuario, "private.pem")
        ruta_certificado = os.path.join(carpeta_usuario, "certificado.pem")

        # Solo generar si no existen
        if os.path.exists(ruta_privada) and os.path.exists(ruta_certificado):
            return

        key = RSA.generate(2048)
        clave_privada_cifrada = key.export_key(passphrase=password, pkcs=8, protection="scryptAndAES128-CBC")
        with open(ruta_privada, "wb") as f:
            f.write(clave_privada_cifrada)

        self.gestor_certificados.emitir_certificado(nombre_jugador, password)
    
    # Para cifrar el resguardo (proteger los datos de la apuesta)
    def cifrar_resguardo(self, data: dict, nombre_jugador: str) -> str:
        ruta_certificado = os.path.join(self.carpeta_llaves, nombre_jugador, "certificado.pem")
        public_key = self.gestor_certificados.obtener_publica_de_certificado(ruta_certificado)
        if public_key is None:
             raise ValueError(f"Error: No se pudo obtener la clave pública del certificado.")
        cipher = PKCS1_OAEP.new(public_key)
        json_data = json.dumps(data, separators=(",", ":")).encode("utf-8")
        cifrado = cipher.encrypt(json_data)
        return base64.b64encode(cifrado).decode("utf-8")
    
    # Para descifrar el resguardo (recuperar los datos de la apuesta)
    def descifrar_resguardo(self, resguardo_cifrado_b64: str, nombre_jugador: str, password: str) -> dict:
        ruta_privada = os.path.join(self.carpeta_llaves, nombre_jugador, "private.pem")
        with open(ruta_privada, "rb") as f:
            try:
                private_key = RSA.import_key(f.read(), passphrase=password)
            except ValueError:
                print("Error: contraseña incorrecta. No se puede acceder a la clave privada.")
                return None, None
        cifrado_bytes = base64.b64decode(resguardo_cifrado_b64)
        cipher = PKCS1_OAEP.new(private_key)
        descifrado_bytes = cipher.decrypt(cifrado_bytes)
        json_data = descifrado_bytes.decode("utf-8")
        return json.loads(json_data), json_data
    
    def generar_hash_resguardo(self, apuesta: dict) -> str:
        # Genera hash SHA256 del resguardo original
        json_data = json.dumps(apuesta, sort_keys=True).encode("utf-8")
        hash_obj = SHA256.new(json_data)
        return hash_obj.hexdigest()

    def guardar_hash_resguardo(self, nombre_jugador, hash_hex, timestamp):
        # Guardar hash del resguardo ya cifrado (verifica su integridad)
        carpeta_usuario = os.path.join(self.carpeta_resguardos, nombre_jugador)
        os.makedirs(carpeta_usuario, exist_ok=True)

        ruta_hash = os.path.join(carpeta_usuario, f"hash_{timestamp}.txt")

        with open(ruta_hash, "w") as f:
            f.write(hash_hex)

        print(f"Hash del resguardo guardado en {ruta_hash}")
    
    def cargar_hash_resguardo(self, nombre_jugador: str, timestamp: str) -> str:
        # Cargar el hash del resguardo para realizar la operación que sea
        ruta_hash = os.path.join(self.carpeta_resguardos, nombre_jugador, f"hash_{timestamp}.txt")
        print(ruta_hash)
        if os.path.exists(ruta_hash):
            with open(ruta_hash, "r") as f:
                return f.read()
        return None
    
    def verificar_hash_resguardo(self, hash_original, hash_guardado) -> bool:
        #Compara el hash guardado con el hash del resguardo descifrado
        return hash_original == hash_guardado
