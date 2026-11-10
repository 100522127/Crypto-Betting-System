import os
import json
import base64
import subprocess
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
from Crypto.PublicKey import RSA

class FirmaCertificados:

    def __init__(self):
        self.base_dir = "Practica"
        self.openssl_bin = r"C:\Program Files\Git\usr\bin\openssl.exe"
        self.carpeta_llaves = os.path.join(self.base_dir, "llaves")
        self.carpeta_ca = os.path.join(self.base_dir, "CA")
        self.ruta_ca_cert = os.path.join(self.carpeta_ca, "ca.pem")
        self.ruta_ca_key = os.path.join(self.carpeta_ca, "ca.key")

        os.makedirs(self.carpeta_llaves, exist_ok=True)
    
    # Código para la ejecución de comandas en terminal
    def _ejecutar_comando(self, comando):
        try:
            resultado = subprocess.run(
                comando,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            return resultado.stdout
        except subprocess.CalledProcessError as e:
            print(f"Error al ejecutar el comando en OpenSSL: {e.stderr}")
            return None
        except FileNotFoundError:
            print("ERROR: El comando 'openssl' no fue encontrado en el PATH.")
            return None

    # Para la emisión de certificados por cada jugador
    def emitir_certificado(self, nombre_jugador: str, password: str):
        """Genera el CSR y lo firma con la CA."""
        carpeta_usuario = os.path.join(self.carpeta_llaves, nombre_jugador)
        ruta_privada = os.path.join(carpeta_usuario, "private.pem")
        ruta_solicitud = os.path.join(carpeta_usuario, "solicitud.csr")
        ruta_certificado = os.path.join(carpeta_usuario, "certificado.pem")

        # Solo generar si no existen
        if os.path.exists(ruta_certificado):
            return

        # Se crea la soliicitud de firma del certificado
        self._ejecutar_comando([
            self.openssl_bin, "req", "-new", 
            "-key", ruta_privada, 
            "-passin", f"pass:{password}",
            "-out", ruta_solicitud,
            "-subj", f"/CN={nombre_jugador}"
        ])

        # Se firma con la CA
        self._ejecutar_comando([
            self.openssl_bin, "x509", "-req", 
            "-in", ruta_solicitud,
            "-CA", self.ruta_ca_cert, 
            "-CAkey", self.ruta_ca_key, 
            "-passin", f"pass:{password}",
            "-CAcreateserial",
            "-out", ruta_certificado, 
            "-days", "365", 
            "-sha256"
        ])

        if os.path.exists(ruta_solicitud):
            os.remove(ruta_solicitud)
        print(f"Certificado de {nombre_jugador} emitido: {ruta_certificado}")

    # Con esta función se extrae la clave pública para realizar operaciones
    def obtener_publica_de_certificado(self, ruta_certificado):
        if not os.path.exists(ruta_certificado):
            return None
        pem_publica = self._ejecutar_comando([
            self.openssl_bin, "x509",
            "-in", ruta_certificado, 
            "-pubkey", "-noout"
        ])
        if pem_publica:
            return RSA.import_key(pem_publica)
        return None
    
    def firmar_resguardo(self, apuesta: dict, nombre_jugador: str, password: str) -> str:
        # Método para firmar el resguardo de la apuesta
        ruta_privada = os.path.join(self.carpeta_llaves, nombre_jugador, "private.pem")
        
        # Cargar la clave privada
        with open(ruta_privada, "rb") as f:
            private_key = RSA.import_key(f.read(), passphrase=password)
        
        # Convertir la apuesta a JSON y calcular su hash
        json_data = json.dumps(apuesta, sort_keys=True).encode("utf-8")
        hash_apuesta = SHA256.new(json_data)
        
        # Firmar el hash con la clave privada
        firma = pkcs1_15.new(private_key).sign(hash_apuesta)
        
        # Retornar la firma en base64
        return base64.b64encode(firma).decode("utf-8")
    
    def verificar_firma(self, apuesta: dict, firma_b64: str, nombre_jugador: str):
        try:
            # Obtenemos la clave pública del usuario en base a su certificado
            ruta_certificado = os.path.join(self.carpeta_llaves, nombre_jugador, "certificado.pem")
            if not self.verificar_validez_certificado_y_cadena(ruta_certificado):
                print("Firma no verificada: Certificado inválido/expirado.")
                return False
            public_key = self.obtener_publica_de_certificado(ruta_certificado)
            if public_key is None:
                return False
            
            # Decodificar la firma
            firma = base64.b64decode(firma_b64)
            
            # Calcular el hash de la apuesta
            json_data = json.dumps(apuesta, sort_keys=True).encode("utf-8")
            hash_apuesta = SHA256.new(json_data)
            
            # Verificar la firma
            pkcs1_15.new(public_key).verify(hash_apuesta, firma)
            return True
            
        except (ValueError, TypeError):
            return False
        
    # Dentro de la clase FirmaCertificados en firma_certificados.py
    def verificar_validez_certificado_y_cadena(self, ruta_certificado_jugador):
        """Verifica la firma y la vigencia del certificado del jugador usando el certificado de la CA."""
        if not os.path.exists(self.ruta_ca_cert):
            print("ERROR: El certificado de la Autoridad de Certificación (CA) no existe.")
            return False

        # El comando 'verify' comprueba la firma criptográfica de la CA y la vigencia del certificado
        comando = [
            self.openssl_bin, "verify",
            "-CAfile", self.ruta_ca_cert,    # Ruta del certificado de la CA (confianza)
            ruta_certificado_jugador         # Ruta del certificado a verificar
        ]
        
        try:
            # Se ejecuta el comando. Si la verificación falla, subprocess.run lanzará un error (check=True)
            self._ejecutar_comando(comando)
            return True
        except subprocess.CalledProcessError as e:
            return False
        except FileNotFoundError:
            return False