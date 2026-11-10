import json
import os
import random
import base64
import getpass
from Crypto.Random import get_random_bytes
from .cifrado_simetrico import cifradoSimetrico

class Control_usuarios:
    def __init__(self):
        # Dirección del fichero de usuarios
        self.base_dir = "Practica"
        self.carpeta = os.path.join(self.base_dir, "json_files")
        os.makedirs(self.carpeta, exist_ok=True)

        self.ruta_usuarios = os.path.join(self.carpeta, "usuarios.json")
        self.ruta_claves = os.path.join(self.carpeta, "claves.json")

        # Clave del cifrado simétrico
        self.usuarios = self.cargar_json(self.ruta_usuarios)
        self.claves_cifradas = self.cargar_json(self.ruta_claves)
        self.cifrado_simetrico = cifradoSimetrico()

    #Cargar ruta archivos .json
    def cargar_json(self, ruta):
        if os.path.exists(ruta):
            with open(ruta, "r") as fichero:
                try:
                    return json.load(fichero)
                except:
                    return {}
        return {}
    
    #Para guardar datos en archivos .json
    def guardar_json(self, ruta, datos):
        with open(ruta, "w") as fichero:
            json.dump(datos, fichero, indent=4) 

    # El usuario introduce todos sus datos
    def registrar_usuario(self):
        # Nombre de usuario
        nombre = input("Introduce tu nombre de usuario: ")
        if nombre in self.usuarios:
            print("Usuario ya existente")
            return
        
        # Contraseña cifrada como un hash 
        password = getpass.getpass("Introduce una contraseña: ")

        if len(password) < 8:
            print("La contraseña debe tener al menos 8 caracteres")
            return
        
        sal = get_random_bytes(16)
        hash_password = self.cifrado_simetrico.derivar_clave(password, sal)

        clave_usuario = get_random_bytes(16)
        clave_cifrada = self.cifrado_simetrico.cifrar(base64.b64encode(clave_usuario).decode("utf-8"), hash_password[:16])
        self.claves_cifradas[nombre] = clave_cifrada
        self.guardar_json(self.ruta_claves, self.claves_cifradas)

        # Número de tarjeta bancaria
        num_tarjeta = input("Introduce tu número de tarjeta de crédito: ")
        if len(num_tarjeta) != 16 or not num_tarjeta.isdigit():
            print("Número de tarjeta no válido")
            return
        
        # Código de seguridad
        cvv = input("Introduce el CVV de tu tarjeta de crédito: ")
        if len(cvv) != 3 or not cvv.isdigit():
            print("CVV no válido")
            return
        
        # Fecha de caducidad de la tarjeta
        f_caducidad = input("Introduce la fecha de caducidad de tu tarjeta de crédito (MM/AA): ")
        mes, ano = f_caducidad.split("/")
        if (len(mes) != 2 or len(ano) != 2 or not mes.isdigit() or not ano.isdigit() or
            int(mes) < 1 or int(mes) > 12):
            print("Fecha de caducidad no válida")
            return
        
        # Saldo en la tarjeta (aleatorio)
        saldo = random.randint(100, 1000)

        # Estructura del usuario en el .json
        self.usuarios[nombre] = {
            "password": self.cifrado_simetrico.cifrar(password, clave_usuario),
            "num_tarjeta": self.cifrado_simetrico.cifrar(num_tarjeta, clave_usuario),
            "cvv": self.cifrado_simetrico.cifrar(cvv, clave_usuario),
            "f_caducidad": self.cifrado_simetrico.cifrar(f_caducidad, clave_usuario),
            "saldo": self.cifrado_simetrico.cifrar(str(saldo), clave_usuario),
            "sal": sal.hex(),
            "hash_password": hash_password.hex()
        }

        # Finalmente, el usuario se guarda en el .json
        self.guardar_json(self.ruta_usuarios, self.usuarios)
        print("Usuario registrado correctamente!")

    # Consulta de información de un usuario registrado para iniciar sesión
    def autenticar_usuario(self):
        nombre = input("Nombre de usuario: ").strip()
        if nombre not in self.usuarios:
            print("Usuario no encontrado")
            return False, False

        password = getpass.getpass("Contraseña: ")

        # Recuperar sal y hash guardados
        sal = bytes.fromhex(self.usuarios[nombre]["sal"])
        hash_guardado = self.usuarios[nombre]["hash_password"]

        hash_password = self.cifrado_simetrico.derivar_clave(password, sal)
        if hash_password.hex() != hash_guardado:
            print("Contraseña incorrecta")
            return False, False

        # Descifrar clave individual usando hash de contraseña
        clave_cifrada = self.claves_cifradas[nombre]
        clave_usuario_b64 = self.cifrado_simetrico.descifrar(clave_cifrada, hash_password[:16])
        clave_usuario = base64.b64decode(clave_usuario_b64)

        # Verificar contraseña descifrada con clave individual
        password_descifrada = self.cifrado_simetrico.descifrar(self.usuarios[nombre]["password"], clave_usuario)
        if password_descifrada != password:
            print("Error al verificar contraseña")
            return False, False

        print("Usuario autenticado correctamente")
        return nombre, password


    def actualizar_saldo(self, nombre, nuevo_saldo):
        if nombre not in self.usuarios:
            print("Usuario no encontrado para actualizar saldo.")
            return False

        # Recuperamos la clave cifrada del usuario
        clave_cifrada = self.claves_cifradas.get(nombre)
        if not clave_cifrada:
            print("Error: no existe clave cifrada para este usuario.")
            return False

        # Pedimos la contraseña para derivar la clave (igual que en autenticación)
        password = getpass.getpass(f"Introduce la contraseña de {nombre} para actualizar el saldo: ")

        try:
            sal = bytes.fromhex(self.usuarios[nombre]["sal"])
        except Exception:
            print("Error interno: no se pudo leer la sal del usuario.")
            return False

        hash_password = self.cifrado_simetrico.derivar_clave(password, sal)

        # Desciframos la clave de usuario
        clave_usuario_b64 = self.cifrado_simetrico.descifrar(clave_cifrada, hash_password[:16])
        if clave_usuario_b64 is None:
            print("Contraseña incorrecta o error al descifrar la clave individual.")
            return False

        try:
            clave_usuario = base64.b64decode(clave_usuario_b64)
        except Exception:
            print("Error al decodificar la clave del usuario.")
            return False

        # Ciframos el nuevo saldo con la clave individual
        try:
            saldo_cifrado = self.cifrado_simetrico.cifrar(str(nuevo_saldo), clave_usuario)
        except Exception:
            print("Error al cifrar el nuevo saldo.")
            return False

        # Guardamos el saldo cifrado
        self.usuarios[nombre]["saldo"] = saldo_cifrado
        self.guardar_json(self.ruta_usuarios, self.usuarios)

        print(f"Nuevo saldo de {nombre}: {nuevo_saldo:.2f} €")
        return True
