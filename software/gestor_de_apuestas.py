import time
import json
import os
import getpass
from json import JSONDecodeError
import base64
from .cifrado_asimetrico import cifradoAsimetrico
from .cifrado_simetrico import cifradoSimetrico
from .firma_certificados import FirmaCertificados


class Apuesta:
    def __init__(self):
        self.base_dir = "Practica"
        self.gestor_asimetrico = cifradoAsimetrico()
        self.cifrado_simetrico = cifradoSimetrico()
        self.gestor_firma = FirmaCertificados()

        # Carpetas principales
        self.carpeta = os.path.join(self.base_dir, "json_files")
        self.carpeta_llaves = os.path.join(self.base_dir, "llaves")
        self.carpeta_resguardos = os.path.join(self.base_dir, "resguardos")

        # Crear directorios si no existen
        os.makedirs(self.carpeta, exist_ok=True)
        os.makedirs(self.carpeta_llaves, exist_ok=True)
        os.makedirs(self.carpeta_resguardos, exist_ok=True)

        # Rutas de archivos principales
        self.ruta = os.path.join(self.carpeta, "apuestas.json")

        # Cargar o crear apuestas
        self.apuestas = self.cargar_apuestas()
        self.tipo_apuesta = ["simple", "combinada"]
        

    # Para cargar el .json para guardar apuestas en caso de que no exista
    def cargar_apuestas(self):
        if os.path.exists(self.ruta):
            with open(self.ruta, "r") as archivo:
                try:
                    apuestas = json.load(archivo)
                except JSONDecodeError:
                    apuestas = {}
        else:
            apuestas = {}
        return apuestas

    # Para guardar las apuestas en un .json
    def guardar_apuestas(self):
        with open(self.ruta, "w") as archivo:
            json.dump(self.apuestas, archivo, indent=4)

    # Creador de apuestas
    def crear_apuesta(self, nombre_jugador, control_usuarios):
        # Validar que el usuario tenga entrada en claves_cifradas
        if nombre_jugador not in control_usuarios.claves_cifradas:
            print("No se encontró clave asociada al usuario.")
            return False

        # Validar cantidad introducida
        try:
            cantidad = float(input(f"{nombre_jugador} introduce la cantidad a apostar: "))
        except ValueError:
            print("Cantidad no válida: debe introducir un número")
            return False

        tipo_apuesta = input("Ahora introduce el tipo de apuesta (simple/combinada): ")

        # Comprobar que la cantidad de dinero a apostar no sea negativo
        if cantidad <= 0:
            print("Cantidad no válida")
            return False

        # Comprobar que el tipo de apuesta realiza es correcto
        if tipo_apuesta not in self.tipo_apuesta:
            print("Tipo de apuesta no válido")
            return False

        # Comprobamos saldo disponible
        # Recuperamos la clave cifrada del usuario
        clave_cifrada = control_usuarios.claves_cifradas.get(nombre_jugador)
        if not clave_cifrada:
            print("No existe clave cifrada para este usuario.")
            return False

        # Pedimos la contraseña del jugador para derivar su clave
        password = getpass.getpass("Introduce tu contraseña para verificar saldo: ")

        # Recuperamos la sal y derivamos la clave
        try:
            sal = bytes.fromhex(control_usuarios.usuarios[nombre_jugador]["sal"])
        except Exception:
            print("No se pudo leer la sal del usuario.")
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

        # Finalmente, desciframos el saldo
        saldo_cifrado = control_usuarios.usuarios[nombre_jugador].get("saldo")
        if not saldo_cifrado:
            print("No se encontró saldo para este usuario.")
            return False

        saldo_descifrado = self.cifrado_simetrico.descifrar(saldo_cifrado, clave_usuario)
        if saldo_descifrado is None:
            print("Error al descifrar el saldo")
            return False

        try:
            saldo_actual = float(saldo_descifrado)
        except ValueError:
            print("El saldo almacenado no es un número válido.")
            return False

        print(f"Saldo disponible: {saldo_actual:.2f} €")

        if cantidad > saldo_actual:
            print("Saldo insuficiente para realizar la apuesta.")
            return False

        # Restamos el saldo y actualizamos
        nuevo_saldo = saldo_actual - cantidad
        saldo_nuevo = control_usuarios.actualizar_saldo(nombre_jugador, nuevo_saldo)
        if saldo_nuevo == False:
            print("Error al actualizar el saldo")
            return False
        
        # Si el jugador no ha realizado una apuesta aún creamos una lista para él con sus apuestas
        if nombre_jugador not in self.apuestas:
            self.apuestas[nombre_jugador] = []
        
        apuesta_original = {
            "cantidad": cantidad,
            "tipo_apuesta": tipo_apuesta,
            "tiempo": time.ctime()
        }

        apuesta_cifrada = {
            "cantidad": self.cifrado_simetrico.cifrar(str(cantidad), clave_usuario),
            "tipo_apuesta": self.cifrado_simetrico.cifrar(tipo_apuesta, clave_usuario),
            "tiempo_de_la_apuesta": self.cifrado_simetrico.cifrar(time.ctime(), clave_usuario)
        }
        # Firma la apuesta, y lo guarda junto a ella, para poder verificar su firma más tarde
        firma = self.gestor_firma.firmar_resguardo(apuesta_original, nombre_jugador, password)
        apuesta_cifrada["firma"] = firma

        self.apuestas[nombre_jugador].append(apuesta_cifrada)
        self.guardar_apuestas()

        # Guardar en resguardo la original SÓLO con RSA
        # Crear resguardo cifrado con RSA
        resguardo_cifrado = self.gestor_asimetrico.cifrar_resguardo(apuesta_original, nombre_jugador)

        # Timestamp para nombre de archivos
        timestamp = time.strftime("%Y%m%d_%H%M%S")

        # Guardar resguardo
        self.guardar_resguardo(nombre_jugador, resguardo_cifrado)

        # Generar hash del resguardo original
        hash_hex = self.gestor_asimetrico.generar_hash_resguardo(resguardo_cifrado)

        # Guardar hash
        self.gestor_asimetrico.guardar_hash_resguardo(nombre_jugador, hash_hex, timestamp)
        print("Apuesta creada con éxito")
        return True


    # Historial con las apuestas realizadas del jugador
    def historial_apuestas(self, nombre_jugador, control_usuarios):
        if nombre_jugador not in self.apuestas or not self.apuestas[nombre_jugador]:
            print("No hay apuestas para este usuario.")
            return None
        # Comprueba que existe clave para este jugador
        if nombre_jugador not in control_usuarios.claves_cifradas:
            print("No existe clave para este usuario.")
            return None
        
        password = getpass.getpass("Introduce tu contraseña para ver tu historial: ")

        # El usuario debe introducir la contraseña para poder ver el historial de sus apuestas
        try:
            sal = bytes.fromhex(control_usuarios.usuarios[nombre_jugador]["sal"])
        except Exception:
            print("Error al leer la sal del usuario.")
            return None
        hash_password = self.cifrado_simetrico.derivar_clave(password, sal)
        clave_usuario_b64 = self.cifrado_simetrico.descifrar(
            control_usuarios.claves_cifradas[nombre_jugador],
            hash_password[:16]
        )
        if clave_usuario_b64 is None:
            print("Contraseña incorrecta.")
            return None
        clave_usuario = base64.b64decode(clave_usuario_b64)

        # Bucle para mostrar las apuestas descifradas
        print("\n===== HISTORIAL DE APUESTAS =====\n")
        for apuesta in self.apuestas[nombre_jugador]:
            # Obtiene apuestas descifradas
            cantidad = self.cifrado_simetrico.descifrar(apuesta["cantidad"], clave_usuario)
            tipo = self.cifrado_simetrico.descifrar(apuesta["tipo_apuesta"], clave_usuario)
            tiempo = self.cifrado_simetrico.descifrar(apuesta["tiempo_de_la_apuesta"], clave_usuario)
            firma = apuesta.get("firma")

            #Reconstruye la apuesta para verificar la firma
            apuesta_descifrada = {
                "cantidad": float(cantidad),
                "tipo_apuesta": tipo,
                "tiempo": tiempo
            }

            verificar_firma = self.gestor_firma.verificar_firma(apuesta_descifrada, firma, nombre_jugador)
            estado_firma = "FIRMA VÁLIDA" if verificar_firma else "FIRMA INVÁLIDA"

            print(f"Cantidad: {cantidad} €")
            print(f"Tipo: {tipo}")
            print(f"Fecha: {tiempo}")
            print(f"Firma: {estado_firma}")
            print("-----------------------------------")

    # Guardar el resguardo en carpeta separada (por usuario)
    def guardar_resguardo(self, nombre_jugador, resguardo_cifrado):
        # Crear carpeta específica del jugador
        carpeta_usuario = os.path.join(self.carpeta_resguardos, nombre_jugador)
        os.makedirs(carpeta_usuario, exist_ok=True)

        # Nombre del archivo con fecha/hora
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        ruta_resguardo = os.path.join(carpeta_usuario, f"resguardo_{timestamp}.txt")

        with open(ruta_resguardo, "w") as f:
            f.write(resguardo_cifrado)

        print(f"Resguardo de la apuesta guardado en {ruta_resguardo}")

    def ver_resguardos(self, nombre_jugador, password):
        carpeta_usuario = os.path.join(self.carpeta_resguardos, nombre_jugador)
        if not os.path.exists(carpeta_usuario):
            #Verifica a ver si el usuario tienes resguardos de apuestas
            print("No se encontraron resguardos para este usuario.")
            return
        
        # Recoge todos los resguardos del usuario
        archivos = [f for f in os.listdir(carpeta_usuario) if f.startswith("resguardo_") and f.endswith(".txt")]
        if not archivos:
            print("No hay resguardos en la carpeta.")
            return
        
        # Muestra por pantalla los resguardo disponibles del usuario
        print("\n===== Resguardos RSA Disponibles =====\n")
        for i, nombre_archivo in enumerate(archivos):
            print(f"[{i+1}] - {nombre_archivo}")
        print("-----------------------------------\n")

        # El usuario decide qué resguardo quiere ver
        try:
            indice = int(input("Introduce el número de resguardo que quieres descifrar: ")) - 1
            if indice < 0 or indice >= len(archivos):
                print("Número de resguardo no válido.")
                return
        except ValueError:
            print("Entrada no válida.")
            return

        # Proceso para mirar qué resguardo, quiere ver el usuario
        nombre_archivo = archivos[indice]
        ruta_resguardo = os.path.join(carpeta_usuario, nombre_archivo)
        with open(ruta_resguardo, "r") as f:
            resguardo_cifrado = f.read()

        try:
            timestamp_completo = nombre_archivo.split("_")[1] + "_" + nombre_archivo.split("_")[2].split(".")[0]
        except IndexError:
            print("Error: Formato de nombre de archivo inesperado. No se puede verificar la integridad del disco.")
            return
        
        # Verifica que la integridad del archivo no se ha visto comprometida
        hash_actual = self.gestor_asimetrico.generar_hash_resguardo(resguardo_cifrado)
        hash_original = self.gestor_asimetrico.cargar_hash_resguardo(nombre_jugador, timestamp_completo)
        verificacion_hash = self.gestor_asimetrico.verificar_hash_resguardo(hash_original, hash_actual)

        if verificacion_hash:
            print("Integridad del resguardo verificada: No se han detectado modificaciones.")
        else:
            print("La integridad del resguardo ha sido comprometida")
            return 
        
        # Descifra el resguardo
        resguardo_descifrado_json = self.gestor_asimetrico.descifrar_resguardo(resguardo_cifrado, nombre_jugador, password)[1]

        # Maneja error a la hora de cargar un .json
        if resguardo_descifrado_json:
            try:
                apuesta_original = json.loads(resguardo_descifrado_json) 
                print("\n===== CONTENIDO DEL RESGUARDO DESCIFRADO =====\n")
                # Al ser un dict, puedes acceder a sus claves con cadenas:
                print(f"Cantidad: {apuesta_original['cantidad']} €") 
                print(f"Tipo: {apuesta_original['tipo_apuesta']}")
                print(f"Fecha: {apuesta_original['tiempo']}")
                print("---------------------------------------------------\n")
            
            # Asegúrate de manejar el error si la cadena no es JSON válida
            except JSONDecodeError:
                print("Error: El contenido descifrado no es un formato JSON válido.")
            except Exception as e:
                print(f"Error al procesar el resguardo: {e}")
        else:
            print("Error al descifrar el resguardo. Posiblemente clave incorrecta.")