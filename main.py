from software.autenticacion_de_usuario import Control_usuarios
from software.gestor_de_apuestas import Apuesta
from software.cifrado_asimetrico import cifradoAsimetrico

# Introducimos las clases
control_usuarios = Control_usuarios()
input_apuesta = Apuesta()
cifrado_asimetrico = cifradoAsimetrico()

while True:
    # Iniciamos la aplicación
    opcion = input("Bienvenido a la casa de apuestas. ¿Qué desea hacer?: " \
    "1 -> Registrarse 2 -> Iniciar sesión 3 -> Salir: ")

    # Registrar usuario
    if opcion == "1":
        control_usuarios.registrar_usuario()
    # Iniciar sesión
    elif opcion == "2":
        nombre_autenticado, password = control_usuarios.autenticar_usuario()
        if not nombre_autenticado:
            print("Error de autenticación")
            continue
        cifrado_asimetrico.generar_claves_usuario(nombre_autenticado, password)
        # Una vez se inicia sesión, se puede realizar una apuesta
        while True:
            opcion_apuesta = input(f"Bienvenido {nombre_autenticado} ¿Qué desea hacer?: 1 -> Crear apuesta, " \
            "2 -> Ver historial de apuestas, 3 -> Ver resguardos, 4 -> Salir: ")

            # Crea una apuesta
            if opcion_apuesta == "1":
                nueva_apuesta = input_apuesta.crear_apuesta(nombre_autenticado, control_usuarios)
                if (nueva_apuesta == False):
                    print("Error al crear la apuesta")

            # Consulta de apuestas realizadas
            if opcion_apuesta == "2":
                input_apuesta.historial_apuestas(nombre_autenticado, control_usuarios)

            # Consulta de resguardo seleccionado
            elif opcion_apuesta == "3":
                input_apuesta.ver_resguardos(nombre_autenticado, password)

            # Salir de pestaña de operaciones
            if opcion_apuesta == "4":
                break

    # Salir de la aplicación
    elif opcion == "3":
        break
    else:
        print("Opción no válida")
