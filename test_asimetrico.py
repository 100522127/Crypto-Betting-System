import time
from software.cifrado_asimetrico import cifradoAsimetrico

gestor_asimetrico = cifradoAsimetrico()
nombre_jugador = "jugador_test"
apuesta_test = {
    "cantidad": 100,
    "tipo_apuesta": "simple",
    "tiempo_de_la_apuesta": time.ctime()
}

def cifrado_asimetrico_funciona_correctamente():
    gestor_asimetrico.generar_claves_usuario(nombre_jugador, "password_test")
    #Comprobar que el cifrado y descifrado funcionan correctamente
    resguardo_cifrado = gestor_asimetrico.cifrar_resguardo(apuesta_test, nombre_jugador)
    resguardo_descifrado = gestor_asimetrico.descifrar_resguardo(resguardo_cifrado, nombre_jugador, "password_test")[0]

    if apuesta_test != resguardo_descifrado:
        ValueError("Error: Los datos descifrados no coinciden con los datos originales")
    else:
        print("Cifrado y descifrado funcionan correctamente")

# Cifra y descifra para ver el tiempo que tarda en hacerlo
def cifrado_asimetrico_rendimiento():
    gestor_asimetrico.generar_claves_usuario(nombre_jugador, "password_test")

    tiempo_inico_cifrado = time.time()
    resguardo_cifrado = gestor_asimetrico.cifrar_resguardo(apuesta_test, nombre_jugador)
    tiempo_final_cifrado = time.time()
    tiempo_total_cifrado = tiempo_final_cifrado - tiempo_inico_cifrado

    tiempo_inico_descifrado = time.time()
    resguardo_descifrado = gestor_asimetrico.descifrar_resguardo(resguardo_cifrado, nombre_jugador, "password_test")[0]
    tiempo_final_descifrado = time.time()
    tiempo_total_descifrado = tiempo_final_descifrado - tiempo_inico_descifrado

    if apuesta_test != resguardo_descifrado:
        ValueError("Error: Los datos descifrados no coinciden con los datos originales")
    else:
        print(f"Tiempo de cifrado: {tiempo_total_cifrado: .6f}")
        print(f"Tiempo de descifrado: {tiempo_total_descifrado: .6f}")

# Hacer que el descifrado falle, quitándole el último carácter
def cifrado_asimetrico_falla():
    gestor_asimetrico.generar_claves_usuario(nombre_jugador, "password_test")
    resguardo_cifrado = gestor_asimetrico.cifrar_resguardo(apuesta_test, nombre_jugador)
    resguardo_modificado = resguardo_cifrado[:-1]
    try:
        gestor_asimetrico.descifrar_resguardo(resguardo_modificado, nombre_jugador, "password_test")
    except ValueError as e:
        print(f"La prueba de fallo pasó: La función detectó la corrupción")
    except Exception as e:
        print(f"Error inesperado durante la prueba de fallo: {e}")

if __name__ == "__main__":
    cifrado_asimetrico_funciona_correctamente()
    cifrado_asimetrico_rendimiento()
    cifrado_asimetrico_falla()
