from software.firma_certificados import FirmaCertificados
from software.cifrado_asimetrico import cifradoAsimetrico
import time

gestor_firma = FirmaCertificados()
gestor_asimetrico = cifradoAsimetrico()
nombre_jugador = "jugador_test"
apuesta_test = {
    "cantidad": 100,
    "tipo_apuesta": "simple",
    "tiempo_de_la_apuesta": time.ctime()
}

def test_firma_digital_valida():
    gestor_asimetrico.generar_claves_usuario(nombre_jugador, "password_test")
    firma_apuesta = gestor_firma.firmar_resguardo(apuesta_test, nombre_jugador, "password_test")
    verificar_firma = gestor_firma.verificar_firma(apuesta_test, firma_apuesta, nombre_jugador)

    if verificar_firma:
        print("La firma digital es válida")
    else:
        print("La firma digital no es válida")
    
def test_firma_digital_invalida():
    gestor_asimetrico.generar_claves_usuario(nombre_jugador, "password_test")
    apuesta_modificada = apuesta_test.copy()
    apuesta_modificada["cantidad"] = 10
    firma_apuesta = gestor_firma.firmar_resguardo(apuesta_test, nombre_jugador, "password_test")
    verificar_firma = gestor_firma.verificar_firma(apuesta_modificada, firma_apuesta, nombre_jugador)

    if not verificar_firma:
        print("La firma digital es inválida como se esperaba")
    else:
        print("La firma digital es válida, no puede ser")
    
def prueba_certificado_inválido():
    gestor_asimetrico.generar_claves_usuario(nombre_jugador, "password_test")
    apuesta_modificada = apuesta_test.copy()
    apuesta_modificada["cantidad"] = 10
    firma_apuesta = gestor_firma.firmar_resguardo(apuesta_test, nombre_jugador, "password_test")
    verificar_firma = gestor_firma.verificar_firma(apuesta_modificada, firma_apuesta, nombre_jugador)

    if not verificar_firma:
        print("El certificado de tu firma está cáducado para el día de hoy")
    else:
        print("El certificado es válido, no puede ser")


if __name__ == "__main__":
    test_firma_digital_valida()
    test_firma_digital_invalida()
    prueba_certificado_inválido()