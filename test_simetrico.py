from software.cifrado_simetrico import cifradoSimetrico
from Crypto.Random import get_random_bytes
import time
import base64

gestor_simetrico = cifradoSimetrico()

# Verificar que el cifrado y descifrado funciona
def cifrado_simetrico_verifica():
    contraseña_test = "JuanCanepa123"
    sal = get_random_bytes(16)
    
    hash_password = gestor_simetrico.derivar_clave(contraseña_test, sal)
    clave_usuario_test = get_random_bytes(16)
    clave_usuario_b64_cifrada = gestor_simetrico.cifrar(base64.b64encode(clave_usuario_test).decode("utf-8"), hash_password[:16])
    contraseña_cifrada = gestor_simetrico.cifrar(contraseña_test, clave_usuario_test)

    clave_usuario_b64_descifrada = gestor_simetrico.descifrar(clave_usuario_b64_cifrada, hash_password[:16])
    clave_usuario_descifrada = base64.b64decode(clave_usuario_b64_descifrada)
    contraseña_descifrada = gestor_simetrico.descifrar(contraseña_cifrada, clave_usuario_descifrada)
    
    if contraseña_test == contraseña_descifrada:
        print("Cifrado y descifrado simétrico funcionan correctamente.")
    else:
        raise ValueError("Error: Los datos descifrados no coinciden con los datos originales.")

# Para ver el tiempo que tardaría cifrar y descifrar
def cifrado_simetrico_rendimiento():
    contraseña_test = "JuanCanepa123"
    sal = get_random_bytes(16)
    
    hash_password = gestor_simetrico.derivar_clave(contraseña_test, sal)
    clave_usuario_test = get_random_bytes(16)

    tiempo_inico_cifrado = time.time()
    
    clave_usuario_b64_cifrada = gestor_simetrico.cifrar(base64.b64encode(clave_usuario_test).decode("utf-8"), hash_password[:16])
    contraseña_cifrada = gestor_simetrico.cifrar(contraseña_test, clave_usuario_test)
    
    tiempo_final_cifrado = time.time()
    tiempo_total_cifrado = tiempo_final_cifrado - tiempo_inico_cifrado

    tiempo_inico_descifrado = time.time()
    
    clave_usuario_b64_descifrada = gestor_simetrico.descifrar(clave_usuario_b64_cifrada, hash_password[:16])
    clave_usuario_descifrada = base64.b64decode(clave_usuario_b64_descifrada)
    
    contraseña_descifrada = gestor_simetrico.descifrar(contraseña_cifrada, clave_usuario_descifrada)
    
    tiempo_final_descifrado = time.time()
    tiempo_total_descifrado = tiempo_final_descifrado - tiempo_inico_descifrado
    
    if contraseña_test == contraseña_descifrada:
        print(f"Tiempo total de CIFRADO: {tiempo_total_cifrado:.6f} segundos")
        print(f"Tiempo total de DESCIFRADO: {tiempo_total_descifrado:.6f} segundos")
    else:
        raise ValueError("Error: Los datos descifrados no coinciden con los datos originales.")

if __name__ == "__main__":
    cifrado_simetrico_verifica()
    cifrado_simetrico_rendimiento()