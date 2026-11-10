import os
import shutil

def limpiar_directorios(base_dir="Practica"):
    carpetas_a_eliminar = [
        os.path.join(base_dir, "resguardos"),
        os.path.join(base_dir, "json_files"),
        os.path.join(base_dir, "llaves"),
    ]
    
    print(f"--- Iniciando limpieza en el directorio '{base_dir}' ---")

    for carpeta in carpetas_a_eliminar:
        if os.path.exists(carpeta):
            try:
                shutil.rmtree(carpeta)
                print(f"Carpeta eliminada con éxito: {carpeta}")
            except OSError as e:
                print(f"Error al eliminar la carpeta {carpeta}: {e}")
        else:
            print(f"Carpeta no encontrada, saltando: {carpeta}")
            
    print("--- Limpieza finalizada ---")

limpiar_directorios()