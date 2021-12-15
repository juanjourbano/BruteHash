#!/usr/bin/python

"""
Script simple para la decodificación de hashes por fuerza bruta.

Opciones:
    -i --inputfile Archivo que contiene los hashes separados por línea
    -d --dictionary Archivo que contiene las posibles contraseñas separadas por línea
    
Ejemplo:
    $ python3 BruteHash.py -i hashes.txt -d pass_dictionary.txt
"""

"""
@Author: Juan José Urbano Parra
@License: GPL
@Version: 1.0.0
"""

# El código está ampliamente comentado por tal de que a alguien que esté aprendiendo pueda aprenderlo
# En la práctica tantas líneas de comentario son innecesarias y muy incómodas ya que es más difícil ubicarse en el archivo

# Se importa todo el contenido del módulo HashUtility
# HashUtility es un módulo creado por mí, contiene los algoritmos de codificación de hashes
# Se aconseja darle un vistazo una vez se haya comprendido este script ya que se comenta la herencia y la abstracción
from HashUtility import *

# Se importan las librerías:
#   sys (utilizada para obtener los argumentos pasados por el usuario)
#   argparse (librería para la gestión de los argumentos)
import sys, argparse

############################################################################################################################

# Método principal, es el primer método al que se llama (ver final del script), desde él se llama al resto de métodos
def main(argv):
    # Se obtienen los argumentos, args será una variable de tipo namespace, un tipo de colección que usa Python
    args = getArguments()

    # Se llama al método beginBruteForce que es el que se encarga de llamar al resto de métodos por tal de cumplir con el objetivo de hacer fuerza bruta
    # Se le pasan como argumentos el archivo de input y el diccionario
    beginBruteForce(args.inputfile, args.dictionary)

############################################################################################################################

# Se utiliza la librería argparse para tratar los argumentos
def getArguments():
    # Se crea una instancia de ArgumentParser, se le indica que el prefijo de los argumentos es '-'
    parser = argparse.ArgumentParser(prefix_chars='-')

    # Se añaden las opciones necesarias para el funcionamiento de este script
    parser.add_argument('-i', '--inputfile', help='Input file with hashes separated by line', required=True)
    parser.add_argument('-d', '--dictionary', type=str, help='Passwords dictionary', required=True)

    # Los argumentos son recogidos y almacenados en la variable args
    args = parser.parse_args()

    # Se retorna la variable args. El retorno es almacenado en el método main en una variable también de nombre args (aunque no es necesario que se llamen igual).
    return args

############################################################################################################################

# Itera sobre cada línea del archivo que contiene los hashes a descifrar
# Cada hash es enviado a la función decode, que se encargará de tratar de decodificarlo
def beginBruteForce(inputFile, dictionary):
    # Se crea una instancia de tipo TextIOWrapper (Objeto nativo de Python para la lectura y escritura de archivos) y se almacena en la variable file
    # Se indica el archivo que se quiere leer y el modo 'r' (read) ya que solamente se quiere leer el archivo
    file = open(inputFile, 'r')

    # Se obtienen todas las líneas del archivo
    lines = file.readlines()

    # Se itera sobre todas las líneas del archivo, por cada iteración se almacenará la línea actual en la variable originalHash
    for originalHash in lines:
        # Se llama a la función decode pasándole el hash y el diccionario de contraseñas
        # La variable originalHash al ser una línea de un archivo de texto puede contener un salto de línea al final, esto puede dar problemas
        # Se usa el método strip() para eliminar saltos de línea.
        decode(originalHash.strip(), dictionary)

    # Una vez se termine de acceder al archivo hay que cerrar el flujo de datos, ya que si no se hace pueden haber errores
    # Estos errores se suelen dar cuando se escribe sobre el archivo, en este caso no se hace, pero es buena práctica cerrar siempre los flujos de datos
    file.close()

############################################################################################################################

# Esta función itera sobre el diccionario de contraseñas y aplica todos los algoritmos de hashes de uno en uno
# Si se encuentra un hash idéntico al original detiene la función e imprime por pantalla la contraseña
def decode(originalHash, dictionary):
    file = open(dictionary, 'r')
    lines = file.readlines()

    # Array que contiene instancias de las clases que representan cada algoritmo
    # Otra forma de instanciar clases sería:
    #   md4=Md4()
    #   md5=Md5()
    #   sha1=Sha1()
    #   ntlm=Ntlm()
    #   hashAlgorythms=[md4, md5, sha1, ntlm]
    #
    # En el código se instancian directamente en el constructor del array
    hashAlgorythms=[Md4(), Md5(), Sha1(), Ntlm()]

    # Se itera sobre todas las contraseñas
    for password in lines:
        password = password.strip()

        # Se itera sobre las instancias de algoritmos hash
        # Por cada contraseña se va a proceder a aplicar cada algoritmo, si coincide el hash devuelto se detiene
        for hashAlgorythm in hashAlgorythms:
            # Se usa el método encode() de los objetos, devuelve la contraseña codificada
            newHash = hashAlgorythm.encode(password)

            # Se comprueba el hash original y el hash obtenido al aplicar el algoritmo actual sobre la contraseña actual
            if originalHash == newHash:
                # Se imprime la contraseña y el tipo de algoritmo
                print("Password Found!!! " + originalHash + " --> Password:" + password + " Type:" + hashAlgorythm.type)

                # Se cierra el flujo de datos
                file.close()

                # Se retorna un valor booleano, también se puede retornar vacío ya que en este caso no se está usando el valor de retorno
                # Es a elección del programador, en este caso se devuelve true, se ha hecho así por:
                #   1. Si en alguna implementación futura se quiere saber si la función ha tenido éxito
                #   2. Mejorar la semántica (para hacer el código más legible por otro programador o por mí mismo en un futuro)
                # Se puede hacer de muchas maneras, por ejemplo también se puede escoger devolver la contraseña encontrada por tal de almacenarlas en un array
                # 
                # Cuando se ejecuta un return la ejecución de la función habrá terminado, no se ejecutarán los siguientes bloques de código de esta función
                # También se saldrá de los bucles
                return True

    # Si ha terminado el bucle y la ejecución ha llegado hasta aquí significa que no se ha encontrado la contraseña
    file.close()
    return False

############################################################################################################################

# Esto es lo único que se necesita ejecutar para "arrancar" el script
# Se comprueba el nombre del módulo en ejecución, si es '__main__' significa que este es el script principal de la aplicación
if __name__ == "__main__":
    # Se ejecuta nuestro método main, se le han de pasar como argumento todos los argumentos que haya puesto el usuario (Ej: --inputfile hashes.txt, --dictionary pass_dictionary.txt)
    main(sys.argv[1:])