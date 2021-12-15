"""
Módulo que contiene los algoritmos de codificación de hashes
"""

"""
@Author: Juan José Urbano Parra
@License: GPL
@Version: 1.0.0
"""

# El problema que se plantea:
#   Se deben de calcular los hashes utilizando muchos algoritmos diferentes y de uno en uno por tal de comprobar el resultado
#   Hay que intentar que no se repita código en la medida de lo posible
# Una forma de conseguirlo es mediante la herencia
# En este caso además la clase padre será abstracta (no se puede instanciar)

# Se importa la clase ABC (Abstract Class), si una clase hereda de ABC significa que esa clase es abstracta y que no se puede instanciar
# Se importa la anotación abstractmethod
# Se usa para determinar que ese método no se puede usar (solamente lo podrán usar los hijos que hereden del padre y la implementen)
from abc import ABC, abstractmethod

# Librerías usadas para crear los hashes
import hashlib, binascii

# La clase HashUtility es la clase padre, hereda de ABC, y por tanto es una clase abstracta y no se puede instanciar
# El método encode es precedido por la anotación @abstractmethod, los métodos abstractos deberán de ser implementados por las clases que hereden de esta (las clases hijas)
class HashUtility(ABC):
    # __init__: Es el constructor de la clase, recibe los argumentos que definen las propiedades del objeto
    # self se debe poner siempre, se usa para determinar las propiedades de la instancia (self hace referencia a la propia instancia y permite acceder a sus propiedades)
    #   Si hay dos instancias de la misma clase, por ejemplo:
    #       manolo=Persona("Manolo", 35)
    #       jose=Persona("Jose", 19)
    #   Como se puede ver las instancias manolo y jose pertenecen a la misma clase, pero son diferentes instancias con diferentes valores.
    def __init__(self, type='None'):
        self.type=type
        # super() siempre hace referencia a la clase padre de la que se esté heredando
        # En un constructor de una clase que herede, siempre se debe llamar al final del mismo al constructor de la clase padre
        super().__init__()

    # Se añade la anotación abstractmethod para que las clases hijas deban implementar obligatoriamente una función llamada encode que reciba una contraseña
    # Se obliga a las clases hijas a que implementen la función, por lo tanto sabemos que al momento de usar una clase que herede de HashUtility va a tener obligatoriamente una función llamada encode (le vamos a pasar una contraseña y nos debe devolver un texto codificado)
    # Este es el motivo por el que la función decode() del script principal BruteHash.py puede iterar sobre un conjunto de clases hijas de HashUtility y llamar a la función encode sin temor a que aparezca un error del estilo 'Esa función no existe'
    @abstractmethod
    def encode(self, password):
        pass

############################################################################################################################

# A continuación se crean las clases utilizadas en el script BruteForce.py
# Todas estas clases heredan de HashUtility por lo que han de implementar la función encode
# Cada una de ellas puede implementar el método encode a su manera y retornar un hash

class Md2(HashUtility):
    def __init__(self, type='md2'):
        super().__init__(type=type)

    def encode(self, password):
        return super().encode(password)

class Md4(HashUtility):
    def __init__(self, type='md4'):
        super().__init__(type=type)

    def encode(self, password):
        hashObject = hashlib.new('md4', password.encode('utf-8'))
        digest = hashObject.hexdigest()
        return digest

class Ntlm(HashUtility):
    def __init__(self, type='ntlm'):
        super().__init__(type=type)

    def encode(self, password):
        hashObject = hashlib.new('md4', password.encode('utf-16le')).digest()
        hex = binascii.hexlify(hashObject)
        return hex.decode('utf-8')

class Md5(HashUtility):
    def __init__(self, type='md5'):
        super().__init__(type=type)

    def encode(self, password):
        hashObject = hashlib.new('md5', password.encode('utf-8'))
        digest = hashObject.hexdigest()
        return digest

class Sha1(HashUtility):
    def __init__(self, type='sha1'):
        super().__init__(type=type)

    def encode(self, password):
        hashObject = hashlib.new('sha1', password.encode('utf-8'))
        digest = hashObject.hexdigest()
        return digest