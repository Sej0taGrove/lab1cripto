def cifrado_cesar(texto, desplazamiento):
    """
    Cifra un texto usando el algoritmo de César.
    """
    resultado = ""
    for caracter in texto:
        if caracter.isalpha():
            codigo_ascii = 65 if caracter.isupper() else 97
            codigo_cifrado = (ord(caracter) - codigo_ascii + desplazamiento) % 26 + codigo_ascii
            resultado += chr(codigo_cifrado)
        else:
            resultado += caracter
    return resultado

def descifrado_cesar(texto, desplazamiento):

    return cifrado_cesar(texto, -desplazamiento)

def main():

    texto = input("Ingrese el texto a cifrar: ")
    desplazamiento = int(input("Ingrese el número de posiciones a desplazar: "))
    
    texto_cifrado = cifrado_cesar(texto, desplazamiento)
    print(f"Texto cifrado: {texto_cifrado}")
    
    texto_descifrado = descifrado_cesar(texto_cifrado, desplazamiento)
    print(f"Texto descifrado: {texto_descifrado}")

if __name__ == "__main__":
    main()