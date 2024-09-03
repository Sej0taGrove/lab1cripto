from scapy.all import sniff, ICMP
import ctypes
import sys

def set_color(color):
    kernel32 = ctypes.windll.kernel32
    handle = kernel32.GetStdHandle(-11)
    
    if color.lower() == "green":
        kernel32.SetConsoleTextAttribute(handle, 10)  # 10 es el código para verde brillante
    else:
        kernel32.SetConsoleTextAttribute(handle, 7)   # 7 es el código para blanco (color normal)

def print_color(text, color):
    set_color(color)
    print(text)
    set_color("white")  # Restaurar el color normal

def descifrado_cesar(texto, desplazamiento):
    resultado = ""
    for caracter in texto:
        if caracter.isalpha():
            codigo_ascii = 65 if caracter.isupper() else 97
            codigo_descifrado = (ord(caracter) - codigo_ascii - desplazamiento) % 26 + codigo_ascii
            resultado += chr(codigo_descifrado)
        else:
            resultado += caracter
    return resultado

def capturar_paquetes(interfaz):
    paquetes = sniff(iface=interfaz, filter="icmp", count=0, timeout=30)
    return paquetes

def extraer_mensaje(paquetes):
    mensaje_cifrado = ""
    timestamps = []
    for paquete in paquetes:
        if paquete.haslayer(ICMP) and paquete[ICMP].type == 8:  # ICMP Echo Request
            tamano_paquete = len(paquete[ICMP].load)
            if tamano_paquete > 100:
                caracter = chr(tamano_paquete - 100)
                mensaje_cifrado += caracter
                timestamps.append(paquete.time)
            elif tamano_paquete == 1:
                break  # Fin del mensaje
    return mensaje_cifrado, timestamps

def analizar_probabilidad(texto):
    frecuencias = {
        'e': 12.53, 'a': 11.52, 'o': 8.69, 'l': 8.37, 's': 7.88, 'n': 7.01,
        'd': 6.87, 'r': 6.41, 'u': 4.80, 'i': 4.15, 't': 3.31, 'c': 2.92,
        'p': 2.76, 'm': 2.12, 'y': 1.54, 'q': 1.53, 'b': 0.92, 'h': 0.89,
        'g': 0.73, 'f': 0.52, 'v': 0.39, 'j': 0.30, 'z': 0.15, 'x': 0.06
    }
    return sum(frecuencias.get(letra.lower(), 0) for letra in texto if letra.isalpha())

def main():
    
    interfaz = input("Ingrese el nombre de la interfaz de red a escuchar: ")
    print("Capturando paquetes... (30 segundos)")
    paquetes = capturar_paquetes(interfaz)
    
    mensaje_cifrado, timestamps = extraer_mensaje(paquetes)
    print(f"Mensaje cifrado capturado: {mensaje_cifrado}")
    print("Timestamps de los paquetes:")
    for i, ts in enumerate(timestamps):
        print(f"Paquete {i+1}: {ts}")
    
    mejores_opciones = []
    for desplazamiento in range(26):
        mensaje_descifrado = descifrado_cesar(mensaje_cifrado, desplazamiento)
        probabilidad = analizar_probabilidad(mensaje_descifrado)
        mejores_opciones.append((desplazamiento, mensaje_descifrado, probabilidad))
    
    mejores_opciones.sort(key=lambda x: x[2], reverse=True)
    
    print("\nPosibles mensajes descifrados (ordenados por probabilidad):")
    for desplazamiento, mensaje, _ in mejores_opciones:
        if mensaje == mejores_opciones[0][1]:
            print_color(f"Desplazamiento {desplazamiento}: {mensaje}", "green")
        else:
            print(f"Desplazamiento {desplazamiento}: {mensaje}")

if __name__ == "__main__":
    main()