from scapy.all import IP, ICMP, send
import time

def cifrado_cesar(texto, desplazamiento):
    resultado = ""
    for caracter in texto:
        if caracter.isalpha():
            codigo_ascii = 65 if caracter.isupper() else 97
            codigo_cifrado = (ord(caracter) - codigo_ascii + desplazamiento) % 26 + codigo_ascii
            resultado += chr(codigo_cifrado)
        else:
            resultado += caracter
    return resultado

def enviar_ping_modificado(ip_destino, mensaje):
    for i, caracter in enumerate(mensaje):
        tamano_paquete = ord(caracter) + 100
        # Crear un payload donde los primeros 8 bytes se basan en el tamaño del paquete
        payload = (f"{tamano_paquete:08d}"[:8]).encode()  # Los primeros 8 bytes como string del tamaño
        payload += b"X" * (tamano_paquete - 8)  # Rellenar el resto del payload con 'X'
        
        paquete = IP(dst=ip_destino)/ICMP(type="echo-request", id=0x0001, seq=i+1)/payload
        
        paquete.time = time.time()
        
        send(paquete, verbose=False)
        
        print(f"Enviando carácter: {caracter}")
        print(f"Tamaño del paquete: {tamano_paquete}")
        print(f"Timestamp: {paquete.time}")
        
        time.sleep(0.5)

    paquete_final = IP(dst=ip_destino)/ICMP(type="echo-request", id=0x0001, seq=len(mensaje)+1)/("X" * 1)
    paquete_final.time = time.time()
    send(paquete_final, verbose=False)
    print("Enviando marca de fin de mensaje")
    print(f"Timestamp: {paquete_final.time}")

mensaje = "criptografia y seguridad en redes"
ip_destino = "8.8.8.8"  # Ejemplo: Google DNS
desplazamiento = 9  # Desplazamiento para el cifrado César
mensaje_cifrado = cifrado_cesar(mensaje, desplazamiento)
print(f"Mensaje original: {mensaje}")
print(f"Mensaje cifrado: {mensaje_cifrado}")
print("Enviando pings modificados...")
enviar_ping_modificado(ip_destino, mensaje_cifrado)
print("Proceso completado.")
