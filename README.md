# Cifrado y Descifrado de Archivos con AES (Modo CTR) en Python

[![Python 3.8+](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![Cryptography](https://img.shields.io/badge/Cryptography-AES--CTR-success.svg)](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Herramienta de consola interactiva en Python para el cifrado y descifrado simétrico de archivos binarios (imágenes, documentos, ejecutables, texto) utilizando el algoritmo estándar **AES (Advanced Encryption Standard / Rijndael)** en modo de operación **CTR (Counter Mode)** y codificación **Base64**.

---

## 🔐 Fundamento Criptográfico

El Estándar de Cifrado Avanzado (AES, especificado en el estándar federal **FIPS PUB 197**) es un cifrador por bloques simétrico con un tamaño de bloque fijo de 128 bits (16 bytes). Admite longitudes de clave criptográfica de 128, 192 y 256 bits, realizando respectivamente 10, 12 o 14 rondas de transformación por sustitución y permutación (SubBytes, ShiftRows, MixColumns y AddRoundKey).

### Modo de Operación CTR (Counter Mode)

A diferencia de los modos ECB (inseguro ante análisis de patrones) o CBC (que requiere relleno o padding estricto):
- El **Modo CTR** convierte el cifrador de bloques en un cifrador de flujo (*stream cipher*).
- Genera un bloque de clave continuo cifrando valores sucesivos de un contador incremental.
- La operación de cifrado y descifrado se realiza aplicando una operación XOR bit a bit ($\oplus$) entre el flujo de texto plano y el flujo generado:

$$C_i = P_i \oplus \text{AES}_K(\text{Counter}_i)$$
$$P_i = C_i \oplus \text{AES}_K(\text{Counter}_i)$$

- **Ventajas:** No requiere relleno (padding), permite acceso aleatorio a los bloques y admite procesamiento de flujos de cualquier longitud.

### Pipeline de Procesamiento de Archivos

```mermaid
flowchart LR
    A["Archivo Binario (e.g. imagen.jpg)"] --> B["Serializacion Base64"]
    B --> C["Cifrador AES-CTR (128/192/256 bits)"]
    C --> D["Archivo Cifrado Resultante"]
    D --> E["Descifrador AES-CTR"]
    E --> F["Decodificacion Base64"]
    F --> G["Archivo Binario Original Restaurado"]
```

---

## 📂 Estructura del Repositorio

```text
aes-files/
├── main.py        # Script interactivo de consola para cifrar y descifrar
├── imagen.jpg     # Archivo de imagen de prueba para validacion
└── Video.txt      # Enlace a demostracion multimedia en YouTube
```

---

## 🚀 Requisitos e Instalación

### Prerrequisitos

- **Python** (versión 3.8 o superior).

### Instalación de Dependencias

El script utiliza la biblioteca `pyaes` (implementación de AES en Python puro sin dependencias de compiladores C):

```bash
pip install pyaes
```

---

## 💻 Guía de Uso

Ejecuta el script principal desde la terminal:

```bash
python main.py
```

### 1. Cifrar un Archivo

1. Selecciona la opción `1`.
2. Ingresa la ruta o nombre del archivo (ejemplo: `imagen.jpg`).
3. Proporciona la clave secreta con la longitud correspondiente:
   - **16 caracteres (16 bytes)**: Modo **AES-128 bits** (ejemplo: `CLAVEDE128BITSSS`).
   - **24 caracteres (24 bytes)**: Modo **AES-192 bits** (ejemplo: `CLAVE_DE_192_BITS_24BYTE`).
   - **32 caracteres (32 bytes)**: Modo **AES-256 bits** (ejemplo: `CLAVE_DE_256_BITS_-_32_BYTES00GG`).
4. El archivo quedará cifrado en disco, protegido contra accesos no autorizados.

### 2. Descifrar un Archivo

1. Selecciona la opción `2`.
2. Ingresa el nombre del archivo cifrado.
3. Introduce con exactitud la misma clave secreta utilizada durante el cifrado.
4. El archivo binario original se reconstruirá en su estado original sin pérdida de bytes.

---

## 📹 Demostración en Video

Puedes consultar la explicación práctica y demostración en video en el siguiente enlace:
[Demostración en YouTube](https://youtu.be/wY7iB2-m-4s)

---

## 📄 Licencia

Distribuido bajo la Licencia MIT. Consulta el archivo `LICENSE` para más información.
