# Cifrado autenticado de archivos con AES-256-GCM en Python

[![CI](https://github.com/KevinAndrey96/python-aes-gcm-file-encryption/actions/workflows/ci.yml/badge.svg)](https://github.com/KevinAndrey96/python-aes-gcm-file-encryption/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.12%20%7C%203.13%20%7C%203.14-3776AB)
![Cobertura](https://img.shields.io/badge/cobertura-100%25-brightgreen)
![mypy](https://img.shields.io/badge/mypy-strict-2A6DB2)
[![Licencia: MIT](https://img.shields.io/badge/licencia-MIT-yellow.svg)](LICENSE)

Herramienta de línea de comandos y librería para **cifrar archivos de cualquier tamaño con AES-256-GCM**: deriva la clave de una frase de paso con scrypt, procesa el archivo por bloques con memoria constante, autentica cada bloque y su posición, y escribe el resultado de forma atómica para que un descifrado fallido nunca deje datos sin verificar en disco.

## Contenido

- [Diseño criptográfico](#diseño-criptográfico)
- [Formato del archivo](#formato-del-archivo)
- [Uso](#uso)
- [Arquitectura](#arquitectura)
- [Pruebas y calidad](#pruebas-y-calidad)
- [Historia del proyecto](#historia-del-proyecto)

## Diseño criptográfico

| Pieza | Elección | Por qué |
| :--- | :--- | :--- |
| Cifrado | AES-256-GCM de [`cryptography`](https://cryptography.io) | Confidencialidad e integridad en una sola primitiva, acelerada por hardware. |
| Clave | scrypt con $N = 2^{17}$, $r = 8$, $p = 1$ y sal aleatoria de 16 bytes | Convierte una frase de paso en 256 bits y encarece la fuerza bruta con 128 MiB de memoria por intento. |
| Bloques | Construcción STREAM de Hoang, Reyhanitabar, Rogaway y Vizár | Permite archivos grandes con memoria constante sin perder la autenticación del conjunto. |
| Nonce | prefijo aleatorio de 7 bytes, contador de 4 bytes y bandera de último bloque | Nunca se repite bajo la misma clave y fija la posición de cada bloque. |
| Datos asociados | la cabecera completa | Cambiar parámetros, sal o tamaño de bloque invalida todos los bloques. |

Con esta construcción se detectan, además de cualquier bit alterado, los ataques que un cifrado autenticado por bloques ingenuo dejaría pasar: **reordenar** bloques (el contador no coincide), **truncar** el archivo justo en un límite de bloque (el último bloque leído no lleva la bandera final) y **añadir** bloques al final. Una frase de paso equivocada falla en el primer bloque.

Los parámetros de scrypt viajan en la cabecera para poder subirlos en el futuro, pero se aceptan solo entre $2^{10}$ y $2^{22}$: un archivo malicioso no puede pedir una derivación que agote la memoria.

## Formato del archivo

```text
offset  bytes  campo
0       4      "AESF"
4       1      versión del formato (1)
5       3      scrypt: log2(N), r, p
8       4      tamaño de bloque en claro (64 KiB por defecto), big endian
12      16     sal de scrypt
28      7      prefijo del nonce
35      ...    bloques: AES-GCM(bloque) || etiqueta de 16 bytes
```

Cada bloque cifrado ocupa 16 bytes más que el original; un archivo vacío produce la cabecera y un único bloque final de 16 bytes.

## Uso

Requiere Python 3.12 o superior y [uv](https://docs.astral.sh/uv/).

```bash
uv sync
uv run aes-files encrypt informe.pdf informe.pdf.aesf
# Frase de paso:
# Repita la frase de paso:
uv run aes-files inspect informe.pdf.aesf
# formato: AESF v1
# scrypt: N=2^17 r=8 p=1
# bloque: 65536 bytes
uv run aes-files decrypt informe.pdf.aesf informe-copia.pdf
```

La frase de paso **nunca se pasa como argumento**, porque quedaría en el historial del shell y en la lista de procesos: se pide de forma interactiva o se toma de la variable de entorno `AES_FILES_PASSPHRASE`, pensada para scripts y CI. El destino no se sobrescribe sin `--force`; con `--force` se puede cifrar un archivo sobre sí mismo de forma segura, porque se escribe en un temporal y se reemplaza solo al terminar. Un archivo alterado o una frase incorrecta terminan con código 2 y no dejan salida.

Como librería:

```python
from pathlib import Path
from aes_files import EncryptionSettings, KdfParams, decrypt_bytes, encrypt_bytes, encrypt_file

sellado = encrypt_bytes(b"datos", "frase de paso larga")
decrypt_bytes(sellado, "frase de paso larga")   # b'datos'

encrypt_file(Path("a.csv"), Path("a.csv.aesf"), "frase", EncryptionSettings(KdfParams(log2_n=18)))
```

## Arquitectura

```text
src/aes_files/
  header.py   cabecera binaria, parámetros de scrypt y sus límites
  stream.py   derivación de clave y STREAM sobre AES-GCM para flujos de bytes
  files.py    archivos con escritura atómica y protección contra sobrescritura
  cli.py      comandos encrypt, decrypt e inspect
```

La única dependencia es `cryptography`. Los errores se reportan con `AuthenticationError`, `FormatError` y `OutputExistsError`.

## Pruebas y calidad

```bash
uv run pytest --cov
uv run ruff check src tests && uv run ruff format --check src tests
uv run mypy
```

33 pruebas con cobertura del 100 % de líneas y ramas. Cubren ida y vuelta con contenidos aleatorios generados por Hypothesis, tamaños en los límites de bloque, bits alterados en cabecera, cuerpo y etiqueta, bloques reordenados, truncamiento en un límite de bloque, frase incorrecta, normalización Unicode de la frase, escritura atómica y la interfaz de línea de comandos con frase interactiva o por variable de entorno. El pipeline de GitHub Actions ejecuta Ruff y mypy en modo estricto, las pruebas en Python 3.12, 3.13 y 3.14, una prueba de humo que cifra y descifra 300 KB aleatorios y compara el resultado byte a byte, y la construcción del paquete con `twine check`.

## Historia del proyecto

El proyecto nació en mayo de 2020 como laboratorio de la clase de criptografía, acompañado de un [video explicativo](https://youtu.be/KpJ-R5DsMy4): un script con `pyaes` que cifraba una imagen en modo CTR. Aquella versión usaba la frase escrita directamente como clave, el contador por defecto (dos archivos con la misma clave compartían flujo de claves, así que el XOR de ambos cifrados revelaba el XOR de los originales), no autenticaba nada y sobrescribía el archivo original. En 2026 se rediseñó como una herramienta de cifrado autenticado con derivación de clave, bloques con STREAM, escritura atómica, pruebas de manipulación y CI; además se eliminaron del historial el entorno virtual, los archivos del IDE y la imagen de prueba que se habían versionado. El código original se conserva en el tag [`v0.1-python-coursework-2020`](https://github.com/KevinAndrey96/python-aes-gcm-file-encryption/tree/v0.1-python-coursework-2020).

## Autor

**Kevin Andrey Herrera Silva** · [GitHub](https://github.com/KevinAndrey96)

## Licencia

Distribuido bajo la [licencia MIT](LICENSE).
