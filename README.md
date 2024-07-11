# SplunkVuln

# POC para CVE-2024-36991: Traversal de Ruta en Splunk Enterprise

Este repositorio contiene una prueba de concepto (POC) para la vulnerabilidad CVE-2024-36991, que permite el traversal de ruta en Splunk Enterprise en versiones de Windows por debajo de 9.2.2, 9.1.5 y 9.0.10. El script está diseñado para identificar si un servidor Splunk es vulnerable al intentar acceder al archivo `/etc/passwd`.

## Descripción

La vulnerabilidad permite a un atacante no autenticado acceder a archivos sensibles en el servidor explotando una debilidad en la validación de rutas en el servidor Splunk. Este script intenta acceder al archivo `/etc/passwd` utilizando rutas de traversal específicas para sistemas operativos Windows.

## Uso

El script se puede usar para realizar escaneos únicos o masivos

### Escaneo Único

python Splunk-Path.py -u https://objetivo:9090 

### Escaneo Masivo

python Splunk-Path.py -l archive.txt 

## Parámetros

    -u, --url: URL del servidor Splunk a probar.
    -f, --file: Archivo de texto que contiene una lista de URLs (una por línea).

# Contribuciones

Las contribuciones son bienvenidas. Por favor, abre un issue o un pull request para mejorar este proyecto.


## SIN MIEDO AL EXITO

Hay mejoras posibles, como payloads mas extensos o mejores exposiciones se los dejo a su mejora al igual unir alguna otra herramienta para hacerlo mas cool 
