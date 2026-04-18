# Portal GRC — Análisis de Logs de Seguridad

Portal web para el análisis de logs de eventos de seguridad bajo un enfoque de Gobierno, Riesgo y Cumplimiento (GRC). Permite cargar registros de actividad, detectar eventos críticos, identificar usuarios sospechosos, monitorear accesos fuera de horario y obtener conclusiones de gobierno derivadas directamente de los datos analizados.

## Qué hace

El sistema recibe un archivo de logs con formato estructurado y produce cuatro análisis:

1. **Parser de eventos** — estructura cada línea en fecha, tipo de evento y detalle.
2. **Eventos críticos** — detecta operaciones DELETE y EXPORT con el usuario y recurso involucrado.
3. **Usuarios sospechosos** — cruza los eventos contra una lista configurable de usuarios de riesgo.
4. **Actividad fuera de horario** — identifica eventos ocurridos fuera del rango operativo configurado.

Además genera respuestas de análisis de gobierno sobre el evento más crítico, los riesgos representados y los controles que fallaron, derivadas dinámicamente de cada conjunto de logs analizado.

## Formato de logs

Cada línea debe seguir esta estructura:

```
YYYY-MM-DD HH:MM:SS | EVENTO | detalle
```

Los eventos soportados son `LOGIN`, `ACCESS`, `QUERY`, `EXPORT` y `DELETE`. El evento `LOGIN` requiere los campos `user=` e `ip=` en el detalle.

Ejemplo:

```
2026-04-09 01:00:01 | LOGIN | user=admin | ip=10.0.0.1
2026-04-09 01:00:15 | EXPORT | users.csv
2026-04-09 03:45:20 | DELETE | TABLE users
```

## Requisitos

- Python 3.9 o superior
- Sin dependencias externas — la librería estándar es suficiente

## Ejecución

```bash
# Clonar el repositorio
git clone https://github.com/FernandoAjset/tarea-grc-caso-01.git
cd tarea-grc-caso-01

# Iniciar el servidor
python3 backend.py
```

El portal queda disponible en `http://localhost:8000`.

Para usar un puerto distinto:

```bash
PORT=9000 python3 backend.py
```

## Configuración

El directorio `data/` se crea automáticamente al primer inicio con valores por defecto.

- `data/settings.json` — define el rango horario que se considera fuera de operación.
- `data/suspect_users.json` — lista de usuarios clasificados como sospechosos.

Ambos archivos son editables desde la interfaz del portal sin necesidad de reiniciar el servidor.

## Estructura del proyecto

```
tarea-grc-caso-01/
├── backend.py          # Servidor HTTP y motor de análisis
├── portal.html         # Interfaz web
├── logs_input.txt      # Logs de ejemplo (7 eventos)
├── logs_input_200.txt  # Logs de ejemplo extendidos (200 eventos)
├── logs_invalidos.txt  # Casos de validación con errores
└── data/
    ├── settings.json
    └── suspect_users.json
```

## Aviso

Este proyecto es de carácter estrictamente académico, desarrollado como práctica del curso de Maestría en Gestión de Riesgos y Cumplimiento. No está diseñado para uso en entornos de producción. Los datos de ejemplo incluidos son ficticios.

## Autores

- [Fernando Ajset](https://github.com/FernandoAjset)
- [Miguel Samayoa](https://github.com/MiguelSamayoa)
- [Brizeth Alvarado](https://github.com/BrizAlv)
- [Katerine Franco](https://github.com/KaterineFrk)
