# MORAGL - Sistema de Asignación de Casos

Proyecto listo para subir a Render.

## Usuario inicial

- Usuario: `admin`
- Clave: `admin123`

Cambiar la clave luego del primer ingreso.

## Deploy en Render

Build Command:

```bash
pip install -r requirements.txt
```

Start Command:

```bash
gunicorn app:app
```

## Datos

Esta versión usa SQLite. En Render free puede servir para prueba inicial.
Para producción conviene migrar a PostgreSQL.
