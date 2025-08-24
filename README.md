# wesview
Enhanced viewer for WES-NG output with colors and filters

# WESView - Windows Exploit Sugester Enhanced Viewer

Una herramienta para visualizar y filtrar resultados de WES-NG con colores y filtros avanzados.

## Características

- Output colorizado para mejor visualización
- Filtros avanzados por impacto, severidad, producto, etc.
- Ordenamiento inteligente (vulnerabilidades críticas primero)
- Compatibilidad con paginadores (less -R)
- liminación de duplicados automática

## Instalación rápida

```bash
# Descargar
git clone https://github.com/adrian-orthuela/wesview.git
cd wesview

# Instalar dependencias
pip install colorama
```

## Uso

```bash
# Uso básico
python3 wesview.py vulns.txt

# Con filtros
python3 wesview.py vulns.txt --impact "Elevation of Privilege" --severity Critical

# Con paginación
python3 wesview.py vulns.txt --product "Windows Server 2012 R2" | less -R
```

## Opciones disponibles

| Opción | Descripción |
|--------|-------------|
| `--impact`, `-i` | Filtrar por tipo de impacto |
| `--severity`, `-s` | Filtrar por severidad |
| `--product`, `-p` | Filtrar por producto |
| `--component`, `-c` | Filtrar por componente |
| `--cve` | Filtrar por CVE específico |
| `--kb` | Filtrar por KB específico |
| `--date`, `-d` | Filtrar por fecha |
| `--no-color` | Desactivar colores |

## Requisitos

- Python 3.x
- Colorama: `pip install colorama`

## Licencia

MIT License
