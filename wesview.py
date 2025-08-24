#!/usr/bin/env python3
import csv
import sys
import os
import argparse
from colorama import init, Fore, Style

# Forzar inicialización de Colorama con colores
init(autoreset=True, strip=False)

def parse_arguments():
    parser = argparse.ArgumentParser(description='Analizador de vulnerabilidades con colores y filtros')
    parser.add_argument('archivo', help='Archivo CSV de vulnerabilidades')
    parser.add_argument('--impact', '-i', help='Filtrar por tipo de impacto (ej: "Elevation of Privilege")')
    parser.add_argument('--severity', '-s', help='Filtrar por severidad (ej: "Critical", "Important")')
    parser.add_argument('--product', '-p', help='Filtrar por producto afectado')
    parser.add_argument('--component', '-c', help='Filtrar por componente afectado')
    parser.add_argument('--cve', help='Filtrar por CVE específico')
    parser.add_argument('--kb', help='Filtrar por KB específico')
    parser.add_argument('--date', '-d', help='Filtrar por fecha (ej: "2024")')
    parser.add_argument('--no-color', action='store_true', help='Desactivar colores')
    return parser.parse_args()

def aplicar_filtros(vulns, args):
    filtered_vulns = []
    
    for row in vulns:
        while len(row) < 9:
            row.append("")
            
        date, cve, kb, title, affected_product, component, severity, impact, critical_severity = row

        # Aplicar filtros
        cumple_filtro = True
        
        if args.impact and args.impact.lower() not in impact.lower():
            cumple_filtro = False
        if args.severity and args.severity.lower() not in severity.lower():
            cumple_filtro = False
        if args.product and args.product.lower() not in affected_product.lower():
            cumple_filtro = False
        if args.component and args.component.lower() not in component.lower():
            cumple_filtro = False
        if args.cve and args.cve.lower() not in cve.lower():
            cumple_filtro = False
        if args.kb and args.kb.lower() not in kb.lower():
            cumple_filtro = False
        if args.date and args.date not in date:
            cumple_filtro = False
            
        if cumple_filtro:
            filtered_vulns.append(row)
            
    return filtered_vulns

def main():
    args = parse_arguments()
    
    if args.no_color:
        global Fore, Style
        class NoColor:
            def __getattr__(self, name):
                return ''
        Fore = NoColor()
        Style = NoColor()

    csv_file = args.archivo

    # Leer todas las filas
    vulns = []
    seen = set()

    try:
        with open(csv_file, newline='', encoding='utf-8') as f:
            reader = csv.reader(f)
            headers = next(reader, None)
            for row in reader:
                if len(row) < 9:
                    continue
                
                row_key = (row[0], row[1], row[2], row[3])
                if row_key not in seen:
                    seen.add(row_key)
                    vulns.append(row)
    except FileNotFoundError:
        print(f"Error: No se encontró el archivo {csv_file}")
        sys.exit(1)
    except Exception as e:
        print(f"Error al leer el archivo: {e}")
        sys.exit(1)

    # Aplicar filtros
    vulns_filtradas = aplicar_filtros(vulns, args)
    
    if not vulns_filtradas:
        print("No se encontraron vulnerabilidades que coincidan con los filtros.")
        sys.exit(0)

    def severity_key(row):
        if len(row) < 7:
            return 0
        sev = row[6].strip().lower()
        if sev == "critical":
            return 2
        elif sev == "important":
            return 1
        else:
            return 0

    vulns_filtradas.sort(key=severity_key, reverse=True)

    def color_value(label, value, color=None):
        if value is None or value == "" or value == "N/A":
            value = "N/A"
            color = Fore.LIGHTBLACK_EX
        colored_val = (color + value + Style.RESET_ALL) if color else value
        return f"{Fore.CYAN}{label}:{Style.RESET_ALL} {colored_val}"

    try:
        # Mostrar información del filtro
        print(f"{Fore.YELLOW}=== FILTROS APLICADOS ===")
        filters_applied = []
        if args.impact: filters_applied.append(f"Impacto: {args.impact}")
        if args.severity: filters_applied.append(f"Severidad: {args.severity}")
        if args.product: filters_applied.append(f"Producto: {args.product}")
        if args.component: filters_applied.append(f"Componente: {args.component}")
        if args.cve: filters_applied.append(f"CVE: {args.cve}")
        if args.kb: filters_applied.append(f"KB: {args.kb}")
        if args.date: filters_applied.append(f"Fecha: {args.date}")
        
        if filters_applied:
            print(", ".join(filters_applied))
        else:
            print("Sin filtros (mostrando todas las vulnerabilidades)")
        print(f"Vulnerabilidades encontradas: {len(vulns_filtradas)}/{len(vulns)}")
        print(f"{'=' * 50}{Style.RESET_ALL}")
        print()

        for i, row in enumerate(vulns_filtradas):
            while len(row) < 9:
                row.append("")
                
            date, cve, kb, title, affected_product, component, severity, impact, critical_severity = row

            # Limpiar valores
            date = date.strip() if date else ""
            cve = cve.strip() if cve else ""
            kb = kb.strip() if kb else ""
            title = title.strip() if title else ""
            affected_product = affected_product.strip() if affected_product else ""
            component = component.strip() if component else ""
            severity = severity.strip() if severity else ""
            impact = impact.strip() if impact else ""
            critical_severity = critical_severity.strip() if critical_severity else ""

            # Colores específicos
            impact_colored = Fore.RED if impact and impact.lower() not in ["none", "n/a", ""] else Fore.LIGHTBLACK_EX
            critical_colored = Fore.RED if critical_severity and critical_severity.lower() == "critical" else Fore.LIGHTBLACK_EX
            
            sev_color = None
            if severity.lower() == "critical":
                sev_color = Fore.RED + Style.BRIGHT
            elif severity.lower() == "important":
                sev_color = Fore.YELLOW + Style.BRIGHT
            elif severity.lower() == "moderate":
                sev_color = Fore.CYAN
            elif severity.lower() == "low":
                sev_color = Fore.GREEN
            else:
                sev_color = Fore.LIGHTBLACK_EX

            # Mostrar número de vulnerabilidad
            print(f"{Fore.GREEN}=== VULNERABILITY {i+1}/{len(vulns_filtradas)} ==={Style.RESET_ALL}")
            
            print(color_value("Date", date))
            print(color_value("CVE", cve, Fore.MAGENTA))
            if kb and kb.lower().startswith("kb"):
                print(color_value("KB", kb, Fore.BLUE))
            else:
                kb_display = "KB" + kb if kb and not kb.lower().startswith("kb") else kb
                print(color_value("KB", kb_display if kb_display else "N/A", Fore.BLUE))
            print(color_value("Title", title, Fore.WHITE + Style.BRIGHT))
            print(color_value("Product", affected_product))
            print(color_value("Component", component))
            print(color_value("Impact", impact, impact_colored))
            print(color_value("Critical", critical_severity, critical_colored))
            print(color_value("Severity", severity, sev_color))
            
            if i < len(vulns_filtradas) - 1:
                print(f"{Fore.LIGHTBLACK_EX}{'─' * 60}{Style.RESET_ALL}")
                print()

    except BrokenPipeError:
        sys.stderr.close()
        sys.exit(0)
    except IOError:
        sys.stderr.close()
        sys.exit(0)

if __name__ == "__main__":
    main()
