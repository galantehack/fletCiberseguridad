import flet as ft
import cv2 #manejo de imagenes
import pytesseract #para extraer texto de la imagen procesada.
import requests #para scrapear la url
import time 
import webbrowser  # Para abrir la URL en el navegador
import os
import exifread
from pymediainfo import MediaInfo #es una biblioteca de Python que permite extraer metadatos de archivos multimedia
from fpdf import FPDF

# Tu API Key de VirusTotal
VIRUSTOTAL_API_KEY = "b2abe893eddb0833ab8353f8d2907be1c5b25465bc763923cc146279fc1c782a"

def main(page: ft.Page):
    page.title = "Detección de Phishing y Virus"
    page.horizontal_alignment = ft.CrossAxisAlignment.CENTER
    page.vertical_alignment = ft.MainAxisAlignment.CENTER
    page.bgcolor = "#003366" 
    page.window.min_width = 360
    page.window.min_height = 800
    page.window.max_width = 550
    page.window.max_height = 1000
   
    # Indicador de carga
    # Texto de carga
    loading_text = ft.Text(
        value="Cargando resultado...",
        color=ft.colors.GREEN,
        visible=False,
        size=20
    )
   
        
    
    
    # Función para analizar los metadatos del archivo
    def analizar_metadatos(archivo):
        try:
            media_info = MediaInfo.parse(archivo)
            metadatos = []
            for track in media_info.tracks:
                if track.track_type == 'General':
                    metadatos.append(f"Nombre del archivo: {track.file_name}")
                    metadatos.append(f"Tamaño del archivo: {track.file_size} bytes")
                    metadatos.append(f"Fecha de creación: {track.file_last_modification_date}")
                    metadatos.append(f"Duración: {track.duration} ms")
                    metadatos.append(f"Software: {track.encoded_library}")
                    metadatos.append(f"Formato: {track.format}")
                    metadatos.append(f"Libreria: {track.writing_library}")
                    
            return "\n".join(metadatos) if metadatos else "No se encontraron metadatos generales en el archivo."
        except Exception as e:
            return f"Error al analizar el archivo: {e}"
     # Función para expandir url   
    def expand_shortened_url(short_url):
        try:
            response = requests.head(short_url, allow_redirects=True)
            expanded_url = response.url
            return expanded_url
        except Exception as e:
            return f"Error al expandir la URL: {str(e)}"

    # Función para analizar el archivo en VirusTotal
    def analyze_file_with_virustotal(file_path):
        url = "https://www.virustotal.com/api/v3/files"
        headers = {
            "x-apikey": VIRUSTOTAL_API_KEY
        }
        files = {
            "file": (file_path, open(file_path, "rb"))
        }
        response = requests.post(url, headers=headers, files=files)
        if response.status_code == 200:
            result = response.json()
            analysis_id = result["data"]["id"]
            return analysis_id
        else:
            result_text.value = "Error al subir el archivo a VirusTotal."
            result_text.color = "red"
            result_text.update()
            return None

    # Función para obtener el resultado del análisis en VirusTotal
    def get_virustotal_analysis_result(analysis_id):
        url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
        headers = {
            "x-apikey": VIRUSTOTAL_API_KEY
        }
        while True:
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                result = response.json()
                if result["data"]["attributes"]["status"] == "completed":
                    scans = result["data"]["attributes"]["results"]
                    return scans
                else:
                    time.sleep(5)
            else:
                result_text.value = "Error al obtener el resultado de VirusTotal."
                result_text.color = "red"
                result_text.update()
                return None

    # Función para analizar la URL en VirusTotal
    def analyze_url_with_virustotal(url):
        api_url = "https://www.virustotal.com/api/v3/urls"
        headers = {
            "x-apikey": VIRUSTOTAL_API_KEY
        }
        response = requests.post(api_url, headers=headers, data={"url": url})
        if response.status_code == 200:
            result = response.json()
            analysis_id = result["data"]["id"]
            return analysis_id
        else:
            result_text.value = "Error al subir la URL a VirusTotal."
            result_text.color = "red"
            result_text.update()
            return None

    # Función para obtener el resultado del análisis de la URL
    def get_url_analysis_result(analysis_id):
        url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
        headers = {
            "x-apikey": VIRUSTOTAL_API_KEY
        }
        while True:
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                result = response.json()
                if result["data"]["attributes"]["status"] == "completed":
                    scans = result["data"]["attributes"]["results"]
                    return scans
                else:
                    time.sleep(5)
            else:
                result_text.value = "Error al obtener el resultado del análisis."
                result_text.color = "red"
                result_text.update()
                return None

    # Función para procesar la imagen y analizar phishing
    def process_image(e):
        if file_picker.result.files:
            file_path = file_picker.result.files[0].path
            resultados = []  # Lista para acumular los resultados
            # Mostrar el texto de carga
            loading_text.visible = True
            page.update()
            # Analizar metadatos
            metadatos = analizar_metadatos(file_path)
            resultados.append(f"Metadatos: {metadatos}")

            # Analizar el archivo con VirusTotal
            analysis_id = analyze_file_with_virustotal(file_path)
            if analysis_id:
                scans = get_virustotal_analysis_result(analysis_id)
                if scans:
                    if any(result["category"] == "malicious" for result in scans.values()):
                        resultados.append("Archivo malicioso detectado.")
                        result_text.color = "red"
                    else:
                        resultados.append("No se detectó ningún archivo malicioso en VirusTotal.")
                        result_text.color = "green"
                    # Mostrar el reporte en una tabla
                    update_report_table(scans)
                else:
                    resultados.append("No se pudo obtener el resultado del análisis.")
            else:
                resultados.append("No se pudo analizar el archivo en VirusTotal.")

            # Procesar la imagen para detectar phishing
            img = cv2.imread(file_path)
            if img is None:
               print("Error: No se pudo cargar la imagen en", file_path)
               # Oculta el texto de carga
               loading_text.visible = False
               page.update()
            else:
                # Convierte la imagen a escala de grises
                gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
                
                # Aplica umbral para binarizar la imagen
                _, thresh = cv2.threshold(gray, 150, 255, cv2.THRESH_BINARY_INV)
                
                # Extrae el texto de la imagen usando pytesseract
                text = pytesseract.image_to_string(thresh)
                print(text)  # Imprime en consola el texto extraído de la imagen
                
                # Palabras clave para detectar phishing
                phishing_keywords = ["password", "login", "verify", "account", "urgent"]
                
                # Verifica si alguna de las palabras clave está en el texto extraído
                if any(keyword in text.lower() for keyword in phishing_keywords):
                    resultados.append("Posible correo de phishing detectado.")
                    result_text.color = "red"
                else:
                    resultados.append("No se detectaron señales de phishing.")
                    result_text.color = "green"
                
                # Actualiza el texto de resultados en la interfaz
                result_text.value = "\n".join(resultados)
                result_text.update()
                
                # Oculta el texto de carga
                loading_text.visible = False
                page.update()

        # Si no se seleccionó un archivo
        else:
            result_text.value = "No se seleccionó ningún archivo."
            result_text.color = "orange"
            result_text.update()



    # Función para analizar una URL
    def process_url(e):
        url = url_input.value
        if url:
            expanded_url = expand_shortened_url(url)
            analysis_id = analyze_url_with_virustotal(expanded_url)
            # Mostrar el texto de carga
            loading_text.visible = True
            page.update()
            
            if analysis_id:
                scans = get_url_analysis_result(analysis_id)
                result_list = []  # Lista para almacenar los resultados
                
                if scans:
                    # Agregar la URL expandida a la lista
                    result_list.append(f"URL expandida: {expanded_url}")
                    
                    # Revisar si alguno de los motores detecta que la URL es maliciosa
                    if any(result["category"] == "malicious" for result in scans.values()):
                        result_list.append("URL maliciosa detectada.")
                        result_text.color = "red"
                    else:
                        result_list.append("No se detectó ninguna amenaza en la URL.")
                        result_text.color = "green"

                    # Actualizar el resultado
                    result_text.value = "\n".join(result_list)
                    
                    # Mostrar el reporte en la tabla
                    update_report_table(scans)
                else:
                    result_text.value = "No se pudo obtener el resultado del análisis."
                    result_text.color = "orange"
            else:
                result_text.value = "No se pudo analizar la URL en VirusTotal."
                result_text.color = "orange"
            # Ocultar el texto de carga
            loading_text.visible = False
            page.update()
        else:
            result_text.value = "No se ingresó ninguna URL."
            result_text.color = "orange"

        result_text.update()



    # Función para abrir la página de denuncia en el navegador
    def open_denuncia_page(e):
        webbrowser.open("https://adenunciar.policia.gov.co/Adenunciar/frm_terminos.aspx")
    
    
    def clear_results(e):
        result_text.value = ""
        url_input.value = ""
        file_picker.result.files = []
        result_text.color = "black"
        report_table.rows = []
        report_table.update()
        result_text.update()
        
    # Función para exportar a PDF con título y estilo de reporte
    def export_to_pdf(e):
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Arial", size=12)

        # Agregar título
        pdf.set_font("Arial", style='B', size=16)
        pdf.cell(0, 10, "Reporte de Análisis de Phishing y Virus", ln=True, align='C')
        pdf.ln(10)  # Salto de línea
        
        # Agregar subtítulo
        pdf.set_font("Arial", style='B', size=14)
        pdf.cell(0, 10, "Resultados del Análisis", ln=True)
        pdf.ln(5)  # Salto de línea
        
        # Agregar texto de resultados
        pdf.set_font("Arial", size=12)
        pdf.multi_cell(0, 10, result_text.value)

        # Guardar el archivo PDF
        pdf_file = "resultados.pdf"
        pdf.output(pdf_file)
        
        # Mostrar diálogo de confirmación
        page.dialog(
            content=ft.Text(f"Archivo PDF guardado como {pdf_file}."),
            actions=[ft.TextButton("Aceptar")]
        ).show()
           
    # Función para actualizar la tabla de reportes
    def update_report_table(scans):
        rows = []
        for engine, result in scans.items():
            status = "Detectado" if result["category"] == "malicious" else "No Detectado"
            status_color = "red" if result["category"] == "malicious" else "green"
            rows.append(ft.DataRow(cells=[
                ft.DataCell(ft.Text(engine, color="cyan")),  # Color blanco para el motor
                ft.DataCell(ft.Text(status, color=status_color))  # Color condicionado para el estado
            ]))
        report_table.rows = rows
        report_table.update()

    # Selector de archivos
    file_picker = ft.FilePicker(on_result=process_image)
    page.overlay.append(file_picker)

    # Campo de texto para ingresar URL
    url_input = ft.TextField(
        label="Ingrese una URL para analizar",
        bgcolor="white",  # Fondo verde oscuro
        color="black",  # Color del texto
        border_color="#006138"
    )

    # Botón para cargar archivo
    upload_button = ft.ElevatedButton(
        "Cargar Archivo",  # Texto del botón
        style=ft.ButtonStyle(
            padding={ft.ControlState.HOVERED: 20},
            overlay_color=ft.colors.TRANSPARENT,
        ),
        on_click=lambda _: file_picker.pick_files(allow_multiple=False)  # Acción al hacer clic
    )

    # Botón para analizar URL
    analyze_url_button = ft.ElevatedButton(
        "Analizar URL",  # Texto del botón
        style=ft.ButtonStyle(
            padding={ft.ControlState.HOVERED: 20},
            overlay_color=ft.colors.TRANSPARENT,
        ),
        on_click=process_url  # Acción al hacer clic
    )


    # Botón para abrir la página de denuncia
    open_denuncia_button = ft.ElevatedButton(
    "Abrir Página de Denuncia",  # Texto del botón
    style=ft.ButtonStyle(
        padding={ft.ControlState.HOVERED: 20},
        overlay_color=ft.colors.TRANSPARENT,
    ),
    on_click=open_denuncia_page  # Acción al hacer clic
)

    
    
    

    # Texto para mostrar los resultados
   
    label_text = ft.Text(
    value="Resultados",
    color="yellow",  # Cambiar el color del label
    size=16,  # Tamaño del label
)

    result_text = ft.TextField(
        multiline=True,
        width=460,
        height=150,
        text_align=ft.TextAlign.LEFT,
        
        color="white",  # Texto en blanco
        
    )

    # Tabla para mostrar el reporte
    report_table = ft.DataTable(
    columns=[
        ft.DataColumn(ft.Text("Motor de Análisis", color="cyan", text_align="center" )),
        ft.DataColumn(ft.Text("Estado", color="lightgreen", text_align="center"))
    ],
    rows=[],
   
    
)

# Contenedor con desplazamiento para la tabla, con mejor estilo
    table_container = ft.Container(
        content=ft.Column(
            controls=[
                report_table
            ],
            scroll=ft.ScrollMode.AUTO,  # Agregar el scroll automático
           
        ),
        width=360,  # Ajusta el ancho según tus necesidades
        height=200,  # Ajusta la altura según tus necesidades
        bgcolor="white",  # Fondo verde oscuro para el contenedor de la tabla
        border_radius=10,  # Radio del borde para esquinas redondeadas
        padding=10,  # Agregar espacio alrededor de la tabla
        margin=10,  # Agregar espacio alrededor del contenedor
        
        
        
    )
    clear_button = ft.ElevatedButton(
    "Limpiar Resultados",  # Texto del botón
    icon=ft.icons.CLEAR,  # Ícono del botón
    style=ft.ButtonStyle(
        bgcolor=ft.colors.WHITE,  # Fondo blanco
        padding={ft.ControlState.HOVERED: 20},
        overlay_color=ft.colors.TRANSPARENT,
    ),
    on_click=clear_results  # Acción al hacer clic
)

    
    titulo = ft.Text("Analista Cibereguridad")
    app_bar = ft.AppBar(
        title=titulo,
        center_title= True,
        color="white",
         bgcolor="#003366",
        
    )
    pdf_button = ft.ElevatedButton(
    text="Exportar a PDF",  # Texto del botón
    icon=ft.icons.DOWNLOAD,  # Ícono de exportación o descarga
    on_click=export_to_pdf,  # Acción al hacer clic
    style=ft.ButtonStyle(
        bgcolor={
            ft.ControlState.DEFAULT: ft.colors.WHITE,  # Color de fondo por defecto
            ft.ControlState.HOVERED: ft.colors.GREEN,  # Color de fondo al pasar el cursor
        },
        padding={ft.ControlState.HOVERED: 20},
        overlay_color=ft.colors.TRANSPARENT,
    )
)

    
    button_row = ft.Row(
    controls=[
        analyze_url_button,
        upload_button,
    ],
    alignment=ft.MainAxisAlignment.CENTER  # Centrar los botones horizontalmente
)

    # Agregar los elementos a la página
   
    
    
    page.add(
    app_bar,
    ft.Container(
        alignment=ft.alignment.center,
        gradient=ft.LinearGradient(
            begin=ft.alignment.top_left,
            end=ft.Alignment(0.8, 1),
            colors=[
                "0xff001f3f",  # Azul oscuro profundo
                "0xff003366",  # Azul cibernético
                "0xff004080",  # Azul intermedio
                "0xff00509d",  # Azul más claro
                "0xff006bb3",  # Azul cian oscuro
                "0xff007acc",  # Azul cian medio
                "0xff0088e6",  # Azul más vibrante
                "0xff3399ff",  # Azul claro cibernético
            ],
            tile_mode=ft.GradientTileMode.MIRROR,
        ),
        
        padding=20,  # Espacio alrededor de los componentes
        content=ft.ResponsiveRow(
            [
                # Organizando url_input y button_row en columnas responsivas
                ft.Container(
                    content=url_input,
                    col={"sm": 12, "md": 6, "xl": 4},
                ),
                ft.Container(
                    content=button_row,
                    col={"sm": 12, "md": 6, "xl": 4},
                ),
                
                ft.Container(
                    content=open_denuncia_button,
                    col={"sm": 12, "md": 6, "xl": 4},
                ),
                ft.Container(
                    content=ft.Column(
                        [label_text, loading_text, result_text],
                        spacing=10
                    ),
                    col={"sm": 12, "md": 6, "xl": 4},
                ),
                # Agregar los botones PDF y clear
                ft.Container(
                    content=pdf_button,
                    col={"sm": 6, "md": 3},
                ),
                ft.Container(
                    content=clear_button,
                    col={"sm": 6, "md": 3},
                ),
                # Tabla, ajustada en pantalla completa
                ft.Container(
                    content=table_container,
                    col={"sm": 12, "md": 12},
                ),
            ],
            run_spacing=10,  # Espacio entre los elementos
            alignment="center",  # Alineación central
        ),
    )
)

# Si tienes un resize handler para ajustar elementos
 
  

ft.app(target=main)
