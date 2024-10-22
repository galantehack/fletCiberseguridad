import flet as ft
import cv2
import pytesseract
import requests
import time
import webbrowser  # Para abrir la URL en el navegador

# Tu API Key de VirusTotal
VIRUSTOTAL_API_KEY = "b2abe893eddb0833ab8353f8d2907be1c5b25465bc763923cc146279fc1c782a"

def main(page: ft.Page):
    page.title = "Detección de Phishing y Virus"
    page.horizontal_alignment = ft.CrossAxisAlignment.CENTER
    page.vertical_alignment = ft.MainAxisAlignment.CENTER
    page.bgcolor = "#057348" 
    page.window_min_width = 360
    page.window_min_height = 640

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

            # Analizar el archivo con VirusTotal
            analysis_id = analyze_file_with_virustotal(file_path)
            if analysis_id:
                scans = get_virustotal_analysis_result(analysis_id)
                if scans:
                    if any(result["category"] == "malicious" for result in scans.values()):
                        result_text.value = "Archivo malicioso detectado."
                        result_text.color = "red"
                    else:
                        result_text.value = "No se detectó ningún archivo malicioso en VirusTotal."
                        result_text.color = "green"
                    # Mostrar el reporte en una tabla
                    update_report_table(scans)
                else:
                    result_text.value = "No se pudo obtener el resultado del análisis."
            else:
                result_text.value = "No se pudo analizar el archivo en VirusTotal."

            # Procesar la imagen para detectar phishing
            img = cv2.imread(file_path)
            gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
            _, thresh = cv2.threshold(gray, 150, 255, cv2.THRESH_BINARY_INV)
            text = pytesseract.image_to_string(thresh)

            phishing_keywords = ["password", "login", "verify", "account", "urgent"]
            if any(keyword in text.lower() for keyword in phishing_keywords):
                result_text.value += "\nPosible correo de phishing detectado."
                result_text.color = "red"
            else:
                result_text.value += "\nNo se detectaron señales de phishing."
                result_text.color = "green"
        else:
            result_text.value = "No se seleccionó ningún archivo."
            result_text.color = "orange"

        result_text.update()

    # Función para analizar una URL
    def process_url(e):
        url = url_input.value
        if url:
            analysis_id = analyze_url_with_virustotal(url)
            if analysis_id:
                scans = get_url_analysis_result(analysis_id)
                if scans:
                    if any(result["category"] == "malicious" for result in scans.values()):
                        result_text.value = "URL maliciosa detectada."
                        result_text.color = "red"
                    else:
                        result_text.value = "No se detectó ninguna amenaza en la URL."
                        result_text.color = "green"
                    # Mostrar el reporte en una tabla
                    update_report_table(scans)
                else:
                    result_text.value = "No se pudo obtener el resultado del análisis."
                    result_text.color = "orange"
            else:
                result_text.value = "No se pudo analizar la URL en VirusTotal."
                result_text.color = "orange"
        else:
            result_text.value = "No se ingresó ninguna URL."
            result_text.color = "orange"

        result_text.update()

    # Función para abrir la página de denuncia en el navegador
    def open_denuncia_page(e):
        webbrowser.open("https://adenunciar.policia.gov.co/Adenunciar/frm_terminos.aspx")
        
    # Función para actualizar la tabla de reportes
    def update_report_table(scans):
        rows = []
        for engine, result in scans.items():
            status = "Detectado" if result["category"] == "malicious" else "No Detectado"
            rows.append(ft.DataRow(cells=[
                ft.DataCell(ft.Text(engine)),
                ft.DataCell(ft.Text(status))
            ]))
        report_table.rows = rows
        report_table.update()

    # Selector de archivos
    file_picker = ft.FilePicker(on_result=process_image)
    page.overlay.append(file_picker)

    # Campo de texto para ingresar URL
    url_input = ft.TextField(
        label="Ingrese una URL para analizar",
        bgcolor="#a3f67f",  # Fondo verde oscuro
        color="white",  # Color del texto
        border_color="#006138"
    )

    # Botón para cargar archivo
    upload_button = ft.ElevatedButton(
        text="Cargar Archivo",
        on_click=lambda _: file_picker.pick_files(allow_multiple=False)
    )

    # Botón para analizar URL
    analyze_url_button = ft.ElevatedButton(
        text="Analizar URL",
        on_click=process_url
    )

    # Botón para abrir la página de denuncia
    open_denuncia_button = ft.ElevatedButton(
        text="Abrir Página de Denuncia",
        on_click=open_denuncia_page
    )

    # Texto para mostrar los resultados
    result_text = ft.Text(
        value="",
        color="white",  # Texto en blanco para resaltar en fondo verde oscuro
        
        text_align=ft.TextAlign.LEFT,
      
    )

    # Tabla para mostrar el reporte
    report_table = ft.DataTable(
        columns=[
            ft.DataColumn(ft.Text("Motor de Análisis", color="white")),
            ft.DataColumn(ft.Text("Estado", color="white"))
        ],
        rows=[]
    )

    # Contenedor con desplazamiento para la tabla
    table_container = ft.Container(
        content=ft.Column(
            controls=[
                report_table
            ],
            scroll=ft.ScrollMode.AUTO  # Agregar el scroll automático
        ),
         #aqui los estilos de la tabla 
                width=1000,  # Ajusta el ancho según tus necesidades
                height=450,  # Ajusta la altura según tus necesidades
                bgcolor="#004d40",  # Fondo verde oscuro para el contenedor de la tabla
                border_radius=5,
                col=12,
    )
    titulo = ft.Text("Analista Cibereguridad")
    app_bar = ft.AppBar(
        title=titulo,
        center_title= True,
        color="white",
         bgcolor="#004d40",
        
    )
    button_row = ft.Row(
        controls=[
            analyze_url_button,
            upload_button,
            open_denuncia_button
    ]
)
    # Agregar los elementos a la página
    page.add(
        app_bar,
        url_input,
        button_row,
        result_text,
        table_container
    )

ft.app(target=main)
