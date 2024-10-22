from playwright.sync_api import sync_playwright

def run(playwright):
    try:
        # Ruta al ejecutable de Google Chrome
        chrome_path = r"C:\Program Files\Google\Chrome\Application\chrome.exe"
        
        # Lanzar el navegador usando Google Chrome
        browser = playwright.chromium.launch(executable_path=chrome_path, headless=False)
        page = browser.new_page()
        
        # Abrir la página deseada
        page.goto('https://www.facebook.com/Diosmehizolibre1')
        
        # Esperar a que la página cargue completamente
        page.wait_for_load_state('networkidle')

        # Asegurarse de que los elementos estén disponibles antes de interactuar con ellos
        like_buttons = page.locator("text=like")
        like_buttons_count = like_buttons.count()
        
        if like_buttons_count > 0:
            for i in range(like_buttons_count):
                like_buttons.nth(i).click()
                # Opcional: esperar un intervalo entre clics para evitar problemas de detección
                page.wait_for_timeout(2000)  # Espera de 2 segundos entre clics
        else:
            print("No se encontraron botones de 'like'.")

    except Exception as e:
        print(f"Se produjo un error: {e}")
    
    finally:
        # Cerrar el navegador
        if 'browser' in locals():
            browser.close()

# Iniciar Playwright
with sync_playwright() as playwright:
    run(playwright)
