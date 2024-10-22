from selenium import webdriver
from selenium.webdriver.chrome.service import Service as ChromeService
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from webdriver_manager.chrome import ChromeDriverManager
import time
import random

# Configuraciones globales
MIN_DELAY = 5     # Tiempo mínimo de espera entre acciones (en segundos)
MAX_DELAY = 10    # Tiempo máximo de espera entre acciones (en segundos)
MAX_USERS = 10    # Número máximo de usuarios a seguir
username = 'deleitevisual2020'
password = 'galante1077441571'

# Inicializar el navegador
service = Service(ChromeDriverManager().install())
driver = webdriver.Chrome(service=service)

def wait_for_element(by, value, timeout=10):
    """Espera hasta que el elemento esté presente en la página."""
    try:
        return WebDriverWait(driver, timeout).until(EC.presence_of_element_located((by, value)))
    except Exception as e:
        print(f"Error al esperar el elemento: {e}")
        return None

def login_instagram():
    """Inicia sesión en Instagram."""
    driver.get('https://www.instagram.com/accounts/login/')
    time.sleep(2)  # Esperar a que la página cargue

    # Encontrar los campos de entrada
    user_input = wait_for_element(By.NAME, 'username')
    pass_input = wait_for_element(By.NAME, 'password')
    
    if user_input and pass_input:
        # Ingresar usuario y contraseña
        user_input.send_keys(username)
        pass_input.send_keys(password)
        pass_input.send_keys(Keys.RETURN)
        print("Iniciando sesión...")
        time.sleep(5)  # Esperar a que inicie sesión

def follow_by_hashtag(tag):
    """Sigue usuarios por hashtag."""
    driver.get(f'https://www.instagram.com/explore/tags/{tag}/')
    time.sleep(5)  # Esperar a que la página cargue

    # Hacer scroll para cargar más publicaciones
    driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
    time.sleep(5)

    # Encontrar todos los enlaces de las publicaciones
    posts = driver.find_elements(By.TAG_NAME, 'a')
    post_links = [elem.get_attribute('href') for elem in posts if '/p/' in elem.get_attribute('href')]

    followed_users = 0

    for link in post_links:
        driver.get(link)
        time.sleep(random.uniform(MIN_DELAY, MAX_DELAY))

        try:
            # Intentar seguir al usuario si el botón de seguir está presente
            follow_button = wait_for_element(By.XPATH, "//button[text()='Follow' or text()='Seguir']")
            if follow_button:
                if follow_button.text in ['Follow', 'Seguir']:
                    follow_button.click()
                    followed_users += 1
                    print(f"Siguiendo usuario en {link}")
                    time.sleep(random.uniform(MIN_DELAY, MAX_DELAY))
                else:
                    print(f"Botón de seguir no encontrado en {link}")
            
            if followed_users >= MAX_USERS:
                break
        except Exception as e:
            print(f"Error al seguir: {e}")
            continue

    print(f"Total de usuarios seguidos: {followed_users}")

# Ejecutar el script
login_instagram()
follow_by_hashtag('medellin')  # Reemplaza 'istmina' por cualquier hashtag
driver.quit()
