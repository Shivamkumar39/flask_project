from flask import Flask, render_template, request, redirect, session
from flask_sqlalchemy import SQLAlchemy
import bcrypt
import secrets
from flask_migrate import Migrate

app = Flask(__name__)
app.secret_key = secrets.token_hex(16) 
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(app)
migrate = Migrate(app, db)

class Users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(50), unique=True, nullable=False)  # Added email column
    password = db.Column(db.String(100))

    def __init__(self, username, password, email):
        self.username = username
        self.email = email
        self.password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    def check_password(self, password):
        return bcrypt.checkpw(password.encode('utf-8'), self.password.encode('utf-8'))

with app.app_context():
    db.create_all()

@app.route("/")
def home():
    return render_template("index.html")

@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        new_user = Users(username=username, email=email, password=password)
        db.session.add(new_user)
        db.session.commit()
        return redirect('/login')

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
      email = request.form['email']
      password = request.form['password']

      user = Users.query.filter_by(email=email).first()
      
      if user and user.check_password(password):
          session['username'] = user.username
          session['email'] = user.email
          session['password'] = user.password  # I assume this is not needed, but you had it in your original code
          return redirect('/deshboard')
      else:
          return render_template('login.html', error='Invalid credentials! Please register.')
    return render_template('login.html')

@app.route('/deshboard')
def deshboard():
    if 'username' in session:  # Check if 'username' exists in session
        return render_template('deshboard.html')
    return redirect('/login')

if __name__ == '__main__':
    app.run(debug=True)
