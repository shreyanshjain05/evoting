from flask import Flask, render_template, request, redirect, session, g
import sqlite3

app = Flask(__name__)
app.secret_key = 'your_secret_key'

DATABASE = 'evoting.db'


# Helper to get database connection
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
    return db


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()


# Create tables if not exists
def init_db():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                aadhaar TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS votes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                candidate TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        db.commit()


@app.route('/')
def index():
    return render_template('login.html')


@app.route('/login', methods=['POST'])
def login():
    aadhaar = request.form['aadhaar']
    password = request.form['password']

    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT id FROM users WHERE aadhaar=? AND password=?', (aadhaar, password))
    user = cursor.fetchone()

    if user:
        session['user_id'] = user[0]
        return redirect('/vote')
    else:
        return 'Login failed! Invalid Aadhaar or password.'


@app.route('/register')
def register():
    return render_template('register.html')


@app.route('/register', methods=['POST'])
def register_user():
    aadhaar = request.form['aadhaar']
    password = request.form['password']

    db = get_db()
    cursor = db.cursor()

    try:
        cursor.execute('INSERT INTO users (aadhaar, password) VALUES (?, ?)', (aadhaar, password))
        db.commit()
        return redirect('/')
    except sqlite3.IntegrityError:
        return 'Aadhaar already registered.'


@app.route('/vote')
def vote():
    if 'user_id' not in session:
        return redirect('/')
    return render_template('vote.html')


@app.route('/submit_vote', methods=['POST'])
def submit_vote():
    if 'user_id' not in session:
        return redirect('/')

    candidate = request.form['candidate']
    user_id = session['user_id']

    db = get_db()
    cursor = db.cursor()
    cursor.execute('INSERT INTO votes (user_id, candidate) VALUES (?, ?)', (user_id, candidate))
    db.commit()

    return render_template('vote_submitted.html')

@app.route('/results')
def results():
    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT candidate, COUNT(candidate) as vote_count FROM votes GROUP BY candidate')
    results = cursor.fetchall()

    # Determine the candidate with the most votes
    if results:
        winner = max(results, key=lambda x: x[1])  # Find the candidate with the most votes
    else:
        winner = None

    return render_template('results.html', results=results, winner=winner)


if __name__ == '__main__':
    init_db()  # Initialize the database
    app.run(debug=True)