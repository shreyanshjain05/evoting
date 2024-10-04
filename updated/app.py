from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'  # Change this to a secure key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///evoting.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Define models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    has_voted = db.Column(db.Boolean, default=False)
    is_admin = db.Column(db.Boolean, default=False)  # To check if user is admin
    vote_for = db.Column(db.Integer, db.ForeignKey('candidate.id'), nullable=True)  # Stores the candidate ID

class Candidate(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)
    votes = db.Column(db.Integer, default=0)  # Add this to track votes for each candidate

# Drop existing database (use with caution)
with app.app_context():
    db.drop_all()  # Uncomment this line to drop the database (for testing only)
    db.create_all()  # Create the database and tables

    # Create an admin user if it doesn't exist
    admin_user = User.query.filter_by(username='admin').first()
    if not admin_user:
        hashed_password = generate_password_hash('adminpassword')  # Change 'adminpassword' to your desired password
        new_admin = User(username='admin', password=hashed_password, is_admin=True)
        db.session.add(new_admin)
        db.session.commit()

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['is_admin'] = user.is_admin  # Set if the user is an admin
            if user.is_admin:
                return redirect(url_for('admin'))  # Admin goes to admin page
            return redirect(url_for('vote'))  # Regular user goes to vote
        else:
            flash("Invalid credentials", "danger")

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = generate_password_hash(password)

        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash("Registration successful. Please log in.", "success")
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        admin_user = User.query.filter_by(username=username, is_admin=True).first()

        if admin_user and check_password_hash(admin_user.password, password):
            session['user_id'] = admin_user.id
            session['is_admin'] = True  # Set an additional flag for admin
            return redirect(url_for('admin'))  # Redirect to admin dashboard
        else:
            flash("Invalid admin credentials", "danger")

    return render_template('admin_login.html')

@app.route('/vote', methods=['GET', 'POST'])
def vote():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    if user.has_voted:
        return redirect(url_for('results'))

    candidates = Candidate.query.all()
    if request.method == 'POST':
        if 'candidate' not in request.form:
            flash('Please select a candidate before submitting your vote.', 'danger')
            return redirect(url_for('vote'))

        candidate_id = request.form['candidate']
        selected_candidate = Candidate.query.get(candidate_id)

        if selected_candidate:
            selected_candidate.votes += 1  # Increment the vote count for the selected candidate
            user.has_voted = True  # Mark the user as having voted
            user.vote_for = selected_candidate.id  # Store the candidate ID voted for
            db.session.commit()
            flash('Your vote has been recorded. Thank you for voting!', 'success')
        else:
            flash('Invalid candidate selection.', 'danger')

        return redirect(url_for('results'))

    return render_template('vote.html', candidates=candidates)

@app.route('/admin', methods=['GET', 'POST'])
def admin():
    if 'user_id' not in session or 'is_admin' not in session:
        return redirect(url_for('admin_login'))  # Ensure user is logged in and is an admin

    admin_user = User.query.get(session['user_id'])
    if not admin_user.is_admin:  # Double-check if the logged-in user is an admin
        return "Access denied."

    if request.method == 'POST':
        candidate_name = request.form['candidate_name']
        if candidate_name:  # Only add if name is provided
            new_candidate = Candidate(name=candidate_name)
            db.session.add(new_candidate)
            db.session.commit()
            flash('Candidate added successfully!', 'success')

    candidates = Candidate.query.all()
    return render_template('admin.html', candidates=candidates)

@app.route('/results')
def results():
    if 'user_id' not in session:
        return redirect(url_for('login'))  # Ensure the user is logged in

    candidates = Candidate.query.all()

    # Count votes for each candidate by checking users who voted for that candidate
    candidate_votes = {candidate: User.query.filter_by(vote_for=candidate.id, has_voted=True).count() for candidate in candidates}

    # Determine the candidate with the highest votes
    winning_candidate = max(candidate_votes, key=candidate_votes.get, default=None)

    return render_template('results.html', candidates=candidates, candidate_votes=candidate_votes, winning_candidate=winning_candidate)

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('is_admin', None)  # Clear admin session flag
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)