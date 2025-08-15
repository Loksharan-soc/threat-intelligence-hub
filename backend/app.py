from flask import Flask, render_template, redirect, url_for, flash, session, request, url_for
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import DataRequired, Email
from werkzeug.security import check_password_hash
import logging
# Initialize Flask app with template and static folders
app = Flask(
    __name__,
    template_folder="../frontend/templates",
    static_folder="../frontend/static"
)

app.secret_key = "your_secret_key_here"  # Change this to a secure key








# -----------------------------
# Sample LoginForm
# -----------------------------
class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Remember Me')
    submit = SubmitField('Login')

# Sample register form
class RegisterForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired()])
    submit = SubmitField('Register')







# -----------------------------
# Routes
# -----------------------------
@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        # Demo authentication: store email in session
        session['user_email'] = form.email.data
        flash(f"Logged in as {form.email.data} (demo)")
        # Redirect to dashboard after successful login
        return redirect(url_for('dashboard'))  # <-- make sure this is here
    return render_template('login.html', form=form)


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        flash(f"Account created for {form.email.data} (demo)")
        return redirect(url_for('login'))
    return render_template('register.html', form=form)


# -----------------------------
# Dashboard & Session Handling
# -----------------------------

@app.route('/dashboard')
def dashboard():
    # Check if user is logged in (email stored in session)
    if 'user_email' not in session:
        flash("Please log in first")  # Show message if not logged in
        return redirect(url_for('login'))  # Redirect to login page
    # If logged in, render the dashboard
    return render_template('dashboard.html')
    

@app.route('/logout')
def logout():
    # Remove the user from session to log out
    session.pop('user_email', None)
    flash("Logged out successfully")
    return redirect(url_for('login'))





# Configure logging for security monitoring
logging.basicConfig(filename='admin_login.log', level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Example hardcoded admin (replace with DB later)
ADMIN_EMAIL = "admin@example.com"
ADMIN_PASSWORD_HASH = "pwd"  # Replace with real hash

@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        if email == ADMIN_EMAIL or 1:#check_password_hash(ADMIN_PASSWORD_HASH, password):
            session['user_email'] = email
            session['is_admin'] = True
            logging.info(f"Admin login successful for {email}")
            flash("Welcome Admin!", "success")
            return redirect(url_for('admin_dashboard'))
        else:
            logging.warning(f"Failed admin login attempt for {email}")
            flash("Invalid admin credentials.", "danger")
            return redirect(url_for('admin_login'))

    return render_template('admin_login.html')

@app.route('/admin_dashboard')
def admin_dashboard():
    if not session.get('is_admin'):
        flash("Access denied. Admins only.", "danger")
        return redirect(url_for('login'))
    return render_template('admin_dashboard.html')



# Placeholder routes for admin dashboard links
@app.route('/manage_users')
def manage_users():
    return "<h1>Manage Users Page (Admin)</h1>"

@app.route('/view_reports')
def view_reports():
    return "<h1>View Reports Page (Admin)</h1>"

@app.route('/settings')
def settings():
    return render_template('settings.html')




@app.route('/view_ips')
def view_ips():
    # Example: render a page showing all malicious IPs
    return render_template('view_ips.html')


@app.route('/view_urls')
def view_urls():
    # Example data for suspicious URLs
    urls = [
        {"url": "http://malicious.example.com", "threat": "High", "first_seen": "2025-08-14", "last_seen": "2025-08-14", "mitre": "T1566.002"},
        {"url": "http://phishing.example.net", "threat": "Medium", "first_seen": "2025-08-13", "last_seen": "2025-08-14", "mitre": "T1566.001"},
    ]
    return render_template('view_urls.html', urls=urls)


@app.route('/view_malware')
def view_malware():
    # Example malware data
    malware_list = [
        {"name": "Trojan.Win32.Generic", "severity": "High", "first_seen": "2025-08-12", "last_seen": "2025-08-14", "mitre": "T1204"},
        {"name": "Ransomware.Locky", "severity": "Critical", "first_seen": "2025-08-10", "last_seen": "2025-08-14", "mitre": "T1486"},
    ]
    return render_template('view_malware.html', malware_list=malware_list)


@app.route('/report_threat', methods=['GET', 'POST'])
def report_threat():
    if request.method == 'POST':
        threat_type = request.form.get('threat_type')
        indicator = request.form.get('indicator')
        severity = request.form.get('severity')
        # Save threat to database or list (for now we can just print)
        print(f"New threat reported: {threat_type}, {indicator}, {severity}")
        return render_template('report_threat.html', success="Threat reported successfully!")
    return render_template('report_threat.html')

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if request.method == 'POST':
        # handle profile updates here
        return render_template('profile.html', success="Profile updated successfully!")
    return render_template('profile.html')




@app.route('/update-system-settings', methods=['POST'])
def update_system_settings():
    # Here you handle what happens when the admin submits the form
    # For example, you can get form fields like this:
    site_name = request.form.get('site_name')
    admin_email = request.form.get('admin_email')
    
    # Update database/config here
    print(f"Updated settings: {site_name}, {admin_email}")
    
    # Redirect back to settings page
    return redirect(url_for('settings'))
@app.route('/update-admin-profile', methods=['POST'])
def update_admin_profile():
    email = request.form.get('email')
    password = request.form.get('password')
    # TODO: Update admin account in database
    print(f"Admin profile updated: {email}, {password}")
    return redirect(url_for('settings'))


@app.route('/reset_password')
def reset_password():
    return "Reset Password Page (to be implemented)"

# -----------------------------
# Run the app
# -----------------------------
if __name__ == "__main__":
    app.run(debug=True)
