from datetime import timedelta

import flask
from flask import Flask, render_template, redirect, url_for, make_response, session, g
from flask_bootstrap import Bootstrap
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, IntegerField, HiddenField
from wtforms.validators import InputRequired, Email, Length, DataRequired
from werkzeug.security import generate_password_hash, check_password_hash
from database import db, SecurityParameters, User



app = Flask(__name__)
app.config['SECRET_KEY'] = "secretkey"

Bootstrap(app)

login_manager = LoginManager()
login_manager.init_app(app)

login_manager.login_view = 'login'


class LoginForm(FlaskForm):
    sp = SecurityParameters.query.first()
    username = StringField('username', validators=[InputRequired(), Length(min=sp.usernameMin, max=sp.usernameMax)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=sp.passwordMin, max=sp.passwordMax)])
    remember = BooleanField('Remember me')


class RegisterForm(FlaskForm):
    sp = SecurityParameters.query.first()
    username = StringField('username', validators=[InputRequired(), Length(min=sp.usernameMin, max=sp.usernameMax)])
    email = StringField('email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=sp.passwordMin, max=sp.passwordMax)])


class SecurityParametersForm(FlaskForm):
    id = HiddenField("id")
    usernameMin = IntegerField('username minimum length', validators=[DataRequired()])
    usernameMax = IntegerField('Username maximum length', validators=[DataRequired()])
    passwordMin = IntegerField('Password minimum length', validators=[DataRequired()])
    passwordMax = IntegerField('Password maximum length', validators=[DataRequired()])
    pwSpecialCharacterAmount = IntegerField('Amount of special characters in password', validators=[DataRequired()])
    pwNumberAmount = IntegerField('Amount of numbers in password', validators=[DataRequired()])
    pwCapitalAmount = IntegerField('Amount of capitals in password', validators=[DataRequired()])
    failedAttemptsMax = IntegerField('Amount of failed connections attempts', validators=[DataRequired()])


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/parametrage')
def parametrage():
    return render_template('parametrage.html')


@app.route('/clients_R')
def clients_R():
    return render_template('clients_R.html')


@app.route('/clients_A')
def clients_A():
    return render_template('clients_A.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    # this function returns true if the form both submitted.
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user, remember=form.remember.data)
                if user.role == 'administrateur':
                    return redirect(url_for('dashboard_admin'))
                elif user.role == 'C_affaire':
                    return redirect(url_for('dashboard_C_affaire'))
                elif user.role == 'C_residentiels':
                    return redirect(url_for('dashboard_C_residentiels'))

                return redirect(url_for('dashboard'))
        return '<h1> the username or password is incorrect </h1>'
        # username are supposed to be unique
        # return  '<h1> '+form.username.data +' '+form.password.data+'</h1>'

    return render_template('login.html', form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.before_request
def before_request():
    g.user = current_user
    session.permanent = True
    app.permanent_session_lifetime = timedelta(minutes=5)


@app.route('/security_parameters', methods=['GET', 'POST'])
@login_required
def security_parameters():
    sp = SecurityParameters.query.first()
    form = SecurityParametersForm(obj=sp)
    if form.validate_on_submit():
        sp.id = form.id.data
        sp.usernameMin = form.usernameMin.data
        sp.usernameMax = form.usernameMax.data
        sp.passwordMin = form.passwordMin.data
        sp.passwordMax = form.passwordMax.data
        sp.pwSpecialCharacterAmount = form.pwSpecialCharacterAmount.data
        sp.pwNumberAmount = form.pwNumberAmount.data
        sp.pwCapitalAmount = form.pwCapitalAmount.data
        sp.failedAttemptsMax = form.failedAttemptsMax.data
        db.session.commit()

        return render_template('security_parameters.html', form=form)
    return render_template('security_parameters.html', form=form)


"""""@app.route('/signup',methods=['GET','POST'])
def signup():
    from database import db,User
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password= generate_password_hash(form.password.data,method='sha256')
        new_user = User(username=form.username.data, password=hashed_password,email=form.email.data)
        db.session.add(new_user)
        db.session.commit()
        return '<h1> new user has been added </h1>'
        #return  '<h1> '+form.username.data +' '+form.email.data+' '+ form.password.data+ '</h1>'
    return render_template('signup.html',form=form)

"""""


@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')


@app.route('/dashboard.admin')
def dashboard_admin():
    return render_template('dashboard.admin.html')


@app.route('/dashboard.C_affaire')
def dashboard_C_affaire():
    return render_template('dashboard.C_affaire.html')


@app.route('/dashboard_C_residentiels')
def dashboard_C_residentiels():
    return render_template('dashboard.C_residentiels.html')


@login_manager.user_loader
def load_user(id):
    return User.query.get(int(id))


if __name__ == '__main__':
    app.run()
