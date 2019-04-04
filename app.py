from datetime import timedelta

from flask import Flask, render_template, redirect, url_for, make_response, session, g
from flask_bootstrap import Bootstrap
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from flask_table import Col, Table
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, IntegerField, HiddenField,SelectField
from wtforms.validators import InputRequired, Email, Length, DataRequired,ValidationError
from werkzeug.security import generate_password_hash, check_password_hash
from database import db, SecurityParameters, User, Client
from init_db import random_alphanumeric

app = Flask(__name__)
app.config['SECRET_KEY'] = "secretkey"

Bootstrap(app)

login_manager = LoginManager()
login_manager.init_app(app)

login_manager.login_view = 'login'



tab=['£','!','@','+','*','*','$','=','£','%']

def is_special_character(l):
    if l in tab :
        return True

def nbr_special_character(s) :
    count = 0
    for x in s:
        if is_special_character(x):
            count = count + 1
    return count


def nbr_uppercase(s):
    count = 0
    for i in s :
        if (i.islower()):
            count = count + 1
    return count

def nbr_lowercase(s):
    count = 0
    for i in s :
        if (i.isupper()):
            count = count + 1
    return count

def nbr_chiffre(s):
    return sum(c.isdigit() for c in s)


class TableClients(Table):
    id = Col('Id', show=False)
    name = Col('Nom')
    age = Col('Age')
    address = Col('Adresse')
    phone = Col('Telephone')




class LoginForm(FlaskForm):

    sp = SecurityParameters.query.first()
    username = StringField('username', validators=[InputRequired(), Length(min=sp.usernameMin, max=sp.usernameMax)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=sp.passwordMin, max=sp.passwordMax)])
    remember = BooleanField('Remember me')




class RegisterForm(FlaskForm):
    sp = SecurityParameters.query.first()

    def validator_form_uppercase(form,field):
        sp = SecurityParameters.query.first()
        if(nbr_uppercase(field.data)<sp.pwCapitalAmount):
            raise ValidationError('Le mot de passe doit contenir au moins '+str(sp.pwCapitalAmount)+' majuscules')


    def validator_form_lowercase(form,field):
        sp = SecurityParameters.query.first()
        if(nbr_lowercase(field.data)<sp.pwlowercaseAmount):
            raise ValidationError('Le mot de passe doit contenir au moins '+str(sp.pwlowercaseAmount)+'minuscules')

    def validator_form_chiffre(form, field):
        sp = SecurityParameters.query.first()
        if (nbr_lowercase(field.data) <sp.pwlowercaseAmount):
            raise ValidationError('Le mot de passe doit contenir au moins ' + str(sp.pwlowercaseAmount) + 'majuscules')

    def validator_form_special_character(form,field):
        sp = SecurityParameters.query.first()
        if (nbr_special_character(field.data) < sp.pwSpecialCharacterAmount):
            raise ValidationError('Le mot de passe doit contenir au moins ' + str(sp.pwSpecialCharacterAmount) + ' caractères speciaux parmi £ ! @ + * $ = £ %')

    def validator_password(form, field):
        from database import db,Passwords
        sp = SecurityParameters.query.first()
        bool = False
        count = 1
        #passwords = Passwords.query.limit(sp.pwlastpassword).all()
        #User.query.filter_by(username=form.username.data
        while bool==False & count<=sp.pwlastpassword :
            password = Passwords.query.filter_by(id=count).first()
            if password is None or check_password_hash(field.data,password.password):
                bool = True
            count=count+1
        if bool==False :
            raise ValidationError('Veuillez trouver un autre mot de passe')


    choices = [('C_affaire', 'Préposé aux clients d affaires' ), ('C_residentiel', 'Préposé aux clients résidentiels')]

    username = StringField('username', validators=[InputRequired(), Length(min=sp.usernameMin, max=sp.usernameMax)])
    email = StringField('email', validators=[InputRequired(), Email(message='email invalide'), Length(max=50)])

    password_length = Length(min=sp.passwordMin, max=sp.passwordMax ,message='longueur doit etre entre '+str(sp.passwordMin)+'et '+str(sp.passwordMax))
    password_required = InputRequired(message='PASSWORD_NOT_PROVIDED')

    password = PasswordField('Saisir un mot de passe', validators=[password_required,password_length,validator_form_uppercase,validator_form_lowercase,validator_form_chiffre,validator_password,validator_form_special_character,validator_password])
    roles = SelectField(u'Role de l utilisateur', validators=[DataRequired()], choices=choices)


class changementmdpForm(FlaskForm):
    sp = SecurityParameters.query.first()
    password1 = PasswordField('ancien mot de passe',
                              validators=[InputRequired(), Length(min=sp.passwordMin, max=sp.passwordMax)])
    password2 = PasswordField('nouveau mot de passe',
                              validators=[InputRequired(), Length(min=sp.passwordMin, max=sp.passwordMax)])

    password3 = PasswordField('Retapez le nouveau mot de passe',
                              validators=[InputRequired(), Length(min=sp.passwordMin, max=sp.passwordMax)])


class SecurityParametersForm(FlaskForm):
    id = HiddenField("id")
    usernameMin = IntegerField('username minimum length', validators=[DataRequired()])
    usernameMax = IntegerField('Username maximum length', validators=[DataRequired()])
    passwordMin = IntegerField('Password minimum length', validators=[DataRequired()])
    passwordMax = IntegerField('Password maximum length', validators=[DataRequired()])
    pwSpecialCharacterAmount = IntegerField('Amount of special characters in password', validators=[DataRequired()])
    pwNumberAmount = IntegerField('Amount of numbers in password', validators=[DataRequired()])
    pwCapitalAmount = IntegerField('Amount of capitals in password', validators=[DataRequired()])
    pwlowercaseAmount = IntegerField('Amount of lowercases in password', validators=[DataRequired()])
    pwlastpassword = IntegerField('n last passwords', validators=[DataRequired()])
    failedAttemptsMax = IntegerField('Amount of failed connections attempts', validators=[DataRequired()])


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/ajouterutilisateur',methods=['GET','POST'])
def ajouterutilisateur():
    from database import db, User,Passwords
    form = RegisterForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is None :
            nbr = random_alphanumeric()
            hashed_password = generate_password_hash(form.password.data + nbr, method='sha256')
            new_user = User(username=form.username.data, email=form.email.data, password=hashed_password,
                            nombre_aleatoire=nbr, failedAttempts=0, isBlocked=False, role=form.roles.data,version_hashage='sha256')
            password = Passwords(password=generate_password_hash(form.password.data, method='sha256'))
            db.session.add(new_user)
            db.session.add(password)
            db.session.commit()
            return '<h1> new user has been added </h1>'
        else :
            return  "le compte utilisateur existe déja "

    return render_template('signup.html', form=form)




@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    form = LoginForm()
    sp = SecurityParameters.query.first()
    # this function returns true if the form both submitted.
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if user.isBlocked:
                return render_template('login.html', form=form, error='Votre compte est bloque, trop de tentatives')
            elif check_password_hash(user.password, form.password.data+user.nombre_aleatoire):
                user.failedAttempts = 0
                db.session.commit()
                login_user(user, remember=form.remember.data)
                if user.role == 'administrateur':
                    return redirect(url_for('dashboard_admin'))
                elif user.role == 'C_affaire':
                    return redirect(url_for('dashboard_clients_affaires'))
                elif user.role == 'C_residentiel':
                    return redirect(url_for('dashboard_clients_residentiels'))
            else:
                user.failedAttempts += 1
                if user.failedAttempts >= sp.failedAttemptsMax:
                    user.isBlocked = True
                db.session.commit()
        error = 'Utilisateur ou le mot de passe est incorrect. Tentatives ', str(user.failedAttempts), ' de ', str(sp.failedAttemptsMax)

    return render_template('login.html', form=form, error=error)


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
    if current_user.role == "administrateur":
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
            sp.pwlowercaseAmount = form.pwlowercaseAmount.data
            sp.failedAttemptsMax = form.failedAttemptsMax.data
            db.session.commit()

            return render_template('security_parameters.html', form=form)
        return render_template('security_parameters.html', form=form)
    return redirect(url_for('index', error='Acces interdit'))


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


@app.route('/changermdp', methods=['GET', 'POST'])
def changermdp():
    from database import db, User
    form = changementmdpForm()
    user = current_user
    # this function returns true if the form both submitted.
    if form.validate_on_submit():
        if form.password2.data == form.password3.data:
            if check_password_hash(user.password, form.password1.data):
                user.password = generate_password_hash(form.password2.data, method='sha256')
                db.session.commit()
            else:
                return '<h1> L ancien mot de passe rentré est incorrect </h1>'
        else:
            return "les deux mot de passe ne sont pas similaires"
    return render_template('changermdp.html', form=form)


@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')


@app.route('/dashboard_admin')
@login_required
def dashboard_admin():
    if current_user.role == "administrateur":
        return render_template('dashboard.admin.html')
    return redirect(url_for('index', error='Acces interdit'))


@app.route('/dashboard_clients_affaires')
@login_required
def dashboard_clients_affaires():
    if current_user.role == "administrateur" or current_user.role == "C_affaire":
        return render_template('dashboard_clients_affaires.html')
    return redirect(url_for('index', error='Acces interdit'))


@app.route('/dashboard_clients_residentiels')
@login_required
def dashboard_clients_residentiels():
    if current_user.role == "administrateur" or current_user.role == "C_residentiel":
        return render_template('dashboard_clients_residentiels.html')
    return redirect(url_for('index', error='Acces interdit'))


@app.route('/clients_affaires')
@login_required
def clients_affaires():
    if current_user.role == "administrateur" or current_user.role == "C_affaire":
        data = Client.query.filter_by(typeClient='affaire').all()
        table = TableClients(data)
        return render_template('clients_affaires.html', table=table)
    return redirect(url_for('index', error='Acces interdit'))


@app.route('/clients_residentiels')
@login_required
def clients_residentiels():
    if current_user.role == "administrateur" or current_user.role == "C_residentiel":
        data = Client.query.filter_by(typeClient='residentiel').all()
        table = TableClients(data)
        return render_template('clients_residentiels.html', table=table)
    return redirect(url_for('index', error='Acces interdit'))


@login_manager.user_loader
def load_user(id):
    return User.query.get(int(id))


if __name__ == '__main__':
    app.run(debug=True)
