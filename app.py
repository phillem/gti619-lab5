from flask import Flask, render_template,redirect,url_for
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField,PasswordField,BooleanField
from wtforms.validators import InputRequired,Email,Length
from werkzeug.security import generate_password_hash,check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = "secretkey"

Bootstrap(app)


class LoginForm(FlaskForm):
    username = StringField('username',validators=[InputRequired(),Length(min=4,max=15) ] )
    password = PasswordField('password',validators=[InputRequired(),Length(min=8,max=80) ] )
    remember = BooleanField('Remenber me')


class RegisterForm(FlaskForm):
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    email = StringField('email',validators=[InputRequired(),Email(message='Invalide email'),Length(max=50)])
    password = PasswordField('password',validators=[InputRequired(),Length(min=8,max=80) ] )


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
@app.route('/creer_nouveau_compte')
def nouveau_compte():
    return render_template('signup.html')

@app.route('/login',methods=['GET','POST'])
def login():
    from database import db,User
    form = LoginForm()
    # this function returns true if the form both submitted.
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password,form.password.data) :
                if user.role =='administrateur' :
                    return redirect(url_for('dashboard_admin'))
                elif user.role == 'C_affaire' :
                    return redirect(url_for('dashboard_C_affaire'))
                else :
                    return redirect(url_for('dashboard_C_residentiels'))


                return redirect(url_for('dashboard'))
        return '<h1> the username or password is incorrect </h1>'
        # username are supposed to be unique
         #return  '<h1> '+form.username.data +' '+form.password.data+'</h1>'

    return render_template('login.html',form=form)

@app.route('/signup',methods=['GET','POST'])
def signup():
    from database import db,User
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password= generate_password_hash(form.password.data,method='sha256')
        new_user = User(username=form.username.data,email=form.email.data, password=hashed_password,role='utilisateur')
        db.session.add(new_user)
        db.session.commit()
        return '<h1> new user has been added </h1>'
        #return  '<h1> '+form.username.data +' '+form.email.data+' '+ form.password.data+ '</h1>'
    return render_template('signup.html',form=form)


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

if __name__ == '__main__':
    app.run()
