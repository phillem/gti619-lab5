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
    username = StringField('username',validators=[InputRequired(),Length(min=4,max=15) ] )
    password = PasswordField('password',validators=[InputRequired(),Length(min=8,max=80) ] )


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/login',methods=['GET','POST'])
def login():
    from database import db,User
    form = LoginForm()
    # this function returns true if the form both submitted.
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password,form.password.data) :
                return redirect(url_for('dashboard'))
        return '<h1> invalid username or password </h1>'
        # username are supposed to be unique
         #return  '<h1> '+form.username.data +' '+form.password.data+'</h1>'

    return render_template('login.html',form=form)


@app.route('/signup',methods=['GET','POST'])
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


@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')


if __name__ == '__main__':
    app.run()
