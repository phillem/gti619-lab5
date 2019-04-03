from sqlalchemy import engine

import database
from database import db
from werkzeug.security import generate_password_hash


if __name__ == "__main__":
    db.reflect()
    db.drop_all()
    db.session.commit()
    print("creating database")
    db.create_all()
    print("database created")

admin = database.User()
admin.username = 'administrateur'
admin.email = 'administrateur@hotmail.com'
admin.password = generate_password_hash('administrateur', method='sha256')
admin.role = 'administrateur'

utilisateur1 = database.User()
utilisateur1.username = 'utilisateur1'
utilisateur1.email = 'utilisateur1@hotmail.com'
utilisateur1.password = generate_password_hash('utilisateur1', method='sha256')
utilisateur1.role = 'C_affaire'

utilisateur2 = database.User()
utilisateur2.username = 'utilisateur2'
utilisateur2.email = 'utilisateur2@hotmail.com'
utilisateur2.password = generate_password_hash('utilisateur2', method='sha256')
utilisateur2.role = 'C_residentiel'

securityParameters = database.SecurityParameters()
securityParameters.pwSpecialCharacterAmount = 0
securityParameters.pwNumberAmount = 0
securityParameters.pwCapitalAmount = 0
securityParameters.failedAttemptsMax = 5
securityParameters.usernameMin = 4
securityParameters.usernameMax = 80
securityParameters.passwordMin = 4
securityParameters.passwordMax = 20

clientA1 = database.Client(name='Paul', age=21, address='123 asd', phone='514-222-2222', typeClient='residentiel')
clientA2 = database.Client(name='Jean', age=22, address='123 asd', phone='514-222-2222', typeClient='residentiel')
clientA3 = database.Client(name='Toto', age=23, address='123 asd', phone='514-222-2222', typeClient='residentiel')
clientA4 = database.Client(name='Renaud', age=24, address='123 asd', phone='514-222-2222', typeClient='residentiel')
clientA5 = database.Client(name='Marie', age=25, address='123 asd', phone='514-222-2222', typeClient='residentiel')

clientR1 = database.Client(name='Jeanne', age=23, address='123 asd', phone='514-222-2222', typeClient='affaire')
clientR2 = database.Client(name='Corinne', age=23, address='123 asd', phone='514-222-2222', typeClient='affaire')
clientR3 = database.Client(name='Samuel', age=23, address='123 asd', phone='514-222-2222', typeClient='affaire')
clientR4 = database.Client(name='Paul', age=23, address='123 asd', phone='514-222-2222', typeClient='affaire')
clientR5 = database.Client(name='Zack', age=23, address='123 asd', phone='514-222-2222', typeClient='affaire')

db.session.add(clientA1)
db.session.add(clientA2)
db.session.add(clientA3)
db.session.add(clientA4)
db.session.add(clientA5)
db.session.commit()

db.session.add(clientR1)
db.session.add(clientR2)
db.session.add(clientR3)
db.session.add(clientR4)
db.session.add(clientR5)
db.session.commit()

db.session.add(admin)
db.session.commit()
db.session.add(utilisateur1)
db.session.commit()
db.session.add(utilisateur2)
db.session.commit()
db.session.add(securityParameters)
db.session.commit()

#   user = database.User()
#    user.email = email[i]
#    user.password = password[i]

#    users +=[user]
#    db.session.add(user)
#    db.session.commit()
