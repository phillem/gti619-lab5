import database
from database import db
from werkzeug.security import generate_password_hash


if __name__ == "__main__":
    db.drop_all()
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
