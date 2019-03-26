import database
from database import db
from werkzeug.security import generate_password_hash
from app import random_nombre


if __name__ == "__main__":
    from database import db

    print("creating database")
    db.create_all()
    print("database created")
num_admin = str(random_nombre())
num_1=random_nombre()
num_2=random_nombre()


admin = database.User()
admin.username = 'administrateur'
admin.email = 'administrateur@hotmail.com'
admin.nombre_aleatoire=num_admin
admin.password = generate_password_hash('administrateur'+num_admin, method='sha256')
version = 'sha256'
admin.role = 'administrateur'

utilisateur1 = database.User()
utilisateur1.username = 'utilisateur1'
utilisateur1.email = 'utilisateur1@hotmail.com'
utilisateur1.password = generate_password_hash('utilisateur1'+num_1, method='sha256')
admin.nombre_aleatoire=num_1
version = 'sha256'
utilisateur1.role = 'C_affaire'

utilisateur2 = database.User()
utilisateur2.username = 'utilisateur2'
utilisateur2.email = 'utilisateur2@hotmail.com'
utilisateur2.password = generate_password_hash('utilisateur2'+num_2, method='sha256')
admin.nombre_aleatoire=num_2
version = 'sha256'
utilisateur2.role = 'C_residentiel'

db.session.add(admin)
db.session.commit()
db.session.add(utilisateur1)
db.session.commit()
db.session.add(utilisateur2)
db.session.commit()

#   user = database.User()
#    user.email = email[i]
#    user.password = password[i]

#    users +=[user]
#    db.session.add(user)
#    db.session.commit()
