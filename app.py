from flask import Flask
from flask_sqlalchemy import SQLAlchemy


app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'
app.secret_key = 'super secret'
app.config['OAUTH_CREDENTIALS'] = {
    'facebook': {
        'id': 'replace with your facebook id',
        'secret': 'replace with your super secret'
    },
    'github': {
        'id': 'replace with your github id',
        'secret': 'replace with your super secret'
    },
    'google': {
        'id': 'replace with your google id',
        'secret': 'replace with your super secret'
    },
    'linkedin': {
        'id': 'replace with your linkedin id',
        'secret': 'replace with your super secret'
    }
}

db = SQLAlchemy(app)


from views import *

if __name__ == '__main__':
    db.create_all()

    app.run(debug=True)
