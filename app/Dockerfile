FROM python:3.8

RUN pip install flask flask-sqlalchemy flask-login psycopg2

WORKDIR app

CMD FLASK_APP=app python -m flask run --host=0.0.0.0