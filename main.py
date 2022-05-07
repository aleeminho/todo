from flask import Flask, flash, render_template, request, url_for, redirect
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Column, ForeignKey, Integer, String, ForeignKey
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired, Length
from flask_bcrypt import Bcrypt
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from sqlalchemy.orm import relationship
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
# "memeg"
Bootstrap(app)
# DATABASE
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL').replace("postgres",'postgresql')
# 'postgresql://postgres:110724@localhost:5432/todo-app'

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

#HASH
bcrypt = Bcrypt(app)

#AUTHENTICATOR
login_manager = LoginManager()
login_manager.init_app(app)

class User(UserMixin, db.Model):
    id = Column(Integer, primary_key=True)
    username = Column(String, nullable=False)
    password = Column(String, nullable=False)
    name = Column(String, nullable=False)
    todos = relationship("Todo", backref="user")

class Todo(db.Model):
    id = Column(Integer, primary_key=True)
    title = Column(String(30), nullable=False)
    description = Column(String(100), nullable=False)
    deadline = Column(String, nullable=False)
    user_id = Column(Integer, ForeignKey('user.id'))

class TodoForm(FlaskForm):
    title = StringField("Title", validators=[DataRequired(), Length(max=30)])
    description = StringField("Description", validators=[DataRequired(), Length(max=100)])
    deadline = StringField("Deadline", validators=[DataRequired()])
    submit = SubmitField("Add Task")

class Login(FlaskForm):
    username = StringField("Username", validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField("Login")
class Register(FlaskForm):
    username = StringField("Username", validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    name = StringField('Name', validators=[DataRequired()])
    submit = SubmitField('Register')

with app.app_context():
    db.create_all()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

@app.route('/')
def page():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = Login()
    user = User.query.filter_by(username=form.username.data).first()
    if form.validate_on_submit():
        if not user:
            flash("That username doesn't exist in database, please try again")
            return redirect(url_for('login'))
        elif not bcrypt.check_password_hash(user.password, form.password.data):
            flash('Password incorrect, please try again.')
            return redirect(url_for('login'))
        else:
            login_user(user)
            return redirect(url_for('home'))
    return render_template('login.html', form=form)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/home')
@login_required
def home():
    user_todo = Todo.query.filter_by(user_id=current_user.get_id()).all()
    return render_template("home.html", todos=user_todo)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = Register()
    user = User.query.filter_by(username=form.username.data).first()
    if user:
        flash('username has been registered.')
        return redirect(url_for('login'))
    if form.validate_on_submit():
        new_user = User(
            username = form.username.data,
            password = bcrypt.generate_password_hash(form.password.data).decode('utf-8'),
            name = form.name.data
        )
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for('home'))
    return render_template('register.html', form=form)


@app.route('/add', methods=['GET', 'POST'])
def add():
    form = TodoForm()
    user_now = User.query.filter_by(id=current_user.get_id()).first()
    if request.method == 'POST' and form.validate():
        new_task = Todo(
            title = form.title.data,
            description = form.description.data,
            deadline = form.deadline.data,
            user_id = user_now.id
        )
        db.session.add(new_task)
        db.session.commit()
        return redirect(url_for('home'))
    return render_template('add.html', form=form)

@app.route('/update/<int:id>', methods=['GET', 'POST'])
def update(id):
    task_to_update = Todo.query.get(id)
    edit_form = TodoForm(
        title = task_to_update.title,
        description = task_to_update.description,
        deadline = task_to_update.deadline
    )
    if edit_form.validate_on_submit():
        task_to_update.title = edit_form.title.data
        task_to_update.description = edit_form.description.data
        task_to_update.deadline = edit_form.deadline.data
        db.session.commit()
        return redirect(url_for('home'))
    return render_template('update.html', form=edit_form)



@app.route('/delete/<id>')
def delete(id):
    task_to_delete = Todo.query.get(id)
    db.session.delete(task_to_delete)
    db.session.commit()
    return redirect(url_for('home'))


if __name__ == "__main__":
    app.run(debug=True)