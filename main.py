import smtplib
import os
import werkzeug
from flask import Flask, render_template, redirect, url_for, flash, request
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor, CKEditorField
from datetime import date

from flask_wtf import FlaskForm
from sqlalchemy import ForeignKey
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email

from forms import CreatePostForm
from flask_gravatar import Gravatar
import hashlib
from smtplib import SMTP

app = Flask(__name__)

login_manager = LoginManager()
login_manager.init_app(app)

app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY")
ckeditor = CKEditor(app)
Bootstrap(app)

gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)


class RegisterForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired()])
    username = StringField("Username", validators=[DataRequired()])
    password= PasswordField("Password", validators=[DataRequired()])
    submit= SubmitField("Submit")

class LoginForm(FlaskForm):
    username=StringField("Username", validators=[DataRequired()])
    password=PasswordField("Password", validators=[DataRequired()])
    login = SubmitField("Login")

class CommentForm(FlaskForm):
    comment = CKEditorField()
    submit=SubmitField("Post comment")

class ContactForm(FlaskForm):
    name=StringField("Name", validators=[DataRequired()])
    email=StringField("Email adress", validators=[Email()])
    phone_number=StringField("Phone number", validators=[DataRequired()])
    message=StringField("Message", validators=[DataRequired()])
    submit=SubmitField("Send email")

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


##CONFIGURE TABLES
class User(db.Model, UserMixin):
    __tablename__= "Users"
    id = db.Column(db.Integer, primary_key=True)
    email=db.Column(db.String(250), nullable=False)
    username=db.Column(db.String(250), nullable=False)
    password=db.Column(db.String(250), nullable=False)
    posts=db.relationship("BlogPost", back_populates="author", cascade="all,delete")
    comments = db.relationship("Comment", cascade="all,delete", back_populates="comment_author")

class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    author = db.Column(db.String(250), nullable=False)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    author=db.relationship("User", back_populates="posts")
    author_id = db.Column(db.Integer, db.ForeignKey("Users.id"))
    post_comments=db.relationship("Comment",back_populates="commented_post", cascade="all,delete")

class Comment(db.Model):
    __tablename__ = "comments"
    id=db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey("Users.id"))
    comment_author = relationship("User", back_populates="comments")
    comment=db.Column(db.String(250), nullable=False)
    commented_post=db.relationship("BlogPost", back_populates="post_comments")
    parent_post_id=db.Column(db.Integer, db.ForeignKey("blog_posts.id"))



@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

@app.route('/')
def get_all_posts():

    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts)


@app.route('/register', methods=["GET","POST"])
def register():
    form=RegisterForm()
    if form.validate_on_submit():
        if not User.query.filter_by(email=request.form["email"]).first()==None:
            flash("This email is already registered")
            return render_template("register.html", form=form)
        if not User.query.filter_by(username=request.form["username"]).first()==None:
            flash("This username already exists")
            return render_template("register.html", form=form)
        new_user=User(email=request.form["email"], username=request.form["username"],
                      password=werkzeug.security.generate_password_hash(request.form["password"],
                                                                        method=os.environ.get("METHOD_HASH"),
                                                                        salt_length=os.environ.get("SALT_LENGTH")))
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for("get_all_posts"))



    return render_template("register.html", form=form)


@app.route('/login', methods=["POST","GET"])
def login():
    form=LoginForm()
    if form.validate_on_submit():
        user=User.query.filter_by(username=request.form["username"]).first()
        if user==None:
            flash("No such username in the database")
            return render_template("login.html", form=form)
        if not werkzeug.security.check_password_hash(user.password, request.form["password"]):
            flash("Invalid password")
            return render_template("login.html", form=form)
        login_user(user)
        return redirect(url_for("get_all_posts"))

    return render_template("login.html", form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>")
def show_post(post_id):
    form=CommentForm()
    comments=BlogPost.query.filter_by(id=post_id).first().post_comments
    requested_post = BlogPost.query.get(post_id)
    return render_template("post.html", post=requested_post, form=form,comments=comments)

@app.route("/post/<int:post_id>/comment", methods=["POST"])
@login_required
def comment(post_id):
    new_comment=Comment(comment=request.form["comment"],author_id=int(current_user.get_id()), parent_post_id=post_id)
    db.session.add(new_comment)
    db.session.commit()
    return redirect(url_for("show_post",post_id=post_id))

@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact",methods=["POST","GET"])
def contact():
    form=ContactForm()
    if form.validate_on_submit():
        connection=smtplib.SMTP(host="smtp.mail.yahoo.com", port=587)
        connection.starttls()
        connection.login(user="kirilltroyak@yahoo.com", password="znqsgrijthlhypzm")
        message=f"Name: {request.form['name']}\nEmail: {request.form['email']}\nPhone number: {request.form['phone_number']}\nMessage: {request.form['message']}"
        connection.sendmail(from_addr=os.environ.get("FROM_ADRESS"), to_addrs=os.environ.get("TO_ADRESS"), msg=f"Subject:Message from user!\n\n{message}")
        flash("Email sent successfully")
        return render_template("contact.html",form=form)

    return render_template("contact.html", form=form)


@app.route("/new-post", methods=["POST","GET"])
@login_required
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y"),
            author_id=int(current_user.get_id())
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form, edit=True)

@app.route("/delete_comment/<comment_id>")
@login_required
def delete_comment(comment_id):
    searched_comment=Comment.query.filter_by(id=comment_id).first()
    if not searched_comment==None:
        post_id=searched_comment.parent_post_id
        if int(current_user.get_id())==1 or int(current_user.get_id())==searched_comment.author_id:
            db.session.delete(searched_comment)
            db.session.commit()
            return redirect(url_for("show_post", post_id=post_id))
    return "Selected comment does not exist anymore", 404


@app.route("/edit-post/<int:post_id>",methods=["POST","GET"])
@login_required
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    if int(current_user.get_id()) == 1 or int(current_user.get_id()) == post.author.id:
        edit_form = CreatePostForm(
            title=post.title,
            subtitle=post.subtitle,
            img_url=post.img_url,
            author=post.author,
            body=post.body
        )
        if edit_form.validate_on_submit():
            post.title = edit_form.title.data
            post.subtitle = edit_form.subtitle.data
            post.img_url = edit_form.img_url.data
            post.body = edit_form.body.data
            db.session.commit()
            return redirect(url_for("show_post", post_id=post.id))

        return render_template("make-post.html", form=edit_form,edit=True)


@app.route("/delete/<int:post_id>")
@login_required
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    if int(current_user.get_id()) == 1 or int(current_user.get_id()) == post_to_delete.author.id:
        db.session.delete(post_to_delete)
        db.session.commit()
        return redirect(url_for('get_all_posts'))




if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)
