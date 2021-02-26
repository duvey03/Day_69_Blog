from flask import Flask, render_template, redirect, url_for, flash, request
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterForm, Login_Form, Comment_Form
from flask_gravatar import Gravatar
from sqlalchemy import exc, Table, Column, Integer, ForeignKey
from functools import wraps
from flask import abort
from sqlalchemy.ext.declarative import declarative_base
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY")
ckeditor = CKEditor(app)
Bootstrap(app)

# CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)

Base = declarative_base()

gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)

# CONFIGURE TABLES


class User(db.Model, UserMixin, Base):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(250), nullable=False)
    email = db.Column(db.String(250), unique=True, nullable=False)
    password = db.Column(db.String(250), nullable=False)
    posts = relationship("BlogPost", back_populates="author")
    comments = relationship("Comment", back_populates="comment_author")


class BlogPost(db.Model, Base):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)

    # Create a foreign key "users.id" that refers to the "users" tablename and id attribute.
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    # Create reference to the User object, the 'posts' refers to the tablename of User
    author = relationship("User", back_populates="posts")

    # Establish parent relationship with comments
    comments = relationship("Comment", back_populates="parent_post")


class Comment(db.Model, Base):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    comment_text =  db.Column(db.Text, nullable=False)

    # Create a foreign key "users.id" that refers to the "users" tablename and id attribute.
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    # Create reference to the User object, the 'comments' refers to the tablename of User
    comment_author = relationship("User", back_populates="comments")

    # Create a foreign key "blog_posts.id" that refers to the "blog_posts" tablename and id attribute.
    post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))
    # Create reference to the BlogPost object, the 'comments' refers to the tablename of BlogPost
    parent_post = relationship("BlogPost", back_populates="comments")

# Init Databases
db.create_all()

# Clear a database
# User.query.delete()
# db.session.commit()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def not_authorized():
    return "<h1>You are not authorized to visit this page</h1>"

def admin_only(page_function):
    @wraps(page_function)
    def decorated_funtion(*args, **kwargs):
        try:
            if current_user.id != 1:
                return abort(403)
        except:
            return abort(403)
        else:
            return page_function(*args, **kwargs)
    return decorated_funtion


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts, current_user=current_user)


@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        password_hashed = generate_password_hash(form.password.data, method="pbkdf2:sha256", salt_length=8)
        new_user = User(
            name=form.name.data,
            email=form.email.data,
            password=password_hashed
        )
        try:
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            return redirect(url_for('get_all_posts'))
        except exc.IntegrityError:
            flash("User already registered, try logging in instead.")
            return redirect(url_for('login'))


    return render_template("register.html", form=form, current_user=current_user)


@app.route('/login', methods=['GET', "POST"])
def login():
    form = Login_Form()
    if form.validate_on_submit():
        email = form.email.data
        entered_password = form.password.data
        user = User.query.filter_by(email=email).first()
        if user is not None:
            if check_password_hash(user.password, entered_password):
                login_user(user)
                flash("Logged In!")
                return redirect(url_for('get_all_posts'))
            else:
                flash("Invalid Password")
                return redirect(url_for('login'))
        else:
            flash("That user does not exist.")
            return redirect(url_for('login'))

    return render_template("login.html", form=form, current_user=current_user)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    requested_post = BlogPost.query.get(post_id)
    form = Comment_Form()
    if form.validate_on_submit():
        if not current_user.is_authenticated:
            flash("You need to login or register to comment.")
            return redirect(url_for('login'))
        new_comment = Comment(
            comment_text=form.comment.data,
            comment_author=current_user,
            parent_post=requested_post
        )
        db.session.add(new_comment)
        db.session.commit()


    return render_template("post.html", post=requested_post, current_user=current_user, form=form)


@app.route("/about")
def about():
    return render_template("about.html", current_user=current_user)


@app.route("/contact")
def contact():
    return render_template("contact.html", current_user=current_user)


@app.route("/new-post", methods=["POST", "GET"])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if request.method == "POST":
        if form.validate_on_submit():
            new_post = BlogPost(
                title=form.title.data,
                subtitle=form.subtitle.data,
                body=form.body.data,
                img_url=form.img_url.data,
                author=current_user,
                date=date.today().strftime("%B %d, %Y")
            )
            db.session.add(new_post)
            db.session.commit()
            return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form, current_user=current_user)


@app.route("/edit-post/<int:post_id>")
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
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
        post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form, current_user=current_user)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(debug=True)
