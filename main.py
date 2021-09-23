from flask import Flask, render_template, redirect, url_for, flash, request, g, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
from flask_gravatar import Gravatar
from functools import wraps
import os


app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
ckeditor = CKEditor(app)
Bootstrap(app)

# Initialise gravatar with flask application and default parameters
gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)


# Login Required Decorator for Flask
# Create a admin_only decorator
def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # if id is not 1 then return abort with 403 error
        if current_user.id != 1:
            return abort(403)
        # Otherwise continue with the route function as usual.
        return f(*args, **kwargs)

    return decorated_function


# Initialise a login manager object
login_manager = LoginManager()

# Configure for login
login_manager.init_app(app)


# Login manager to load users
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))  # Modified such that user is based on id in DB


##CONNECT TO DB
# app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL1", "sqlite:///blog.db")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


##CONFIGURE TABLES

# Child table
class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)

    # Create Foreign Key, "users.id" the users refers to the tablename of Users
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))

    # Create reference to the User object, the "posts" refers to the posts property in the User Class
    author = relationship("User", back_populates="posts")

    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)

    # ------------------Parent Relationship-------------------#
    comments = relationship("Comment", back_populates="parent_post")


# CREATE User Table PARENT table
# USER table is parent of comment table
class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))

    # This will act like a List of BlogPost objects attached to each User.
    # The "author" refers to the author property in the BlogPost class.
    posts = relationship("BlogPost", back_populates="author")

    # This acts as a list of Comment objects attached to each user.
    comments = relationship("Comment", back_populates="comment_author")


# CREATE table Comment where tablename = comments
# Comment table is child of USER table.
class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)


    # *******Add child relationship*******#
    # "users.id" The users refers to the tablename of the Users class.
    # "comments" refers to the comments property in the User class.
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    comment_author = relationship("User", back_populates="comments")

    # ------------Child Relationship ------------------
    post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))
    parent_post = relationship("BlogPost", back_populates="comments")
    text = db.Column(db.Text, nullable=False)


# Create the above tables to blog.db database
#db.create_all()


# Everytime you call render_template(), you pass the current_user over to the template.
# current_user.is_authenticated will be True if they are logged in/authenticated after registering.
# You can check for this is header.html
@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts, current_user=current_user)


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    # If its a POST request i.e submit button clicked and form submitted..
    if form.validate_on_submit():

        # Take email from register form and query into DB. If email exists in DB means already registered.
        if User.query.filter_by(email=request.form.get('email')).first():
            flash("This email already exist. Please log in instead.")
            return redirect(url_for('login'))

        hash_and_salted_password = generate_password_hash(
            form.password.data,
            method='pbkdf2:sha256',
            salt_length=8,
        )

        new_user = User(
            email=form.email.data,
            name=form.name.data,
            password=hash_and_salted_password,
        )

        db.session.add(new_user)
        db.session.commit()

        # Login new user after creating account
        login_user(new_user)

        # Log in and authenticate user after adding details to DB
        return redirect(url_for("get_all_posts"))

    # Else if not form submit means going to register page to key in details for submission
    return render_template("register.html", form=form, current_user=current_user)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        # Find user via email on DB
        user = User.query.filter_by(email=email).first()
        print(user)

        # If email does not exist?
        if not user:
            flash('That email does not exist. Please register for an account.')
            print('Email does not exist..')
            return redirect(url_for('login'))

        # else check password hash against DB password hash if email exists and want to check password.
        # if password hash in DB does not equal to password hash typed then invalid
        # Basically below is checking if password hash DB is not equal to typed password hash. == False
        elif not check_password_hash(user.password, password):
            flash("Incorrect password. Please try again.")
            print('Wrong password')
            return redirect(url_for('login'))

        # else if not above 2 scenarios means both also exist and correct. Log in user.
        else:
            login_user(user)
            print("You are logged in!")
            return redirect(url_for('get_all_posts'))

    return render_template("login.html", form=form, current_user=current_user)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=['GET', 'POST'])
def show_post(post_id):
    form = CommentForm()
    requested_post = BlogPost.query.get(post_id)
    comments = Comment.query.get(post_id)

    # If users logged in and form submitted, then take the comment form data and send as POST
    if form.validate_on_submit():

        # Check if user exist and is logged in
        if not current_user.is_authenticated:
            flash("You need to login or register to comment.")
            return redirect(url_for("login"))

        # New Comment Fields data to be added into Comment Table
        new_comment = Comment(
            text=form.comment_text.data,
            # Comment author basically is current_user
            comment_author=current_user,
            # parent_post is the post that the comment is being posted on. i.e the requested_post = post.id
            parent_post=requested_post
        )
        db.session.add(new_comment)
        db.session.commit()

    return render_template("post.html", post=requested_post, current_user=current_user, form=form, comments=comments)


@app.route("/about")
def about():
    return render_template("about.html", current_user=current_user)


@app.route("/contact", methods=['GET', 'POST'])
def contact():
    contact_message = False
    if request.method == 'POST':
        contact_message = True

        return render_template('contact.html', contact_message=contact_message)

    return render_template("contact.html", current_user=current_user)


@app.route("/new-post", methods=['GET', 'POST'])
# Mark with decorator
@admin_only
def add_new_post():
    form = CreatePostForm()
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


@app.route("/edit-post/<int:post_id>", methods=['GET', 'POST'])
# Mark with decorator
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=current_user,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form, is_edit=True, current_user=current_user)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(debug=True, port=5000)
