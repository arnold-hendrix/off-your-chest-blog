from flask import Flask, render_template, redirect, url_for, flash, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
from flask_gravatar import Gravatar
import email_validator
from functools import wraps
# import os

app = Flask(__name__, template_folder='templates')
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
# app.config['SECRET_KEY'] = os.environ['SECRET_KEY']
ckeditor = CKEditor(app)  # init comment editor object.
Bootstrap(app)  # init Bootstrap object.

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
# app.config['SQLALCHEMY_DATABASE_URI'] = os.environ['SQLALCHEMY_DATABASE_URI']
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)  # init SQLAlchemy db object.
login_manager = LoginManager()  # init login_manager object for user authentication.
login_manager.init_app(app)

gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)  # init gravatar object for user avatar on comment section.


@login_manager.user_loader  # function to load user with id.
def load_user(user_id):
    return User.query.get(int(user_id))


class BlogPost(db.Model):  # class that defines a blogpost object.
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))  # will attach to the user that creates a new post.
    author = relationship("User", back_populates="posts")  # author is a User object. the author can be accessed by
    # accessing the property, "name" in author user object. The default author in this case is admin.
    # any time a user creates a post, the author properties in this class identify the user as the author.
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    comments = relationship("Comment", back_populates="post")  # One to many from BlogPost to Comment obj(s).


class User(UserMixin, db.Model):  # defines a user object.
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(250), nullable=False)
    email = db.Column(db.String(250), unique=True, nullable=False)
    password = db.Column(db.String(250), nullable=False)
    posts = relationship("BlogPost", back_populates="author")  # one to many relationship from User to BlogPost obj(s).
    comments = relationship("Comment", back_populates="comment_author")  # User --> Comment one to many relationship.


class Comment(db.Model):  # defines a comment object.
    __tablename__ = "comment"
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    # --------------------------------------------------User ----> Comment(s) relationship ------------------------------- #
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))  # will attach to the user that makes a new comment.
    comment_author = relationship("User", back_populates="comments")
    # ----------------------------------------------BlogPost ----> Comment(s) relationship ------------------------------- #
    post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))
    post = relationship("BlogPost", back_populates="comments")


# db.create_all()  # should ideally be done in the terminal.


def admin_only(f):  # wrapper function that restricts web page access to admin only (userID: 1).
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # If id is not 1 return abort with 403 error
        if not current_user.is_authenticated or current_user.id != 1:
            return abort(403)
        # continue with route function
        return f(*args, **kwargs)

    return decorated_function


@app.route('/')  # wrapper function that creates url routes for html page returned by its function.
def get_all_posts():  # function that returns the home page.
    posts = BlogPost.query.all()  # return all posts on page load.
    return render_template("index.html", all_posts=posts, logged_in=current_user.is_authenticated)


@app.route('/register', methods=["GET", "POST"])  # url wrapper function with kwargs to allow capture of form input.
def register():  # returns the user registration page.
    new_user_form = RegisterForm()
    if new_user_form.validate_on_submit():  # get user registration data when form is filled.
        email = new_user_form.email.data
        user_exists = User.query.filter_by(email=email).first()
        if user_exists:  # check if registration attempt is from an existing user.
            flash("The email you entered is for a user that already exists.")
            return redirect(url_for("login"))  # redirect to login page if user already exists.
        name = new_user_form.name.data  # continue with new user registration.
        password = new_user_form.password.data
        pwd_hash = generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)  # hash for user password.
        new_user = User(
            email=email,
            password=pwd_hash,
            name=name
        )  # new user object.
        db.session.add(new_user)  # added to user table in db.
        db.session.commit()  # confirm change to db.
        login_user(new_user)  # Log in and authenticate user.
        return redirect(url_for("get_all_posts"))  # send user back to home page.
    return render_template("register.html", form=new_user_form)


@app.route('/login', methods=["GET", "POST"])
def login():  # returns the login page.
    login_form = LoginForm()
    if login_form.validate_on_submit():  # get user login data from form.
        pwd_to_verify = login_form.password.data
        email_to_search = login_form.email.data
        user = User.query.filter_by(email=email_to_search).first()  # search for user in db through email property.
        if not user:  # flash error msg if user does not exist and reload login page.
            flash('The email you entered does not exist.')
            return redirect(url_for("login"))
        elif not check_password_hash(user.password, pwd_to_verify):  # flash error msg if incorrect password for user.
            flash('The password you entered is incorrect. Please try again.')
            return redirect(url_for("login"))
        else:  # login user and redirect to home page if user validation succeeds.
            login_user(user)
            return redirect(url_for("get_all_posts"))
    return render_template("login.html", form=login_form)


@app.route('/logout')
def logout():  # logs out user and redirects to the home page.
    logout_user()  # function to log out user.
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):  # returns a blog post page by post id.
    requested_post = BlogPost.query.get(post_id)  # query db for blogpost using post_id property.
    response_form = CommentForm()
    if response_form.validate_on_submit():  # get user comment from comment form.
        if not current_user.is_authenticated:  # check if comment is from authenticated user.
            flash("You need to login or register to comment.")
            return redirect(url_for("login"))  # return to login page if not authenticated.
        user_comment = Comment(
            text=response_form.comment.data,
            comment_author=current_user,
            post=requested_post
        )  # new user comment object.
        db.session.add(user_comment)  # added to comment table in db.
        db.session.commit()
        return redirect(url_for("show_post", post_id=requested_post.id))  # reload page to show it with user comment.
    return render_template("post.html", post=requested_post, logged_in=current_user.is_authenticated,
                           form=response_form)


@app.route("/about")
def about():  # returns the about page.
    return render_template("about.html", logged_in=current_user.is_authenticated)


@app.route("/contact")
def contact():  # returns the contact page.
    return render_template("contact.html", logged_in=current_user.is_authenticated)


@app.route("/new-post", methods=["GET", "POST"])
@admin_only
def add_new_post():  # returns the make-post page (create new blogpost) - visible to admin only.
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )  # new blogpost object.
        db.session.add(new_post)  # add to blogpost table in db.
        db.session.commit()
        return redirect(url_for("get_all_posts"))  # return to home page to show new blogpost.
    return render_template("make-post.html", form=form, logged_in=current_user.is_authenticated)


@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@admin_only
def edit_post(post_id):  # returns existing blog post in make-post page editor for editing.
    post = BlogPost.query.get(post_id)  # retrieve blogpost from db by id.
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=current_user,
        body=post.body
    )  # fill form with blogpost properties for editing.
    if edit_form.validate_on_submit():  # get edited form and update properties in db.
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))  # load page displaying newly edited form.
    return render_template("make-post.html", form=edit_form, logged_in=current_user.is_authenticated, is_edit=True)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):  # function to delete post on home page by id - delete icon visible to admin only.
    post_to_delete = BlogPost.query.get(post_id)  # get the post to delete by id.
    db.session.delete(post_to_delete)  # delete from blogpost table using id property.
    db.session.commit()  # confirm action.
    return redirect(url_for('get_all_posts'))  # redirect to home.


if __name__ == "__main__":  # run flask app on local host.
    app.run(host='0.0.0.0', port=5000)
