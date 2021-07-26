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

app = Flask(__name__, template_folder='../templates')
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)

gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class BlogPost(db.Model):
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


class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(250), nullable=False)
    email = db.Column(db.String(250), unique=True, nullable=False)
    password = db.Column(db.String(250), nullable=False)
    posts = relationship("BlogPost", back_populates="author")  # one to many relationship from User to BlogPost obj(s).
    comments = relationship("Comment", back_populates="comment_author")  # User --> Comment one to many relationship.


class Comment(db.Model):
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


def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # If id is not 1 then return abort with 403 error
        if not current_user.is_authenticated or current_user.id != 1:
            return abort(403)
        # Otherwise continue with the route function
        return f(*args, **kwargs)

    return decorated_function


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts, logged_in=current_user.is_authenticated)


@app.route('/register', methods=["GET", "POST"])
def register():
    new_user_form = RegisterForm()
    if new_user_form.validate_on_submit():
        email = new_user_form.email.data
        user_exists = User.query.filter_by(email=email).first()
        if user_exists:
            flash("The email you entered is for a user that already exists.")
            return redirect(url_for("login"))
        name = new_user_form.name.data
        password = new_user_form.password.data
        pwd_hash = generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)
        new_user = User(
            email=email,
            password=pwd_hash,
            name=name
        )
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)  # Log in and authenticate user after adding details to database.
        return redirect(url_for("get_all_posts"))
    return render_template("register.html", form=new_user_form)


@app.route('/login', methods=["GET", "POST"])
def login():
    login_form = LoginForm()
    if login_form.validate_on_submit():
        pwd_to_verify = login_form.password.data
        email_to_search = login_form.email.data
        user = User.query.filter_by(email=email_to_search).first()
        if not user:
            flash('The email you entered does not exist.')
            return redirect(url_for("login"))
        elif not check_password_hash(user.password, pwd_to_verify):
            flash('The password you entered is incorrect. Please try again.')
            return redirect(url_for("login"))
        else:
            login_user(user)
            return redirect(url_for("get_all_posts"))
    return render_template("login.html", form=login_form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    requested_post = BlogPost.query.get(post_id)
    response_form = CommentForm()
    if response_form.validate_on_submit():
        if not current_user.is_authenticated:
            flash("You need to login or register to comment.")
            return redirect(url_for("login"))
        user_comment = Comment(
            text=response_form.comment.data,
            comment_author=current_user,
            post=requested_post
        )
        db.session.add(user_comment)
        db.session.commit()
        return redirect(url_for("show_post", post_id=requested_post.id))
    return render_template("post.html", post=requested_post, logged_in=current_user.is_authenticated,
                           form=response_form)


@app.route("/about")
def about():
    return render_template("about.html", logged_in=current_user.is_authenticated)


@app.route("/contact")
def contact():
    return render_template("contact.html", logged_in=current_user.is_authenticated)


@app.route("/new-post", methods=["GET", "POST"])
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
    return render_template("make-post.html", form=form, logged_in=current_user.is_authenticated)


@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
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
    return render_template("make-post.html", form=edit_form, logged_in=current_user.is_authenticated, is_edit=True)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)
