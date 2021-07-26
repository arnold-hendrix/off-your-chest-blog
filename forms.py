from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired, URL, Email, Length
from flask_ckeditor import CKEditorField


##WTForm
class CreatePostForm(FlaskForm):
    title = StringField("Blog Post Title", validators=[DataRequired()])
    subtitle = StringField("Subtitle", validators=[DataRequired()])
    img_url = StringField("Blog Image URL", validators=[DataRequired(), URL()])
    body = CKEditorField("Blog Content", validators=[DataRequired()])
    submit = SubmitField("Submit Post")


class RegisterForm(FlaskForm):
    name = StringField("Your Name", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired(), Length(min=8)])
    submit = SubmitField("Sign Up")


class LoginForm(FlaskForm):
    email = StringField("Your Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired(), Length(min=8)])
    submit = SubmitField("Log In")


class CommentForm(FlaskForm):
    comment = CKEditorField("", validators=[DataRequired()])
    submit = SubmitField("Submit Comment")


# https://getpocket.com/explore/item/how-to-cook-moist-tender-chicken-breasts-every-time?utm_source=pocket-newtab
# https://nypost.com/2021/04/02/putin-is-russias-sexiest-man-russian-poll-finds/
# https://www.themoscowtimes.com/2021/04/02/putin-named-russias-hottest-man-a73452
# https://www.abc.net.au/triplej/programs/hack/2020-edelman-trust-barometer-shows-growing-sense-of-inequality/11883788