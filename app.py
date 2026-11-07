import os
import secrets
import requests
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from datetime import datetime, timezone
from pathlib import Path
from sqlalchemy import and_, or_ 


from flask import (
    Flask, render_template, redirect, url_for, request,
    flash, abort, jsonify
)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, UserMixin, login_user, logout_user,
    login_required, current_user
)
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from email_validator import validate_email, EmailNotValidError
from PIL import Image, UnidentifiedImageError

BASE_DIR = Path(__file__).resolve().parent
UPLOAD_DIR = BASE_DIR / "static" / "uploads"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

app = Flask(__name__)

app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY")
if not app.config["SECRET_KEY"]:
    raise RuntimeError("Set SECRET_KEY in Render Environment.")

database_url = os.environ.get("DATABASE_URL")
if not database_url:
    raise RuntimeError("Set DATABASE_URL to your PostgreSQL database.")

app.config["SQLALCHEMY_DATABASE_URI"] = database_url.replace(
    "postgres://", "postgresql://", 1
).replace("postgresql://", "postgresql+psycopg://", 1)

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = True
def send_brevo_email(to_email, subject, html_content):
    api_key = os.environ.get("BREVO_API_KEY")
    sender_email = os.environ.get("BREVO_SENDER_EMAIL")

    if not api_key or not sender_email:
        print("Brevo email configuration is missing.")
        return False

    headers = {
        "accept": "application/json",
        "api-key": api_key,
        "content-type": "application/json"
    }

    payload = {
        "sender": {
            "name": "Sankha Web 2.0",
            "email": sender_email
        },
        "to": [{"email": to_email}],
        "subject": subject,
        "htmlContent": html_content
    }

    try:
        response = requests.post(
            "https://api.brevo.com/v3/smtp/email",
            headers=headers,
            json=payload,
            timeout=15
        )
        response.raise_for_status()
        return True

    except requests.RequestException as error:
        print("Brevo email failed:", type(error).__name__)
        return False

db = SQLAlchemy(app)
csrf = CSRFProtect(app)

login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.login_message = "Please log in first."

ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "webp"}


def utcnow():
    return datetime.now(timezone.utc)
def generate_email_token(user):
    serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"])
    return serializer.dumps(user.id, salt="email-verify")


def verify_email_token(token, max_age=86400):
    serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"])
    try:
        user_id = serializer.loads(
            token,
            salt="email-verify",
            max_age=max_age
        )
        return db.session.get(User, int(user_id))
    except (BadSignature, SignatureExpired, ValueError, TypeError):
        return None

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(24), unique=True, nullable=False, index=True)
    email = db.Column(db.String(254), unique=True, nullable=False, index=True)
    email_verified = db.Column(db.Boolean, default=False, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    bio = db.Column(db.String(160), default="")
    created_at = db.Column(db.DateTime(timezone=True), default=utcnow)


class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    body = db.Column(db.String(1000), default="")
    image = db.Column(db.String(255))
    created_at = db.Column(db.DateTime(timezone=True), default=utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    author = db.relationship("User", backref="posts")


class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    body = db.Column(db.String(500), nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey("post.id"), nullable=False)
    author = db.relationship("User")
    post = db.relationship("Post", backref="comments")


class Like(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey("post.id"), nullable=False)
    __table_args__ = (
        db.UniqueConstraint("user_id", "post_id", name="unique_user_post_like"),
    )


class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    body = db.Column(db.String(2000), nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=utcnow)
    sender = db.relationship("User", foreign_keys=[sender_id])
    receiver = db.relationship("User", foreign_keys=[receiver_id])


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


@app.context_processor
def inject_globals():
    def liked_by_me(post):
        if not current_user.is_authenticated:
            return False
        return Like.query.filter_by(
            user_id=current_user.id,
            post_id=post.id
        ).first() is not None

    def like_count(post):
        return Like.query.filter_by(post_id=post.id).count()

    return {
        "site_name": "Sankha Web 2.0",
        "liked_by_me": liked_by_me,
        "like_count": like_count,
    }


@app.route("/")
def index():
    posts = Post.query.order_by(Post.created_at.desc()).limit(100).all()
    return render_template("index.html", posts=posts)


@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("index"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        try:
            email = validate_email(email, check_deliverability=False).normalized
        except EmailNotValidError:
            flash("Enter a valid email address.", "error")
            return render_template("register.html")

        if not (3 <= len(username) <= 24) or not username.replace("_", "").isalnum():
            flash("Username must be 3–24 characters using letters, numbers or underscores.", "error")
        elif len(password) < 10:
            flash("Password must be at least 10 characters.", "error")
        elif User.query.filter_by(username=username).first():
            flash("That username is already taken.", "error")
        elif User.query.filter_by(email=email).first():
            flash("That email is already registered.", "error")
        else:
            user = User(
                username=username,
                email=email,
                password_hash=generate_password_hash(password),
            )
            db.session.add(user)
            db.session.commit()
            login_user(user)
            flash("Account created! Email verification will be available soon.", "success")
            return redirect(url_for("index"))

    return render_template("register.html")

@app.route("/verify-email/<token>")
def verify_email(token):
    user = verify_email_token(token)

    if not user:
        flash("This verification link is invalid or has expired.", "error")
        return redirect(url_for("login"))

    if user.email_verified:
        flash("Your email is already verified. Please log in.", "success")
        return redirect(url_for("login"))

    user.email_verified = True
    db.session.commit()

    flash("Email verified successfully! You can now log in.", "success")
    return redirect(url_for("login"))
    
@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("index"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password_hash, password):
            if not user.email_verified:
                flash("Please verify your email before logging in.", "error")
                return render_template("login.html")

            login_user(user)
            return redirect(url_for("index"))

        flash("Incorrect username or password.", "error")

    return render_template("login.html")


@app.post("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("index"))


def save_image(file):
    if not file or not file.filename:
        return None

    ext = file.filename.rsplit(".", 1)[-1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise ValueError("Use a PNG, JPG or WEBP image.")

    try:
        image = Image.open(file.stream)
        image.verify()
        file.stream.seek(0)
        image = Image.open(file.stream)
        image.thumbnail((1600, 1600))

        filename = secrets.token_hex(16) + ".jpg"
        image.convert("RGB").save(
            UPLOAD_DIR / filename, "JPEG", quality=88
        )
        return filename
    except (UnidentifiedImageError, OSError):
        raise ValueError("That is not a valid image.")


@app.post("/post")
@login_required
def create_post():
    body = request.form.get("body", "").strip()

    if len(body) > 1000:
        flash("Posts must be 1,000 characters or fewer.", "error")
        return redirect(url_for("index"))

    try:
        image_name = save_image(request.files.get("image"))
    except ValueError as exc:
        flash(str(exc), "error")
        return redirect(url_for("index"))

    if not body and not image_name:
        flash("Write a message or choose an image.", "error")
        return redirect(url_for("index"))

    post = Post(body=body, image=image_name, author=current_user)
    db.session.add(post)
    db.session.commit()
    return redirect(url_for("index"))


@app.post("/like/<int:post_id>")
@login_required
def toggle_like(post_id):
    post = db.session.get(Post, post_id)
    if not post:
        abort(404)

    like = Like.query.filter_by(
        user_id=current_user.id, post_id=post.id
    ).first()

    if like:
        db.session.delete(like)
    else:
        db.session.add(Like(user_id=current_user.id, post_id=post.id))

    db.session.commit()
    return redirect(request.referrer or url_for("index"))


@app.post("/comment/<int:post_id>")
@login_required
def add_comment(post_id):
    post = db.session.get(Post, post_id)
    if not post:
        abort(404)

    body = request.form.get("body", "").strip()
    if not body or len(body) > 500:
        flash("Comments must contain 1–500 characters.", "error")
    else:
        db.session.add(Comment(
            body=body, author=current_user, post=post
        ))
        db.session.commit()

    return redirect(request.referrer or url_for("index"))


@app.post("/delete/<int:post_id>")
@login_required
def delete_post(post_id):
    post = db.session.get(Post, post_id)
    if not post:
        abort(404)
    if post.user_id != current_user.id:
        abort(403)

    if post.image:
        (UPLOAD_DIR / secure_filename(post.image)).unlink(missing_ok=True)

    Like.query.filter_by(post_id=post.id).delete()
    Comment.query.filter_by(post_id=post.id).delete()
    db.session.delete(post)
    db.session.commit()
    return redirect(url_for("index"))


@app.route("/u/<username>")
def profile(username):
    user = User.query.filter_by(username=username).first_or_404()
    posts = Post.query.filter_by(user_id=user.id).order_by(
        Post.created_at.desc()
    ).all()
    return render_template("profile.html", profile_user=user, posts=posts)


@app.route("/messages/<username>", methods=["GET", "POST"])
@login_required
def private_messages(username):
    other = User.query.filter_by(username=username).first_or_404()
    if other.id == current_user.id:
        abort(400)

    if request.method == "POST":
        body = request.form.get("body", "").strip()
        if not body or len(body) > 2000:
            flash("Messages must contain 1–2,000 characters.", "error")
        else:
            message = Message(
                sender_id=current_user.id,
                receiver_id=other.id,
                body=body,
            )
            db.session.add(message)
            db.session.commit()
        return redirect(url_for("private_messages", username=username))

    conversation = Message.query.filter(
        or_( 
            and_(
                Message.sender_id == current_user.id,
                Message.receiver_id == other.id,
            ),
            and_(
                Message.sender_id == other.id,
                Message.receiver_id == current_user.id,
            ),
        )
    ).order_by(Message.created_at.asc()).limit(300).all()

    return render_template(
        "conversation.html", other_user=other, messages=conversation
    )


@app.route("/explore")
def explore():
    users = User.query.order_by(User.username.asc()).limit(100).all()
    return render_template("explore.html", users=users)


@app.errorhandler(413)
def file_too_large(_error):
    flash("Images must be 5 MB or smaller.", "error")
    return redirect(url_for("index"))


with app.app_context():
    db.create_all()


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000)),
        debug=False,
    )

