import os
from flask import Flask, render_template, redirect, url_for, request, flash, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from models import db, User, Post, Comment, Like
from forms import RegisterForm, LoginForm

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///social.db'
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['AVATAR_FOLDER'] = 'static/avatars'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

db.init_app(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.before_first_request
def create_tables():
    db.create_all()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    posts = Post.query.order_by(Post.timestamp.desc()).all()
    return render_template('index.html', posts=posts)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        is_admin = User.query.count() == 0
        hashed_pw = generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password=hashed_pw, is_admin=is_admin)
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for('index'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for('index'))
        flash('Неверные данные для входа.')
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/profile/<username>')
def profile(username):
    user = User.query.filter_by(username=username).first_or_404()
    return render_template('profile.html', user=user)

@app.route('/profile/<username>/edit', methods=['GET', 'POST'])
@login_required
def edit_profile(username):
    user = User.query.filter_by(username=username).first_or_404()
    if user != current_user:
        abort(403)
    if request.method == 'POST':
        new_username = request.form.get('username')
        file = request.files.get('avatar')
        if new_username:
            user.username = new_username
        if file and allowed_file(file.filename):
            filename = secure_filename(f"{user.id}_{file.filename}")
            file.save(os.path.join(app.config['AVATAR_FOLDER'], filename))
            user.avatar = filename
        db.session.commit()
        return redirect(url_for('profile', username=user.username))
    return render_template('edit_profile.html', user=user)

@app.route('/post/new', methods=['POST'])
@login_required
def new_post():
    if current_user.is_banned:
        flash('Вы заблокированы и не можете публиковать посты.')
        return redirect(url_for('index'))
    content = request.form.get('content')
    file = request.files.get('image')
    filename = None
    if file and allowed_file(file.filename):
        filename = secure_filename(f"{current_user.id}_{file.filename}")
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
    if content:
        post = Post(content=content, author=current_user, image=filename)
        db.session.add(post)
        db.session.commit()
    return redirect(url_for('index'))

@app.route('/post/<int:post_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_post(post_id):
    post = Post.query.get_or_404(post_id)
    if post.author != current_user and not current_user.is_admin:
        abort(403)
    if request.method == 'POST':
        post.content = request.form['content']
        db.session.commit()
        return redirect(url_for('index'))
    return render_template('edit_post.html', post=post)

@app.route('/post/<int:post_id>/delete')
@login_required
def delete_post(post_id):
    post = Post.query.get_or_404(post_id)
    if post.author != current_user and not current_user.is_admin:
        abort(403)
    db.session.delete(post)
    db.session.commit()
    return redirect(url_for('index'))

@app.route('/like/<int:post_id>')
@login_required
def like(post_id):
    if current_user.is_banned:
        flash('Вы заблокированы и не можете ставить лайки.')
        return redirect(request.referrer)
    post = Post.query.get_or_404(post_id)
    if not any(l.user_id == current_user.id for l in post.likes):
        like = Like(user=current_user, post=post)
        db.session.add(like)
        db.session.commit()
    return redirect(request.referrer)

@app.route('/comment/<int:post_id>', methods=['POST'])
@login_required
def comment(post_id):
    if current_user.is_banned:
        flash('Вы заблокированы и не можете комментировать.')
        return redirect(request.referrer)
    content = request.form.get('comment')
    if content:
        comment = Comment(content=content, author=current_user, post_id=post_id)
        db.session.add(comment)
        db.session.commit()
    return redirect(request.referrer)

@app.route('/admin/users')
@login_required
def admin_users():
    if not current_user.is_admin:
        abort(403)
    users = User.query.all()
    return render_template('admin_users.html', users=users)

@app.route('/admin/ban/<int:user_id>')
@login_required
def ban_user(user_id):
    if not current_user.is_admin:
        abort(403)
    user = User.query.get_or_404(user_id)
    if user.is_admin or user == current_user:
        abort(403)
    user.is_banned = True
    db.session.commit()
    return redirect(url_for('admin_users'))

@app.route('/admin/unban/<int:user_id>')
@login_required
def unban_user(user_id):
    if not current_user.is_admin:
        abort(403)
    user = User.query.get_or_404(user_id)
    user.is_banned = False
    db.session.commit()
    return redirect(url_for('admin_users'))

if __name__ == '__main__':
    app.run(debug=True)
