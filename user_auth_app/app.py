from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager

# Khởi tạo Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'  # Khóa bảo mật
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'  # Database SQLite
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # Tắt theo dõi thay đổi (để tiết kiệm bộ nhớ)

# Khởi tạo các thư viện sau khi tạo ứng dụng
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Import routes sau khi các thư viện được khởi tạo
from routes import *

# Đảm bảo tạo bảng nếu chưa có (dùng db.create_all())
with app.app_context():
    db.create_all()  # Tạo bảng nếu chưa tồn tại

if __name__ == "__main__":
    app.run(debug=True)
