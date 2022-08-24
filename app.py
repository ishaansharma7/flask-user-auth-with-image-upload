import traceback
import uuid
from flask import Flask, request, jsonify, send_file, url_for
from werkzeug.utils import secure_filename
import bcrypt
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
from models import User
from extensions import db
import os

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///sqlite.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False


UPLOAD_FOLDER = 'uploaded_pics'
ALLOWED_EXTENSIONS = set(['txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'])
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def renamed_file(email, filename):
    pre_email = email.split('@')[0]
    unique_id = str(uuid.uuid4())
    file_ext = filename.rsplit('.', 1)[1].lower()
    print('ext-----', file_ext)
    return pre_email + '|' + unique_id + '.' + file_ext


db.init_app(app)
app.config['JWT_SECRET_KEY'] = '74cae432-b297-41ea-b8ad-aef99184d0f6'
jwt = JWTManager(app)

@app.route('/register', methods=['POST'])
def register():
    try:
        email = request.json.get('email', None)
        password = request.json.get('password', None)
        if not email:
            return jsonify({'error':'provide email'}), 400
        if not password:
            return jsonify({'error':'provide password'}), 400
        already_present = User.query.filter_by(email=email).first()
        if already_present:
            return jsonify({'error':'user already exist'}), 400
        hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        user = User(email=email, password=hashed)
        db.session.add(user)
        db.session.commit()
        access_token = create_access_token(identity={"email": email})
        return {"access_token": access_token}, 200
    except Exception:
        traceback.print_exc()
        return jsonify({'error':'provide email and password'}), 400


@app.route('/login', methods=['POST'])
def login():
    try:
        email = request.json.get('email', None)
        password = request.json.get('password', None)
        if not email:
            return jsonify({'error':'provide email'}), 400
        if not password:
            return jsonify({'error':'provide password'}), 400
        
        user = User.query.filter_by(email=email).first()
        if not user:
            return jsonify({'error':'user not found with the given credentials'}), 404
        if bcrypt.checkpw(password.encode('utf-8'), user.password):
            access_token = create_access_token(identity={"email": email})
            return {"access_token": access_token}, 200
        else:
            return jsonify({'error':'incorrect password'}), 400
    except Exception:
        traceback.print_exc()
        return jsonify({'error':'provide email and password'}), 400



@app.route('/test', methods=['GET'])
@jwt_required()
def test():
    user = get_jwt_identity()
    email = user['email']
    return jsonify({'message': f'welcome {email}'})


@app.route('/profile-pic/upload', methods=['POST'])
@jwt_required()
def upload_profile_pic():
    jwt_user = get_jwt_identity()
    email = jwt_user['email']
    user = User.query.filter_by(email=email).first()
    if 'file' not in request.files:
        return jsonify({'error':'image not provided'}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error':'No selected file'}), 400
    if file and allowed_file(file.filename):
        file.filename = renamed_file(email, file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], file.filename))
        user.profile_pic = file.filename
        db.session.add(user)
        db.session.commit()
        return jsonify({'message': 'successfully uploaded image'})


@app.route('/profile-details/upload', methods=['POST'])
@jwt_required()
def upload_profile_details():
    jwt_user = get_jwt_identity()
    email = jwt_user['email']
    try:
        full_name = request.json['full_name']
        bio = request.json['bio']
        age = request.json['age']
        if not full_name or not bio or not age:
            return jsonify({'error': 'details missing'}), 400
        user = User.query.filter_by(email=email).first()
        user.full_name = full_name
        user.bio = bio
        user.age = age
        db.session.add(user)
        db.session.commit()
        return jsonify({'message': f'details added for {email}'})
    except Exception:
        traceback.print_exc()
        return jsonify({'error': 'something went wrong'}), 500
        


@app.route('/get-image/<filename>', methods=['GET'])
def get_image(filename):
    filename = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    return send_file(filename, mimetype='image/gif')



@app.route('/display-details', methods=['GET'])
@jwt_required()
def display_details():
    jwt_user = get_jwt_identity()
    email = jwt_user['email']
    user = User.query.filter_by(email=email).first()
    res = {
        'email': user.email,
        'name': user.full_name,
        'age': user.age,
        'bio': user.bio,
        'profile_pic': url_for('get_image', filename=user.profile_pic)
        }
    return jsonify(res)

if __name__ == '__main__':
    app.run(debug=True, port=5000)