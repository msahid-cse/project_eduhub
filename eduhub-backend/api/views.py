from django.http import JsonResponse, HttpResponse
from django.views.decorators.csrf import csrf_exempt
from .models.user import User
import json, bcrypt, jwt
from datetime import datetime, timedelta

SECRET_KEY = 'your_secret_key'  # 👉 Move to settings later

# 🏠 Home
def home(request):
    return HttpResponse("🎓 Welcome to EduHub Backend API — Visit /api/ to use the API")

# ✅ Register
@csrf_exempt
def register(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            username = data.get('username')
            email = data.get('email')
            password = data.get('password')
            role = data.get('role', 'user')

            if User.objects(username=username).first():
                return JsonResponse({'error': 'Username already exists'}, status=400)

            hashed_pw = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
            user = User(username=username, email=email, password=hashed_pw, role=role)
            user.save()
            return JsonResponse({'message': 'User registered successfully'})
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)
    
    return JsonResponse({'error': 'Only POST method is allowed'}, status=405)

# ✅ Login
@csrf_exempt
def login(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            username = data.get('username')
            password = data.get('password')

            user = User.objects(username=username).first()
            if user and bcrypt.checkpw(password.encode(), user.password.encode()):
                payload = {
                    'id': str(user.id),
                    'username': user.username,
                    'role': user.role,
                    'exp': datetime.utcnow() + timedelta(hours=1)  # token expires in 1 hour
                }
                token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')
                return JsonResponse({'token': token})
            return JsonResponse({'error': 'Invalid credentials'}, status=401)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)
    
    return JsonResponse({'error': 'Only POST method is allowed'}, status=405)

# 🔒 Protected Test View
@csrf_exempt
def protected_view(request):
    auth_header = request.headers.get('Authorization')

    if not auth_header or not auth_header.startswith('Bearer '):
        return JsonResponse({'error': 'Unauthorized'}, status=401)

    token = auth_header.split(' ')[1]
    try:
        decoded = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        return JsonResponse({'message': 'Welcome, you are authenticated!', 'user': decoded})
    except jwt.ExpiredSignatureError:
        return JsonResponse({'error': 'Token expired'}, status=401)
    except jwt.InvalidTokenError:
        return JsonResponse({'error': 'Invalid token'}, status=401)
