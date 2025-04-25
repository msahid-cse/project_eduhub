from django.urls import path
from .views import register, login, home, protected_view

urlpatterns = [
    path('', home),
    path('register/', register),
    path('login/', login),
    path('protected/', protected_view),
]
