from django.urls import path
from . import views


urlpatterns = [
    path('eml parser/', views.index, name='index'),
    path('', views.base, name='base'),
    path('analyze/', views.analyze, name='analyze'),
    path('contact-us/', views.analyze, name='analyze'),
]
