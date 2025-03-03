from django.urls import path
from . import views
from .views import download_pdf


urlpatterns = [
    path('eml parser/', views.index, name='index'),
    path('', views.base, name='base'),
    path('analyze/', views.analyze, name='analyze'),
    path('contact-us/', views.contact, name='contact-us'),
    path('chat/', views.chat, name='chat'),
     path("download-pdf/", download_pdf, name="download_pdf")
]
