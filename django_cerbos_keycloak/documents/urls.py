
from django.urls import path
from . import views

urlpatterns = [
    path('', views.home, name='home'),
    path('<str:document_id>/<str:action>/', views.manage_document, name='manage_document'),

]