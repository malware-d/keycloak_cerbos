
from django.urls import path
from . import views

urlpatterns = [
    path('', views.home, name='home'),
    path('api/cerbos-logs/', views.cerbos_logs_api, name='cerbos_logs_api'),
    path('api/cerbos-logs/poll/', views.cerbos_logs_poll, name='cerbos_logs_poll'),
    path('<str:document_id>/<str:action>/', views.manage_document, name='manage_document'),
    

]