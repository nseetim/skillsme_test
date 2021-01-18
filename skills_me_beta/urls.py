from django.urls import path

from skills_me_beta import views

app_name = 'skills_me_beta'

urlpatterns = [
    path('signup', views.signup_user, name='signup'),
    path('login', views.login_user, name='login'),
    path('logout', views.logout_user, name='logout'),
    path('password_reset_request/', views.password_reset_request, name='password_reset_request'),
    path('password_reset_confirm/<uidb64>/<token>', views.password_reset_confirm, name='password_reset_confirm'),
    path('current_flights/', views.currently_available_flights, name='current_flights')

]
