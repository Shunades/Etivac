from django.urls import path
from . import views
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path('', views.index, name='index'),
    path('ridesAttraction/', views.ridesAtt, name='ridesAttraction'),
    path('signin/', views.signin, name='signin'),
    path('signup/', views.Signup, name='signup'),
    path('verify_email/', views.verify_email, name='verify_email'),  # New route for email verification
    path('costumer_main/', views.costumer_main, name='costumer_main'),
    path('buy_ticket/', views.submit_ticket, name='buy_ticket'),  # Corrected function name
    path('cost_Rides/', views.cost_rides, name='cost_Rides'),
    path('cost_account/', views.cost_acc, name='cost_acc'),
    path('eaadmin/account/', views.admin_acc, name='eaadmin_acc'),
    path('eaadmin/history/', views.admin_history, name='eaadmin_history'),
    path('eaadmin/create/', views.eaadmin_create, name='eaadmin_create'),
    path('eaadmin/rides/', views.eaadmin_rides, name='eaadmin_rides'),  # Correct path
    path('gateadmin/account/', views.gateadmin_acc, name='gateadmin_acc'),
    path('gateadmin/history/', views.gateadmin_bh, name='gateadmin_bh'),
    path('gateadmin/buyticket/', views.gateadminticket, name='gateadminticket'),
    path('invoice/', views.invoice, name='invoice'),
    path('logout/', views.user_logout, name='logout'),
    path('forgot-password/', views.forgot_password, name='forgot_password'),
    path('verify-otp/', views.verify_otp, name='verify_otp'),
    path('reset-password/', views.reset_password, name='reset_password'),
    path('generate-report/', views.generate_report, name='generate_report'),
    path('payment/', views.payment_view, name='payment'),  # Add this line
    path('GateAdminInvoice/', views.invoice2, name='GateAdminInvoice'),
    path('GateAdminPayment/', views.payment_view2, name='GateAdminPayment'),
    path('send_email/', views.send_email, name='send_email'),
    path('mark_paid/', views.mark_paid, name='mark_paid'),
    path('send_email/', views.send_receipt_email, name='send_receipt_email'),

    
    


    

  
]  
