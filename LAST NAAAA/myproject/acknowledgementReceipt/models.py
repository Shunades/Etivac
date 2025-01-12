from django.db import models
from django.core.validators import EmailValidator
from django.contrib.auth.hashers import make_password
from django.utils import timezone
from django.contrib.auth.models import AbstractUser
import uuid
from django.utils.crypto import get_random_string




class CustomUser(AbstractUser):
    """
    Custom user model with email verification functionality.
    """
    email_verified = models.BooleanField(default=False)
    verification_code = models.CharField(max_length=6, null=True, blank=True)  # Email verification code

    def generate_verification_code(self):
        """
        Generates a unique 6-digit verification code.
        """
        self.verification_code = get_random_string(6, allowed_chars='0123456789')
        self.save()

    def __str__(self):
        return self.username
    
class EAAdminAccount(models.Model):
    email = models.EmailField(unique=True, validators=[EmailValidator()])
    password = models.CharField(max_length=128)

    @classmethod
    def create_default_admin(cls):
        # List of admin accounts to be created (removed 'admin@etivacthrillz.admin.com')
        admin_accounts = [
            ('admin1@etivacthrillz.admin.com', 'etivacthrillz1'),
            ('admin2@etivacthrillz.admin.com', 'etivacthrillz2'),
            ('admin3@etivacthrillz.admin.com', 'etivacthrillz3'),
        ]

        for email, password in admin_accounts:
            if not cls.objects.filter(email=email).exists():
                cls.objects.create(
                    email=email,
                    password=make_password(password)  # Hash the password before storing
                )

class gate_adminaccount(models.Model):
    first_name = models.CharField(max_length=150)
    last_name = models.CharField(max_length=150)
    email = models.EmailField(unique=True)
    password = models.CharField(max_length=255)  # The password will be hashed before storing

    def __str__(self):
        return f"{self.first_name} {self.last_name} ({self.email})"

class RidesAttraction(models.Model):
    CATEGORY_CHOICES = [
        ('attractions', 'Attractions'),
        ('kiddie', 'Kiddie Rides'),
        ('family', 'Family Rides'),
        ('extreme', 'Extreme Rides'),
    ]
    
    image = models.ImageField(upload_to='attractions/')
    description = models.TextField(max_length=100)  # Limit to 100 characters
    information = models.TextField(default='Default information text here')
    category = models.CharField(max_length=50, choices=CATEGORY_CHOICES, default='attractions')

    def __str__(self):
        return f"Attraction: {self.description[:50]}"  # Display first 50 characters

class RidesAttraction_Archive(models.Model):
    picture = models.ImageField(upload_to='archive_attractions/')  # Stores archived images in a separate directory
    archived_description = models.TextField()  # Stores the description of the archived attraction
    archived_information = models.TextField()  # Stores archived information
    
    def __str__(self):
        return f"Archived Attraction: {self.archived_description[:50]}"

class TicketReservation(models.Model):
    customer_name = models.CharField(max_length=150)
    customer_email = models.EmailField()
    unlimited_quantity = models.PositiveIntegerField(default=0)
    limited_quantity = models.PositiveIntegerField(default=0)
    number_of_rides = models.PositiveIntegerField(default=0)
    receipt_of_payment = models.PositiveIntegerField(default=0)
    total_price = models.DecimalField(max_digits=10, decimal_places=2)
    date_of_purchase = models.DateTimeField()
    ticket_date_availed = models.DateTimeField(null= True, blank= True)
    Gcash_number = models.PositiveIntegerField(default=0)
    status = models.CharField(
        max_length=50,
        choices=[('PENDING', 'Pending'), ('PAID', 'Paid'), ('DECLINED', 'Declined')],
        default='PENDING'
    )

    def __str__(self):
        return f"Ticket for {self.customer_name}"

class TicketReservation_Archive(models.Model):
    customer_name_archive = models.CharField(max_length=150)
    customer_email_archive = models.EmailField()
    unlimited_quantity_archive = models.PositiveIntegerField(default=0)
    limited_quantity_archive = models.PositiveIntegerField(default=0)
    number_of_rides_archive = models.PositiveIntegerField(default=0)
    receipt_of_payment_archive = models.PositiveIntegerField(default=0)
    total_price_archive = models.DecimalField(max_digits=10, decimal_places=2)
    ticket_date_availed = models.DateTimeField(null= True, blank= True)
    date_of_purchase_archive = models.DateTimeField()

    def __str__(self):
        return f"Ticket for {self.customer_name}"

class Ticket(models.Model):
    customer_name = models.CharField(max_length=255)
    customer_email = models.EmailField()
    status = models.CharField(max_length=20, choices=[('PENDING', 'Pending'), ('PAID', 'Paid'), ('DECLINED', 'Declined')], default='PENDING')
    qr_code = models.URLField(null=True, blank=True)  # Store the URL of the generated QR code
    receipt_number = models.CharField(max_length=20, null=True, blank=True)  # Store the unique receipt number

    def __str__(self):
        return f"{self.customer_name} - {self.status}"