# Generated by Django 5.1.2 on 2024-10-25 08:49

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('acknowledgementReceipt', '0014_ticketreservation_receipt_of_payment'),
    ]

    operations = [
        migrations.AddField(
            model_name='ridesattraction',
            name='information',
            field=models.TextField(default='Default information text here'),
        ),
    ]
