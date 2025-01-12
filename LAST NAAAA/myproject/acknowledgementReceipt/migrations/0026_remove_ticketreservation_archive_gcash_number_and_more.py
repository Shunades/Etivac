# Generated by Django 5.0.6 on 2025-01-11 23:29

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('acknowledgementReceipt', '0025_ticketreservation_archive_gcash_number'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='ticketreservation_archive',
            name='Gcash_number',
        ),
        migrations.AddField(
            model_name='ticketreservation',
            name='Gcash_number',
            field=models.PositiveIntegerField(default=0),
        ),
    ]
