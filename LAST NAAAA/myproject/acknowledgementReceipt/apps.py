from django.apps import AppConfig
from django.db.models.signals import post_migrate


class AcknowledgementreceiptConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'acknowledgementReceipt'

    def ready(self):
        from .signals import create_default_admin_signal
        post_migrate.connect(create_default_admin_signal, sender=self)