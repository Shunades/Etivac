from django.db.utils import OperationalError, ProgrammingError


def create_default_admin_signal(sender, **kwargs):
    try:
        from .models import EAAdminAccount
        EAAdminAccount.create_default_admin()
    except (OperationalError, ProgrammingError):
        pass
