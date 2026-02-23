from django.db import models
from django.contrib.auth.models import AbstractUser

class CustomUser(AbstractUser):
    ROLE_CHOICES = (
        ('1', 'ordinary mason'),
        ('2', 'silver mason'),
        ('3', 'gold mason'),
    )

    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default='1')
    is_inspector = models.BooleanField(default=False)
    is_first_login = models.BooleanField(default=False)

    def __str__(self):
        return self.username

