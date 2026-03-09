from django.contrib.auth.models import AbstractUser
from django.core.exceptions import ValidationError
from django.db import models
from django.db.models import Q


class CustomUser(AbstractUser):
    ROLE_CHOICES = (
        ("1", "ordinary mason"),
        ("2", "silver mason"),
        ("3", "gold mason"),
        ("4", "architect")
    )

    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default="1")
    is_inspector = models.BooleanField(default=False)
   # is_first_login = models.BooleanField(default=False)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=['role'],
                condition=Q(role='4'),
                name='unique_architect_in_system'
            )
        ]

    def clean(self):
        super().clean()
        if self.role == '4':
            if CustomUser.objects.filter(role='4').exclude(pk=self.pk).exists():
                raise ValidationError({"role": "Only one Architect can be exist"})

    def __str__(self):
        return str(self.username)