from django.db import models

class DomainQuery(models.Model):
    domain = models.CharField(max_length=255)
    malicious = models.IntegerField()
    suspicious = models.IntegerField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.domain} - {self.created_at.strftime('%Y-%m-%d %H:%M')}"

from django.contrib.auth.models import User

class DomainQuery(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)  # 🔥 yeni satır
    domain = models.CharField(max_length=255)
    malicious = models.IntegerField()
    suspicious = models.IntegerField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.domain} ({self.user.username}) - {self.created_at.strftime('%Y-%m-%d %H:%M')}"
