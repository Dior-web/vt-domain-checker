from django.shortcuts import render, redirect  # <-- redirect burada
import requests
import os
from dotenv import load_dotenv
from .models import DomainQuery  # <-- Bunu ekle

load_dotenv()  # .env dosyasını yükle

API_KEY = os.getenv("VT_API_KEY")


def domain_check_view(request):
    result = None

    if request.method == 'POST':
        domain = request.POST.get('domain')
        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        headers = {
            "x-apikey": API_KEY
        }

        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            data = response.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]

            # 🔥 Veritabanına sorguyu kaydet
            DomainQuery.objects.create(
                user=request.user,
                domain=domain,
                malicious=stats["malicious"],
                suspicious=stats["suspicious"]
            )

            result = {
                "domain": domain,
                "malicious": stats["malicious"],
                "suspicious": stats["suspicious"]
            }
        else:
            result = {"error": "API isteği başarısız."}

    return render(request, 'check/domain_form.html', {"result": result})

from django.contrib.auth.decorators import login_required

@login_required(login_url='/login/')
def domain_history_view(request):
    query = request.GET.get('q')  # arama kutusundaki input
    if query:
        sorgular = DomainQuery.objects.filter(user=request.user, domain__icontains=query).order_by('-created_at')
    else:
        sorgular = DomainQuery.objects.filter(user=request.user).order_by('-created_at')
    return render(request, 'check/domain_history.html', {'sorgular': sorgular, 'q': query})


from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth import login

def signup_view(request):
    if request.method == 'POST':
        form = UserCreationForm(request.POST)
        if form.is_valid():
            user = form.save()
            login(request, user)  # kayıt sonrası otomatik giriş
            return redirect('/')  # istersen '/gecmis/' de yapabilirsin
    else:
        form = UserCreationForm()
    return render(request, 'check/signup.html', {'form': form})
