"""SAST fixture: Django settings and views."""
from django.contrib.auth.models import User
from django.http import HttpResponse
from django.utils.safestring import mark_safe
from django.views.decorators.csrf import csrf_exempt

# tg-expect: SAST-080 | high | CWE-489 | Django DEBUG enabled
DEBUG = True
# tg-expect: SAST-081 | medium | CWE-183 | ALLOWED_HOSTS wildcard
ALLOWED_HOSTS = ["*"]


def user_by_name(request):
    name = request.GET.get("name")
    # tg-expect: SAST-082 | critical | CWE-89 | Tainted SQL injection: request.GET -> QuerySet.raw f-string
    users = User.objects.raw(f"SELECT * FROM auth_user WHERE username = '{name}'")
    return HttpResponse(", ".join(u.username for u in users))


def users_sorted(request):
    clause = request.GET.get("where")
    # tg-expect: SAST-083 | high | CWE-89 | Tainted SQL injection: request.GET -> QuerySet.extra(where=)
    return HttpResponse(str(list(User.objects.extra(where=[clause]))))


def profile_bio(request):
    bio = request.GET.get("bio", "")
    # tg-expect: SAST-084 | high | CWE-79 | XSS: mark_safe on request data
    return HttpResponse(mark_safe("<p>" + bio + "</p>"))


# tg-expect: SAST-085 | medium | CWE-352 | CSRF protection disabled on state-changing view
@csrf_exempt
def change_email(request):
    request.user.email = request.POST["email"]
    request.user.save()
    return HttpResponse("updated")
