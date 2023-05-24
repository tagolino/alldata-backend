def get_client_ip(request):
    return request.META.get("HTTP_X_GOOGLE_REAL_IP") or \
        request.META.get("HTTP_X_FORWARDED_FOR")
