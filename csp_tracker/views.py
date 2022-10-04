from django.http import HttpRequest, HttpResponse
import json

def report_uri(request: HttpRequest) -> HttpResponse:
    report = json.loads(request.body.decode())
    print(report)
    return HttpResponse()

