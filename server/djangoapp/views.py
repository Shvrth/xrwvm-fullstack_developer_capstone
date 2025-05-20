from django.contrib.auth import login, authenticate, logout
from django.contrib.auth.models import User
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt, csrf_protect
from django.views.decorators.http import require_POST, require_http_methods
from django.conf import settings
import json
import logging
from .models import CarMake, CarModel
from .restapis import get_request, analyze_review_sentiments, post_review
from .populate import initiate

logger = logging.getLogger(__name__)


@csrf_exempt
def login_user(request):
    data = json.loads(request.body)
    username = data['userName']
    password = data['password']
    user = authenticate(username=username, password=password)
    response_data = {"userName": username}
    if user is not None:
        login(request, user)
        response_data = {"userName": username, "status": "Authenticated"}
    return JsonResponse(response_data)


@require_POST
@csrf_protect
def logout_view(request):
    username = request.user.username if request.user.is_authenticated else ""
    logout(request)
    return JsonResponse({"userName": username})


@csrf_exempt
def registration(request):
    data = json.loads(request.body)
    username = data['userName']
    password = data['password']
    first_name = data['firstName']
    last_name = data['lastName']
    email = data['email']
    username_exist = False

    try:
        User.objects.get(username=username)
        username_exist = True
    except User.DoesNotExist:
        logger.debug("%s is new user", username)

    if not username_exist:
        user = User.objects.create_user(
            username=username,
            first_name=first_name,
            last_name=last_name,
            password=password,
            email=email
        )
        login(request, user)
        return JsonResponse({"userName": username, "status": "Authenticated"})
    else:
        return JsonResponse({"userName": username, "error": "Already Registered"})


def get_cars(request):
    count = CarMake.objects.filter().count()
    if count == 0:
        initiate()
    car_models = CarModel.objects.select_related('car_make')
    cars = [
        {"CarModel": car_model.name, "CarMake": car_model.car_make.name}
        for car_model in car_models
    ]
    return JsonResponse({"CarModels": cars})


def get_dealerships(request, state="All"):
    endpoint = "/fetchDealers" if state == "All" else f"/fetchDealers/{state}"
    dealerships = get_request(endpoint)
    return JsonResponse({"status": 200, "dealers": dealerships})


def get_dealer_reviews(request, dealer_id):
    if dealer_id:
        endpoint = f"/fetchReviews/dealer/{dealer_id}"
        reviews = get_request(endpoint)
        for review_detail in reviews:
            response = analyze_review_sentiments(review_detail['review'])
            review_detail['sentiment'] = response['sentiment']
        return JsonResponse({"status": 200, "reviews": reviews})
    return JsonResponse({"status": 400, "message": "Bad Request"})


def get_dealer_details(request, dealer_id):
    if dealer_id:
        endpoint = f"/fetchDealer/{dealer_id}"
        dealership = get_request(endpoint)
        return JsonResponse({"status": 200, "dealer": dealership})
    return JsonResponse({"status": 400, "message": "Bad Request"})


@csrf_exempt
@require_http_methods(["POST"])
def add_review(request):
    if request.user.is_anonymous:
        logger.warning("Unauthorized access attempt from anonymous user")
        return JsonResponse({"status": 403, "message": "Unauthorized"}, status=403)

    try:
        data = json.loads(request.body)
        logger.debug("Parsed JSON data: %s", data)
        response = post_review(data)
        logger.info("API response: %s", response)
        return JsonResponse({"status": 200, "message": "Saved"})
    except json.JSONDecodeError as e:
        logger.error("JSONDecodeError: Invalid JSON in request body - %s", str(e))
        return JsonResponse({"status": 400, "message": "Invalid JSON format"}, status=400)
    except Exception as e:
        logger.exception("Error in post_review:")
        return JsonResponse({"status": 500, "message": "Internal server error"}, status=500)
