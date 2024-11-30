# views.py
import logging
from django.shortcuts import render
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import google.generativeai as genai
import os
import json
from .email_analyzer import analyze_email

logger = logging.getLogger(__name__)

# Configure Google Gemini API
API_KEY = "AIzaSyDgi3nN7l5fXQ_c97nclS3v95-8ggPgT50"  # Replace with your actual Gemini API key
genai.configure(api_key=API_KEY)

def base(request):
    return render(request, 'base.html')

def index(request):
    return render(request, 'parser.html')

def analyze(request):
    if request.method == 'POST':
        logger.debug("Received a POST request")
        if request.FILES.get('eml_file'):
            logger.debug("EML file uploaded")
            eml_file = request.FILES['eml_file']
            result = analyze_email(eml_file)
            logger.debug(f"Analysis result: {result}")
            return render(request, 'results.html', {'result': result})
        else:
            logger.debug("No EML file uploaded")
    else:
        logger.debug("Not a POST request")
    return render(request, 'parser.html')

def contact(request):
    return render(request, 'contact-us.html')

@csrf_exempt
def chat(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        user_message = data.get('message', '').strip()

        if not user_message:
            return JsonResponse({'error': 'Message cannot be empty'}, status=400)

        try:
            # Create the generative model and generate content using Gemini
            model = genai.GenerativeModel("gemini-1.5-flash")  # Use correct model ID for Gemini
            response = model.generate_content(user_message)

            # Extract and return the text response from the API
            ai_response = response.text
            return JsonResponse({'response': ai_response})
        
        except Exception as e:
            logger.error(f"Error communicating with Gemini API: {e}")
            return JsonResponse({'error': 'Error processing the AI response'}, status=500)

    return JsonResponse({'error': 'Invalid request method'}, status=400)
