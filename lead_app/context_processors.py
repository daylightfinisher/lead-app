from django.conf import settings
from lead_app.models import LeadApi_Settings
from django.contrib.auth.decorators import login_required, user_passes_test
from google.appengine.api import images
from livesettings import config_value





@login_required
def custom_icon(request):
    footer_content = config_value('leadappsettings','copy_rights')
    try: 
        lead_api = LeadApi_Settings.objects.get(user = request.user)
        get_blob_key = str(lead_api.icon_image).split('/')
        image_url = images.get_serving_url(get_blob_key[0])
    except:
        image_url = ''
        lead_api = ''
            

    return {'image_url': image_url,'footer_content':footer_content,'lead_api':lead_api}
