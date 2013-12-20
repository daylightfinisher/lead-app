from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth import login as auth_login, authenticate,logout as auth_logout
from django.utils.encoding import smart_str, smart_unicode
from django.shortcuts import render_to_response,render, get_object_or_404,redirect
from django.conf import settings
from django.http import HttpResponseRedirect, HttpResponse
from datetime import date,timedelta,datetime
from urllib import urlencode
import logging
import json
import urllib
import urllib2

from google.appengine.api import urlfetch
from lead_app.models import Api_Settings,LeadApi_Settings
from livesettings import config_value

#####################################
#     OAuth Credentials             #
#####################################
redirect_uri = settings.REDIRECT_URI
client_id = settings.CLIENT_ID
secret = settings.SECRET

@login_required(login_url='/login/')
def home(request):
    '''
    Lead enhancer settings. Using to configure google analytics id and
    Openapi Lead enhancer.
    '''
    user = request.user
    usr_obj = User.objects.get(username=user)
    #initialize the info message
    info_msg = ''
    
    try:
        ga_api = Api_Settings.objects.get(user=request.user)
    except:
        ga_api = None
        pass
    try:
        lead_api = LeadApi_Settings.objects.get(user=request.user)
    except:
        lead_api = None
        pass
    
    if request.method == 'POST':
        if 'profile_id' in request.POST:
            try:
                ga_profile,created = Api_Settings.objects.get_or_create(user=request.user)
                if created:
                    ga_profile.ga_profile_id = request.POST['profile_id']
                    ga_profile.save()
                else:
                    ga_profile.ga_profile_id = request.POST['profile_id']
                    ga_profile.save()
                href = 'https://accounts.google.com/o/oauth2/auth?response_type=code&redirect_uri=%s&client_id=%s&scope=https://www.googleapis.com/auth/analytics.readonly&access_type=offline&approval_prompt=force'%(redirect_uri, client_id)    
                return HttpResponseRedirect(href)
                #return render(request, 'configure.html', {'msg':'Your Google analytics profile id has been configured'})            
            except Exception as e:
                logging.info(str(e))
                pass
            
        if 'token_id' in request.POST:
            try:
                lead_settings,created = LeadApi_Settings.objects.get_or_create(user=usr_obj)    
                if created:
                    lead_settings.lead_token = request.POST['token_id']
                    lead_settings.save()
                else:
                    lead_settings.lead_token = request.POST['token_id']
                    lead_settings.save()
                
                try:
                    ga_api = Api_Settings.objects.get(user=request.user)
                except:
                    ga_api = None
                    pass
                try:
                    lead_api = LeadApi_Settings.objects.get(user=request.user)
                except:
                    lead_api = None
                    pass
                
                return render(request, 'configure.html', {'ga_api':ga_api,'lead_api':lead_api, 'msg':'Your Lead token has been configured'})
            
            except Exception as e:
                logging.info(str(e))
                pass
            
    if ga_api == None or lead_api == None:
        info_msg = 'Please configure both Google Analyics and Leadenhancer Apis to view the report'
        
    return render(request, 'configure.html', {'ga_api':ga_api,'lead_api':lead_api, 'info_msg':info_msg})


def oauth2callback(request):
    '''
    Get the Google Oauth Access.
    '''
    user = request.user
    
    from urllib import urlencode
    import urllib2
    import json
    
    if request.GET:
        if request.GET['code']:
            code = request.GET['code']
            url = 'https://accounts.google.com/o/oauth2/token'
            
            data = dict(code=str(code), client_id=client_id, client_secret=secret, redirect_uri=redirect_uri, grant_type='authorization_code')
            
            response = urllib2.urlopen(url, urlencode(data))
            response_details = json.loads(response.read())
            #analytics_id = request.session['analytics_id']
            lead_analytics_access = Api_Settings.objects.get(user=request.user)
            
            lead_analytics_access.access_token = response_details['access_token']
            lead_analytics_access.refresh_token = response_details['refresh_token']
            lead_analytics_access.expires = response_details['expires_in']
            lead_analytics_access.token_type = response_details['token_type']
            #lead_analytics_access.response = response_details
            lead_analytics_access.save()
       
        else:
            error_message = str(request.GET['error'])
        
    return HttpResponseRedirect('/')
    #return render(request, 'configure.html', {'msg':'Your GA Profile ID has been configured',})


def oauth2callback_using_refresh_token(request, **kwargs):
    '''
    Oauth Refresh token generation.
    '''
    try:
        user = request.user
        api_settings = Api_Settings.objects.get(user=user)
        refresh_token = api_settings.refresh_token
        
        url = 'https://accounts.google.com/o/oauth2/token'
        data = dict(refresh_token=refresh_token, client_id=client_id, client_secret=secret, grant_type='refresh_token')
        
        response = urllib2.urlopen(url, urlencode(data))
        response_details = json.loads(response.read())
        
        api_settings.access_token = response_details['access_token']
        api_settings.expires = response_details['expires_in']
        #api_settings.response = response_details
        api_settings.save()
        refreshed = True
        return refreshed
        #return HttpResponse("New Token Created Successfully")
    
    except Exception as e:
        logging.info(str(e))
        return HttpResponse("New Token Creation Error %s"%(str(e)))


def login(request):
    '''
    Login page for Lead Enhancer
    '''
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        user = authenticate(username=username, password=password)
        if user is not None:
            if user.is_active:
                auth_login(request, user)
                return redirect('view_reports')
                #return redirect('home')
            else:
                return render(request, 'login.html', {'msg':'User is not active'})
        else:
            return render(request, 'login.html', {'msg':'Your username and password didnt match. Please try again.'})
    return render(request, 'login.html', {})


def logout(request):
    auth_logout(request)
    return redirect('login')


@login_required(login_url='/login/')
@csrf_exempt
def view_reports(request):
    '''
    Reports display the Google analytics and Lead Enhancer.
    '''
    user = request.user
    try:
        api_settings = Api_Settings.objects.get(user=user)
        lead_api_settings = LeadApi_Settings.objects.get(user=user)
    except:
        return HttpResponseRedirect('/')
    
    if api_settings.ga_profile_id == None or lead_api_settings.lead_token == None :
        return HttpResponseRedirect('/')
    
    try:
        from_date_range = date.today() - timedelta(days=30)
        to_date_range = date.today()
        from_date = str(from_date_range.year)+'-'+str(from_date_range.month)+'-'+str(from_date_range.day)
        to_date = str(to_date_range.year)+'-'+str(to_date_range.month)+'-'+str(to_date_range.day)
    except Exception as e:
        logging.info(str(e))
        pass

    if request.method == "POST":
        if 'from_date' in request.POST:
            from_date = request.POST['from_date']
            to_date = request.POST['to_date']
            if from_date == '' and to_date == '':
                from_date_range = date.today() - timedelta(days=30)
                to_date_range = date.today()
                from_date = str(from_date_range.year)+'-'+str(from_date_range.month)+'-'+str(from_date_range.day)
                to_date = str(to_date_range.year)+'-'+str(to_date_range.month)+'-'+str(to_date_range.day)
            page_title = request.POST['page_title']
            
            try:
                #Session create for from_date, to_date and page title or url
                request.session['from_date'] = from_date
                request.session['to_date'] = to_date
                request.session['page_title'] = page_title
            except:
                pass
            
            ## Page URL Report Generation ##
            #Check page title input is url or page title
            page_list = page_title.split('https://')

            if len(page_list) == 1:
                page_list = page_title.split('http://')
            
            generate_url = 'http://openapi.leadenhancer.com/v1/leadopenapi/visits?token=%s&fromdate=%s&todate=%s&countriesiso=DE'% (lead_api_settings.lead_token,str(from_date),str(to_date))
            
            lead_data = {
            'token':lead_api_settings.lead_token,#67560806,77873725
            'fromdate':str(from_date),#'2012-03-03',
            'todate':str(to_date),#'2013-11-09',
            'countriesiso':'DE',
            }
                
            lead_encoded_data = urllib.urlencode(lead_data)
            lead_gen_result = urllib2.Request('http://openapi.leadenhancer.com/v1/leadopenapi/visits?%s'%(lead_encoded_data))
            lead_api_response = urllib2.urlopen(lead_gen_result)
            generate_lead_result = json.loads(lead_api_response.read())
            
            #GA Report encoded data creation
            data = {
                'ids':'ga:'+str(api_settings.ga_profile_id),#67560806,77873725
                'start-date':from_date,#'2012-03-03'
                'end-date':to_date,#'2013-11-09',
                'metrics':'ga:visits',
                'dimensions':'ga:pageTitle',
                'alt':'json'
                }
                        
            encoded_data = urllib.urlencode(data)
            
            try :
                if datetime.now() :
                    api_response = urlfetch.fetch(url= 'https://www.googleapis.com/analytics/v3/data/ga?%s'%(encoded_data),
                    method=urlfetch.GET,
                    headers={'Content-Type': 'application/x-www-form-urlencoded','Authorization':'Bearer %s' % api_settings.access_token})
                    
                    ga_result = json.loads(api_response.content)
                    url_list = []
                    for j in ga_result['rows']:
                        url_list.append(j[0])
                    
                    update_list = []
                    for i in generate_lead_result:
                        update_dict = lead_parse_dict_creation(i)
                        update_list.append(update_dict)
                    
                    update_list = sorted(update_list, key=lambda l: l['page'])
                    
                    dict_list = []
                    graph_result = []
                    for updated_item in update_list:
                        visitscore = ''
                        ga_visits = ''
                        report_details = []
                        #URL List contains the lead enhancer result urls
                        for url_item in url_list:                     
   			    #Check page title is url or page title
                            if len(page_list) > 1:
                                if updated_item['page'] == url_item and updated_item['url'] == page_title:
                                    report_details = parse_report_details(updated_item)
                            
                            elif page_title and len(page_list) == 1:
                                if updated_item['page'] == url_item and updated_item['page'] == page_title:
                                    report_details = parse_report_details(updated_item)
                            else:
                                if updated_item['page'] == url_item:
                                    report_details = parse_report_details(updated_item)
                        
                        if report_details:
                            for ga_visit_count in ga_result['rows']:
                                if ga_visit_count[0] == updated_item['page']:
                                    ga_visits = ga_visit_count[1]
                                    
                            if report_details[6] and ga_visits:
                                graph_result.append([int(report_details[6]), int(ga_visits)])
                                #Report display in template - google analytics visits in 7th position
                                report_details.insert(7, ga_visits)
                                dict_list.append(report_details)
                
            except Exception as e:
                logging.info(str(e))
                ga_result = ''
                graph_data = ''
                graph_result = ''
                dict_list = ''
                pass
            return render(request, 'reports.html', {'ga_result':ga_result,'graph_result':graph_result,'dict_list':dict_list,'from_date':from_date,'to_date':to_date,'lead_api_settings':lead_api_settings, 'page_title':page_title})
        
        elif 'filters' in request.POST:
            #Get the session values and pass the data to template
            select_filter = 'Select'
            try:
                from_date = request.session['from_date']
                to_date = request.session['to_date']
                page_title = request.session['page_title']
            except Exception as e:
                page_title = ''
                pass
            
            select_filter = request.POST['select_filter']
            
            url = 'http://openapi.leadenhancer.com/v1/leadopenapi/visits?token=%s&fromdate=%s&todate=%s&countriesiso=DE'% (lead_api_settings.lead_token,from_date,to_date)

            #Using Page title and generate the report while filtering
            if page_title:
                page_list = page_title.split('https://')
            
                if len(page_list) == 1:
                    page_list = page_title.split('http://')
            else:
                page_list = []
            
            result = urlfetch.fetch(url)
            
            #Google Analytics Data
            data = {
                'ids':'ga:'+str(api_settings.ga_profile_id),#67560806,77873725
                'start-date':from_date,#'2012-03-03',str(from_date),
                'end-date':to_date,#str(to_date),#'2013-11-09',
                'metrics':'ga:visits',
                'dimensions':'ga:pageTitle',#'ga:pagePath',
                'alt':'json'
                }
            
            encoded_data = urllib.urlencode(data)
            try :
                if datetime.now() > api_settings.updated:
                    api_response = urlfetch.fetch(url= 'https://www.googleapis.com/analytics/v3/data/ga?%s'%(encoded_data),
                    method=urlfetch.GET,
                    headers={'Content-Type': 'application/x-www-form-urlencoded','Authorization':'Bearer %s' % api_settings.access_token})
        
                    ga_result = json.loads(api_response.content)
                    lead_result = json.loads(result.content)
                    
                    url_list = []
                    for j in ga_result['rows']:
                        url_list.append(j[0])
                    
                    ### Parsing the lead list using filter values ###
                    update_list = lead_list_parsing(lead_result, select_filter, request.POST['filter_val'].strip(' '))
                    
                    update_list = sorted(update_list, key=lambda l: l['page'])
                            
                    dict_list = []
                    graph_result = []
                    for new_item in update_list:
                        visitscore = ''
                        ga_visits = ''
                        report_details = []
                        for ga_url in url_list:                         
   			    #Check page title is url or page title
                            if len(page_list) > 1:
                                if new_item['page'] == ga_url and new_item['url'] == page_title:
                                    report_details = parse_report_details(new_item)
                            
                            elif page_title and len(page_list) == 1:
                                if new_item['page'] == ga_url and new_item['page'] == page_title:
                                    report_details = parse_report_details(new_item)
                            else:
                                if new_item['page'] == ga_url:
                                    report_details = parse_report_details(new_item)
                        
                        if report_details:
                            for ga_res in ga_result['rows']:
                                if ga_res[0] == new_item['page']:
                                    ga_visits = ga_res[1]
                            
                            if report_details[6] and ga_visits:
                                graph_result.append([int(report_details[6]), int(ga_visits)])
                                #Report display in template - google analytics visits in 7th position
                                report_details.insert(7, ga_visits)
                                dict_list.append(report_details)
            
            except Exception as e:
                logging.info(str(e))
                logging.info(str("Exception in Filter"))
                ga_result = ''
                graph_result = ''
                dict_list = ''
                pass
            
            return render(request, 'reports.html', {'ga_result':ga_result,'graph_result':graph_result,'dict_list':dict_list,'lead_api_settings':lead_api_settings, 'from_date':from_date, 'to_date':to_date, 'page_title':page_title, 'select_filter':select_filter, 'name_val':request.POST['filter_val'].strip(' ')})
        
    ga_response = ''
    from_date_range = date.today() - timedelta(days=30)
    to_date_range = date.today()
    from_date = str(from_date_range.year)+'-'+str(from_date_range.month)+'-'+str(from_date_range.day)
    to_date = str(to_date_range.year)+'-'+str(to_date_range.month)+'-'+str(to_date_range.day)
    url = 'http://openapi.leadenhancer.com/v1/leadopenapi/visits?token=%s&fromdate=%s&todate=%s&countriesiso=DE'% (lead_api_settings.lead_token,from_date,to_date)
    try:
        result = urlfetch.fetch(url)
    except:
        message = 'API Connection Exceeds'
        return render(request, 'message.html', {'message':message})
    
    try:
        try:
            if api_settings.expires == 3600:
                expire_in = api_settings.updated + timedelta(seconds=int(3000))
            else:
                expire_in = api_settings.updated + timedelta(seconds=int(api_settings.expires))
                
        except Exception as e:
            logging.info(str(e))
            expire_in = api_settings.updated + timedelta(seconds=int(3000))

        if datetime.now() > expire_in or datetime.now() < api_settings.updated:
            ### Access Token Expired ###
            ### Get a new access token using refresh token ###
            ga_response = oauth2callback_using_refresh_token(request)
        else:
            pass
    except Exception as e:
        logging.info(str(e))
        logging.info(str("Exception in Oauth token expired"))
        pass
    
    #GA Report
    data = {
        'ids':'ga:'+str(api_settings.ga_profile_id),#67560806,77873725
        'start-date':from_date,#'2012-03-03',
        'end-date':to_date,#'2013-11-09',
        'metrics':'ga:visits',
        'dimensions':'ga:pageTitle',#'ga:pagePath',
        'alt':'json'
        }
                
    encoded_data = urllib.urlencode(data)
    try :
        if datetime.now() < expire_in or datetime.now() > api_settings.updated:
            api_response = urlfetch.fetch(url= 'https://www.googleapis.com/analytics/v3/data/ga?%s'%(encoded_data),
            method=urlfetch.GET,
            headers={'Content-Type': 'application/x-www-form-urlencoded','Authorization':'Bearer %s' % api_settings.access_token})

            ga_result = json.loads(api_response.content)
            lead_result = json.loads(result.content)
            graph_data = zip([lead_result],[ga_result])
            url_list = []
            for j in ga_result['rows']:
                url_list.append(j[0])
                
            update_list = []
            for i in lead_result:
                update_dict = lead_parse_dict_creation(i)
                update_list.append(update_dict)
            
            update_list = sorted(update_list, key=lambda l: l['page']) 
                    
            dict_list = []
            graph_result = []
            for update_item in update_list:
                visitscore = ''
                ga_visits = ''
                report_details = []
                for url_name in url_list:
                    if update_item['page'] == url_name:
                        report_details = parse_report_details(update_item)
                
                if report_details:
                    for g in ga_result['rows']:
                        if g[0] == update_item['page']:
                            ga_visits = g[1]
                    
                    if report_details[6] and ga_visits:
                        graph_result.append([int(report_details[6]), int(ga_visits)])
                        #Report display in template - google analytics visits in 7th position
                        report_details.insert(7, ga_visits)
                        dict_list.append(report_details)
                    
    except Exception as e:
        logging.info(str(e))
        ga_result = ''
        graph_data = ''
        graph_result = ''
        dict_list = ''
        pass
        
    try:
        #Clear the Session for from_date and to_date 
        del(request.session['from_date'])
        del(request.session['to_date'])
        del(request.session['page_title'])
    except:
        pass
    
    return render(request, 'reports.html', {'response_details':json.loads(result.content),'ga_result':ga_result,'graph_data':graph_data,'graph_result':graph_result,'dict_list':dict_list,'lead_api_settings':lead_api_settings, 'from_date':from_date, 'to_date':to_date})
    
    
def customize_reports(request):
    user = request.user
    response = {}
    if request.is_ajax():
        try:
            report_fields = LeadApi_Settings.objects.get(user=user)
            if 'page_title' in request.POST:
                report_fields.page_title = True
            else:
                report_fields.page_title = False
            if 'page_url' in request.POST:    
                report_fields.page_url = True
            else:
                report_fields.page_url = False
            if 'revenue' in request.POST:    
                report_fields.revenue = True
            else:
                report_fields.revenue = False
            if 'no_emp' in request.POST:    
                report_fields.no_of_employees = True
            else:
                report_fields.no_of_employees = False
            if 'city' in request.POST:    
                report_fields.city = True
            else:
                report_fields.city = False
            if 'region' in request.POST:    
                report_fields.region = True
            else:
                report_fields.region = False
            if 'country' in request.POST:    
                report_fields.country = True
            else:
                report_fields.country = False
            if 'continent' in request.POST:    
                report_fields.continent = True
            else:
                report_fields.continent = False
            if 'address' in request.POST:    
                report_fields.address = True
            else:
                report_fields.address = False
            report_fields.save()
            response['success'] = True
        except:
            response['success'] = False
    
    return HttpResponse(json.dumps(response),mimetype="application/json")


def about_us(request):
    about_us = config_value('leadappsettings','about_us')
    return render(request, 'aboutus.html', {'about_us':about_us})


def help(request):
    how_to = config_value('leadappsettings','how_to')
    return render(request, 'howto.html', {'how_to':how_to})


def lead_list_parsing(lead_result, select_filter, value):
    '''
    Lead List Parsing
    '''
    update_list = []
    try:
       
        key_dict = {}
        if select_filter == 'Organisation name':
            key_dict['arg_name'] = "['organisation']['name']"
        elif select_filter == 'SIC':
            key_dict['arg_name'] = "['organisation']['sicprimarycode']"
        elif select_filter == 'Revenue':
            key_dict['arg_name'] = "['organisation']['sales']"
        elif select_filter == 'Location':
            key_dict['arg_name'] = "['organisation']['address']['city']"
        elif select_filter == 'No. of Employees':
            key_dict['arg_name'] = "['organisation']['noofemployees']"
        else:
            key_dict['arg_name'] = ''
    
        for i in lead_result:
            try:
                key_arg = eval("%s%s"%(i,key_dict['arg_name']))
                
                if key_dict['arg_name'] == "['organisation']['noofemployees']" or key_dict['arg_name'] == "['organisation']['sales']" :
                    key_arg = str(key_arg)
                
                if key_arg == value:
                    update_dict = lead_parse_dict_creation(i)
                    update_list.append(update_dict)
            except:
                pass
        return update_list
    
    except Exception as e:
        logging.info("Exception in - lead_list_parsing")
        logging.info(str(e))
        return update_list


def lead_parse_dict_creation(i):
    '''
    Parse the lead list and update the dictionary.
    '''
    update_dict = {}
    try:
        update_dict['visitscore'] = i['visitscore']
    except:
        update_dict['visitscore'] = 0
    try:
        update_dict['sic'] = i['organisation']['sicprimarycode']
    except:
        update_dict['sic'] = 0
    try:
        update_dict['org_name'] = i['organisation']['name']
    except:
        update_dict['org_name'] = ''
    try:
        update_dict['org_sales'] = i['organisation']['sales']
    except:
        update_dict['org_sales'] = 0
    try:
        update_dict['city'] = i['organisation']['city']
    except:
        update_dict['city'] = ''
    try:
        update_dict['countryname'] = i['organisation']['address']['countryname']
    except:
        update_dict['countryname'] = ''
    try:
        update_dict['continent'] = i['organisation']['address']['continent']
    except:
        update_dict['continent'] = ''
    try:
        update_dict['region'] = i['organisation']['address']['region']
    except:
        update_dict['region'] = ''
    try:
        update_dict['address'] = i['organisation']['address']['address']
    except:
        update_dict['address'] = ''
    try:
        update_dict['no_of_employees'] = i['organisation']['noofemployees']
    except:
        update_dict['no_of_employees'] = ''     
        
    for j in i['pageviews']:
        update_dict['url'] = j['url']
        update_dict['page'] = j['page']
    
    return update_dict


def parse_report_details(updated_item):
    '''
    Parse the report details
    '''
    page = updated_item['page']
    url = updated_item['url']
    sic = updated_item['sic']
    org_name = updated_item['org_name']
    org_sales = updated_item['org_sales']
    city = updated_item['city']
    visitscore = updated_item['visitscore']
    countryname = updated_item['countryname']
    continent = updated_item['continent']
    region = updated_item['region']
    address = updated_item['address']
    no_of_employees = updated_item['no_of_employees']
    
    return [page, url, sic, org_name, org_sales, city,visitscore, countryname, continent, region,address, no_of_employees]
