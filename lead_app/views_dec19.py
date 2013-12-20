from django.shortcuts import render_to_response,render, get_object_or_404,redirect
from django.conf import settings
from django.http import HttpResponseRedirect, HttpResponse
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.contrib.auth import login as auth_login, authenticate,logout as auth_logout
#from django.views.decorators.csrf import csrf_protect
from django.views.decorators.csrf import csrf_exempt
import logging
from lead_app.models import Api_Settings,LeadApi_Settings
import json
#import datetime
from datetime import date,timedelta,datetime

import urllib
import urllib2
from urllib import urlencode
from django.utils.encoding import smart_str, smart_unicode
from google.appengine.api import urlfetch
from livesettings import config_value

#####################################
#     OAuth Credentials             #
#####################################

### Localhost ###
redirect_uri = 'http://localhost/oauth2callback'
client_id    = '913800940021-ec908ltute57hf1msk8r70d149nf99q7.apps.googleusercontent.com'
secret       = 'S2ujv9LCGRfBz1NgJf5AKEWd'

###  Live  ####
#redirect_uri = 'http://dev-openapi-lead.appspot.com/oauth2callback'#'http://leadopenapi.appspot.com/oauth2callback'
#client_id = '519472029765.apps.googleusercontent.com'#'26274428914-haed3qqmctlpf44udsjrfm3e3etl3uc7.apps.googleusercontent.com'
#secret = 'H62EaYsvH__jC4oCC_1ezHv2'#'362m0RcIWCaV4aBZlauErP4E'

@login_required(login_url='/login/')
def home(request):
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
    
    logging.info(usr_obj.id)
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
    user = request.user
    
    #from httplib2 import Http
    from urllib import urlencode
    import urllib2
    import json
    
    if request.GET:
        if request.GET['code']:
            code = request.GET['code']
            url = 'https://accounts.google.com/o/oauth2/token'
            
            data = dict(code=str(code), client_id=client_id, client_secret=secret, redirect_uri=redirect_uri, grant_type='authorization_code')
            
            response = urllib2.urlopen(url, urlencode(data))
            #logging.info(response)
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
        
        #del(request.session['analytics_id']) 
        
    return HttpResponseRedirect('/')
    #return render(request, 'configure.html', {'msg':'Your GA Profile ID has been configured',})



def oauth2callback_using_refresh_token(request, **kwargs):
    try:
        user = request.user
        api_settings = Api_Settings.objects.get(user=user)
        refresh_token = api_settings.refresh_token
        
        url = 'https://accounts.google.com/o/oauth2/token'
        
        data = dict(refresh_token=refresh_token, client_id=client_id, client_secret=secret, grant_type='refresh_token')
        
        response = urllib2.urlopen(url, urlencode(data))
        #print response, "URLIB2 RESPONSE Using Refresh Token"
        response_details = json.loads(response.read())
        
        api_settings.access_token = response_details['access_token']
        api_settings.expires = response_details['expires_in']
        #api_settings.response = response_details
        api_settings.save()
        logging.info("Token Refreshed")
        refreshed = True
        #return HttpResponse("New Token Created Successfully")
        return refreshed
    except Exception as e:
        logging.info(str(e))
        return HttpResponse("New Token Creation Error %s"%(str(e)))


def login(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        user = authenticate(username=username, password=password)
        if user is not None:
            if user.is_active:
                auth_login(request, user)
                return redirect('home')
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
    user = request.user
    try:
        api_settings = Api_Settings.objects.get(user=user)
        lead_api_settings = LeadApi_Settings.objects.get(user=user)
    except:
        return HttpResponseRedirect('/')
    
    #logging.info(lead_api_settings.lead_token)
    if api_settings.ga_profile_id == None or lead_api_settings.lead_token == None :
        return HttpResponseRedirect('/')
    
    #api_req = urllib2.urlopen('http://openapi.leadenhancer.com/v1/leadopenapi/visits?token=%s' % (lead_api_settings.lead_token))
    #response_details = json.dumps(api_req.read())

    try:
        from_date_range = date.today() - timedelta(days=30)
        to_date_range = date.today()
        from_date = str(from_date_range.year)+'-'+str(from_date_range.month)+'-'+str(from_date_range.day)
        to_date = str(to_date_range.year)+'-'+str(to_date_range.month)+'-'+str(to_date_range.day)
    except Exception as e:
        print str(e), "------------------- EXCEPTION IN DATE TIME -------------------------"
        from_date = '2013-11-09'
        to_date = '2013-12-09'

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
                #Session create for from_date and to_date
                request.session['from_date'] = from_date
                request.session['to_date'] = to_date
                request.session['page_title'] = page_title
            except:
                pass
            
            
            ## Page URL Report Generation ##
            
            #Check page title input is url or page title
            #By Muthuvel
            page_list = page_title.split('https://')

            if len(page_list) == 1:
                page_list = page_title.split('http://')
            
            
            if len(page_list) == 1:
                generate_url = 'http://openapi.leadenhancer.com/v1/leadopenapi/visits?token=%s&fromdate=%s&todate=%s&countriesiso=DE&pagenames=%s'% (lead_api_settings.lead_token,str(from_date),str(to_date),str(page_title))
                logging.info(generate_url)
                lead_data = {
                'token':lead_api_settings.lead_token,#67560806,77873725
                'fromdate':str(from_date),#'2012-03-03',str(from_date),
                'todate':str(to_date),#str(to_date),#'2013-11-09',
                'countriesiso':'DE',
                'pagenames':page_title,#'ga:pagePath',
                }
                
            else:
                generate_url = 'http://openapi.leadenhancer.com/v1/leadopenapi/visits?token=%s&fromdate=%s&todate=%s&countriesiso=DE'% (lead_api_settings.lead_token,str(from_date),str(to_date))
                logging.info(generate_url)
                lead_data = {
                'token':lead_api_settings.lead_token,#67560806,77873725
                'fromdate':str(from_date),#'2012-03-03',str(from_date),
                'todate':str(to_date),#str(to_date),#'2013-11-09',
                'countriesiso':'DE',
                #'pagenames':page_title,#'ga:pagePath',
                }
            
            '''
            generate_url = 'http://openapi.leadenhancer.com/v1/leadopenapi/visits?token=%s&fromdate=%s&todate=%s&countriesiso=DE&pagenames=%s'% (lead_api_settings.lead_token,str(from_date),str(to_date),str(page_title))
            logging.info(generate_url)
            lead_data = {
            'token':lead_api_settings.lead_token,#67560806,77873725
            'fromdate':str(from_date),#'2012-03-03',str(from_date),
            'todate':str(to_date),#str(to_date),#'2013-11-09',
            'countriesiso':'DE',
            'pagenames':page_title,#'ga:pagePath',
                }
            '''
            
            lead_encoded_data = urllib.urlencode(lead_data)
            lead_gen_result = urllib2.Request('http://openapi.leadenhancer.com/v1/leadopenapi/visits?%s'%(lead_encoded_data))
            lead_api_response = urllib2.urlopen(lead_gen_result)
            #logging.info(api_response)
            generate_lead_result = json.loads(lead_api_response.read())
            
            
            #GA Report
            data = {
                'ids':'ga:'+str(api_settings.ga_profile_id),#67560806,77873725
                'start-date':from_date,#'2012-03-03',str(from_date),
                'end-date':to_date,#str(to_date),#'2013-11-09',
                'metrics':'ga:visits',
                'dimensions':'ga:pageTitle',#'ga:pagePath',
                #'sort':sort,#'-ga:pageviews',
                #'max-results':5,
                'alt':'json'
                    }
                        
            encoded_data = urllib.urlencode(data)
            #logging.info(encoded_data)
            #request = urllib2.Request('https://www.googleapis.com/analytics/v3/data/ga?sort=-ga%3Avisits&max-results=5&dimensions=ga%3AsocialNetwork&start-date=2012-11-13&ids=ga%3A66641849&metrics=ga%3Avisits%2C+ga%3Apageviews%2C+ga%3AuniquePageviews%2C+ga%3AvisitBounceRate%2C+ga%3ApageviewsPerVisit&alt=json&end-date=2013-11-13')
            #logging.info(ga_response)
            #total_list = []
            try :
                if datetime.now() :
                    #logging.info("helllloooooooo")
                    #anayl_request = urllib2.Request('https://www.googleapis.com/analytics/v3/data/ga?%s'%(encoded_data))
                    #anayl_request.add_header('Authorization', 'Bearer %s' % api_settings.access_token)
                    #
                    #api_response = urllib2.urlopen(anayl_request)
                    #logging.info(api_response)
                    api_response = urlfetch.fetch(url= 'https://www.googleapis.com/analytics/v3/data/ga?%s'%(encoded_data),
                    method=urlfetch.GET,
                    headers={'Content-Type': 'application/x-www-form-urlencoded','Authorization':'Bearer %s' % api_settings.access_token})
                    
                    ga_result = json.loads(api_response.content)
                    #logging.info(ga_result)
                    url_list = []
                    for j in ga_result['rows']:
                        url_list.append(j[0])
                        
                    #url_list = []
                    #for j in lead_result:
                    #    for k in j['pageviews']:
                    #        url_list.append(k['page'])    
                        
                    #graph_result = [['date', 'LeadEnhancer', 'Google Analytics']]
                    """startttttttttttttttttttts"""
                    
                    update_list = []
                    for i in generate_lead_result:
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
                        update_list.append(update_dict)
                    
                    update_list = sorted(update_list, key=lambda l: l['page']) 
        
                            
                    dict_list = []
                    graph_result = []
                    for k in update_list:
                        visitscore = ''
                        ga_visits = ''
                        #for j in url_list:
                        #    if k['page'] == j:
                        #        page = k['page']
                        #        url = k['url']
                        #        sic = k['sic']
                        #        org_name = k['org_name']
                        #        org_sales = k['org_sales']
                        #        city = k['city']
                        #        visitscore = k['visitscore']
                        #        countryname = k['countryname']
                        #        continent = k['continent']
                        #        region = k['region']
                        #        address = k['address']
                        #        no_of_employees = k['no_of_employees']
                        
                        for j in url_list:                         
   			    #Check page title is url or page title
                            #By Muthuvel
                            if len(page_list) > 1:
                                if k['page'] == j and k['url'] == page_title:
                                    page = k['page']
                                    url = k['url']
                                    sic = k['sic']
                                    org_name = k['org_name']
                                    org_sales = k['org_sales']
                                    city = k['city']
                                    visitscore = k['visitscore']
                                    countryname = k['countryname']
                                    continent = k['continent']
                                    region = k['region']
                                    address = k['address']
                                    no_of_employees = k['no_of_employees']
                            else:
                                if k['page'] == j:
                                    page = k['page']
                                    url = k['url']
                                    sic = k['sic']
                                    org_name = k['org_name']
                                    org_sales = k['org_sales']
                                    city = k['city']
                                    visitscore = k['visitscore']
                                    countryname = k['countryname']
                                    continent = k['continent']
                                    region = k['region']
                                    address = k['address']
                                    no_of_employees = k['no_of_employees']
                        
                        for g in ga_result['rows']:
                            if g[0] == k['page']:
                                ga_visits = g[1]
                                
                        if visitscore and ga_visits:
                            graph_result.append([int(visitscore), int(ga_visits)])
                            dict_list.append([page,url,sic,org_name,org_sales,city,visitscore,ga_visits,countryname,continent,region,address,no_of_employees])
        
                    """endsssssssssssss"""     
                    
            except Exception as e:
                logging.info(str(e))
                ga_result = ''
                graph_data = ''
                graph_result = ''
                dict_list = ''
                pass
            return render(request, 'reports.html', {'ga_result':ga_result,'graph_result':graph_result,'dict_list':dict_list,'from_date':from_date,'to_date':to_date,'lead_api_settings':lead_api_settings})
        
        elif 'filters' in request.POST:
            #Get the session values
            try:
                from_date = request.session['from_date']
                to_date = request.session['to_date']
                page_title = request.session['page_title']
            except Exception as e:
                pass
            
            select_filter = request.POST['select_filter']
            logging.info(select_filter)
            if select_filter == 'Organisation name':
                org_name = request.POST['filter_val']
                url = 'http://openapi.leadenhancer.com/v1/leadopenapi/visits?token=%s&fromdate=%s&todate=%s&orgname=%s'% (lead_api_settings.lead_token,from_date,to_date,str(org_name).replace(" ","%20"))
                logging.info(url)
                result = urlfetch.fetch(url)
                
                
            elif select_filter == 'SIC':
                sic_code = request.POST['filter_val']
                url = 'http://openapi.leadenhancer.com/v1/leadopenapi/visits?token=%s&fromdate=%s&todate=%s&countriesiso=DE'% (lead_api_settings.lead_token,from_date,to_date)
                result = urlfetch.fetch(url)
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
                        
                        """startttttttttttttttttttts"""
                        
                        update_list = []
                        for i in lead_result:
                            if i['organisation']['sicprimarycode'] == sic_code :
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
                                update_list.append(update_dict)
                        
                        update_list = sorted(update_list, key=lambda l: l['page']) 
                        logging.info(update_list)    
                                
                        dict_list = []
                        graph_result = []
                        for k in update_list:
                            visitscore = ''
                            ga_visits = ''
                            for j in url_list:
                                if k['page'] == j:
                                    logging.info('ggggggggggggggggggggggg')
                                    page = k['page']
                                    url = k['url']
                                    sic = k['sic']
                                    org_name = k['org_name']
                                    org_sales = k['org_sales']
                                    city = k['city']
                                    visitscore = k['visitscore']
                                    countryname = k['countryname']
                                    continent = k['continent']
                                    region = k['region']
                                    address = k['address']
                                    no_of_employees = k['no_of_employees']
                            for g in ga_result['rows']:
                                if g[0] == k['page']:
                                    ga_visits = g[1]
                                    
                            if visitscore and ga_visits:
                                graph_result.append([int(visitscore), int(ga_visits)])
                                dict_list.append([page,url,sic,org_name,org_sales,city,visitscore,ga_visits,countryname,continent,region,address,no_of_employees])
            
                        """endsssssssssssss"""    
                            
                        #logging.info(update_list)
                except Exception as e:
                    logging.info(str(e))
                    logging.info(str("sicccccccccccccccccccccccccccccccccccc"))
                    ga_result = ''
                    graph_result = ''
                    dict_list = ''
                    pass
                
                return render(request, 'reports.html', {'ga_result':ga_result,'graph_result':graph_result,'dict_list':dict_list,'lead_api_settings':lead_api_settings})
                
                
                
                
            elif select_filter == 'Revenue':
                revenue = request.POST['filter_val']
                url = 'http://openapi.leadenhancer.com/v1/leadopenapi/visits?token=%s&fromdate=%s&todate=%s&countriesiso=DE%'% (lead_api_settings.lead_token,from_date,to_date)
                result = urlfetch.fetch(url)
                
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
                        
                        """startttttttttttttttttttts"""
                        
                        update_list = []
                        for i in lead_result:
                            if i['organisation']['sales'] == revenue :
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
                                update_list.append(update_dict)
                        
                        update_list = sorted(update_list, key=lambda l: l['page']) 
                        logging.info(update_list)    
                                
                        dict_list = []
                        graph_result = []
                        for k in update_list:
                            visitscore = ''
                            ga_visits = ''
                            for j in url_list:
                                if k['page'] == j:
                                    logging.info('ggggggggggggggggggggggg')
                                    page = k['page']
                                    url = k['url']
                                    sic = k['sic']
                                    org_name = k['org_name']
                                    org_sales = k['org_sales']
                                    city = k['city']
                                    visitscore = k['visitscore']
                                    countryname = k['countryname']
                                    continent = k['continent']
                                    region = k['region']
                                    address = k['address']
                                    no_of_employees = k['no_of_employees']
                            for g in ga_result['rows']:
                                if g[0] == k['page']:
                                    ga_visits = g[1]
                                    
                            if visitscore and ga_visits:
                                graph_result.append([int(visitscore), int(ga_visits)])
                                dict_list.append([page,url,sic,org_name,org_sales,city,visitscore,ga_visits,countryname,continent,region,address,no_of_employees])
            
                        """endsssssssssssss"""    
                            
                        #logging.info(update_list)
                except Exception as e:
                    logging.info(str(e))
                    logging.info(str("sicccccccccccccccccccccccccccccccccccc"))
                    ga_result = ''
                    graph_result = ''
                    dict_list = ''
                    pass
                
                return render(request, 'reports.html', {'ga_result':ga_result,'graph_result':graph_result,'dict_list':dict_list,'lead_api_settings':lead_api_settings})
                
                
           
            elif select_filter == 'Location':
                location = request.POST['filter_val']
                url = 'http://openapi.leadenhancer.com/v1/leadopenapi/visits?token=%s&fromdate=%s&todate=%s&countriesiso=%s'% (lead_api_settings.lead_token,from_date,to_date,location)
                result = urlfetch.fetch(url)
                pass
            elif select_filter == 'No of Employees':
                no_of_emp = request.POST['filter_val']
                url = 'http://openapi.leadenhancer.com/v1/leadopenapi/visits?token=%s&fromdate=%s&todate=%s&minnoemployees=%s'% (lead_api_settings.lead_token,from_date,to_date,no_of_emp)
                result = urlfetch.fetch(url)
                pass
            
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
                    
                    """startttttttttttttttttttts"""
                    
                    update_list = []
                    for i in lead_result:
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
                        update_list.append(update_dict)
                    
                    update_list = sorted(update_list, key=lambda l: l['page']) 
                    logging.info(update_list)    
                            
                    dict_list = []
                    graph_result = []
                    for k in update_list:
                        visitscore = ''
                        ga_visits = ''
                        
                        for j in url_list:
                            if k['page'] == j:
                                logging.info('ggggggggggggggggggggggg')
                                page = k['page']
                                url = k['url']
                                sic = k['sic']
                                org_name = k['org_name']
                                org_sales = k['org_sales']
                                city = k['city']
                                visitscore = k['visitscore']
                                countryname = k['countryname']
                                continent = k['continent']
                                region = k['region']
                                address = k['address']
                                no_of_employees = k['no_of_employees']
                                logging.info('filterrrrrrrrrrrrrrrrrrrrrr')
                                
                        for g in ga_result['rows']:
                            if g[0] == k['page']:
                                ga_visits = g[1]
                                
                        if visitscore and ga_visits:
                            graph_result.append([int(visitscore), int(ga_visits)])
                            dict_list.append([page,url,sic,org_name,org_sales,city,visitscore,ga_visits,countryname,continent,region,address,no_of_employees])
        
                    """endsssssssssssss"""    
                        
                    #logging.info(update_list)
            except Exception as e:
                logging.info(str(e))
                logging.info(str("gogoggoogogogogogoogogogo"))
                ga_result = ''
                graph_result = ''
                dict_list = ''
                pass
            
            return render(request, 'reports.html', {'ga_result':ga_result,'graph_result':graph_result,'dict_list':dict_list,'lead_api_settings':lead_api_settings})
        
    
    ga_response = ''
    from_date_range = date.today() - timedelta(days=30)
    to_date_range = date.today()
    from_date = str(from_date_range.year)+'-'+str(from_date_range.month)+'-'+str(from_date_range.day)
    to_date = str(to_date_range.year)+'-'+str(to_date_range.month)+'-'+str(to_date_range.day)
    #logging.info(lead_api_settings.lead_token)
    url = 'http://openapi.leadenhancer.com/v1/leadopenapi/visits?token=%s&fromdate=%s&todate=%s&countriesiso=DE'% (lead_api_settings.lead_token,from_date,to_date)
    #logging.info(url)
    result = urlfetch.fetch(url)
    #logging.info(result.content)
    try:
        #from datetime import datetime, timedelta
        try:
            if api_settings.expires == 3600:
                expire_in = api_settings.updated + timedelta(seconds=int(3000))
            else:
                expire_in = api_settings.updated + timedelta(seconds=int(api_settings.expires))
                
        except Exception as e:
            logging.info(str(e))
            logging.info(str("00000000"))
            expire_in = api_settings.updated + timedelta(seconds=int(3000))

        #logging.info(expire_in)
        #logging.info(datetime.now())
        #logging.info(api_settings.updated)
        if datetime.now() > expire_in or datetime.now() < api_settings.updated:
            ### Access Token Expired ###
            ### Get a new access token using refresh token ###
            ga_response = oauth2callback_using_refresh_token(request)
            #logging.info(ga_response['ga_response'])
            #logging.info("### Refreshing Access Token###")
        else:
            #ga_response = True
            #Access Token live
            #logging.info("### Access Token live #Access Token live ###")
            pass
    except Exception as e:
        logging.info(str(e))
        logging.info(str("1111111111111111"))
        pass
    
    #GA Report
    data = {
        'ids':'ga:'+str(api_settings.ga_profile_id),#67560806,77873725
        'start-date':from_date,#'2012-03-03',str(from_date),
        'end-date':to_date,#str(to_date),#'2013-11-09',
        'metrics':'ga:visits',
        'dimensions':'ga:pageTitle',#'ga:pagePath',
        #'sort':sort,#'-ga:pageviews',
        #'max-results':5,
        'alt':'json'
            }
                
    encoded_data = urllib.urlencode(data)
    #logging.info(encoded_data)
    #request = urllib2.Request('https://www.googleapis.com/analytics/v3/data/ga?sort=-ga%3Avisits&max-results=5&dimensions=ga%3AsocialNetwork&start-date=2012-11-13&ids=ga%3A66641849&metrics=ga%3Avisits%2C+ga%3Apageviews%2C+ga%3AuniquePageviews%2C+ga%3AvisitBounceRate%2C+ga%3ApageviewsPerVisit&alt=json&end-date=2013-11-13')
    #logging.info(ga_response)
    #total_list = []
    try :
        if datetime.now() < expire_in or datetime.now() > api_settings.updated:
            logging.info("helllloooooooo")
            #changerequest = urllib2.Request('https://www.googleapis.com/analytics/v3/data/ga?%s'%(encoded_data))
            #logging.info("hellll2222222222")
            #logging.info(str(changerequest))
            #logging.info(api_settings.access_token)
            #changerequest.add_header('Authorization', 'Bearer %s' % api_settings.access_token)
            #
            
            api_response = urlfetch.fetch(url= 'https://www.googleapis.com/analytics/v3/data/ga?%s'%(encoded_data),
            method=urlfetch.GET,
            headers={'Content-Type': 'application/x-www-form-urlencoded','Authorization':'Bearer %s' % api_settings.access_token})

            #api_response = urllib2.urlopen(changerequest)
            #logging.info(api_response)
            logging.info("apiiiiiiiiiiiii")
            ga_result = json.loads(api_response.content)
            #logging.info(ga_result)
            logging.info("gaggggggggggggggggg")
            lead_result = json.loads(result.content)
            graph_data = zip([lead_result],[ga_result])
            
            #logging.info(lead_result)
            #logging.info(ga_result)
            url_list = []
            for j in ga_result['rows']:
                url_list.append(j[0])
                
            #url_list = []
            #for j in lead_result:
            #    for k in j['pageviews']:
            #        url_list.append(k['page'])    
                
            #graph_result = [['date', 'LeadEnhancer', 'Google Analytics']]
            """startttttttttttttttttttts"""
            
            update_list = []
            for i in lead_result:
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
                update_list.append(update_dict)
            
            update_list = sorted(update_list, key=lambda l: l['page']) 
            logging.info(update_list)    
                    
            dict_list = []
            graph_result = []
            for k in update_list:
                visitscore = ''
                ga_visits = ''
                for j in url_list:
                    if k['page'] == j:
                        logging.info('fooooooooooooooooo')
                        page = k['page']
                        url = k['url']
                        sic = k['sic']
                        org_name = k['org_name']
                        org_sales = k['org_sales']
                        city = k['city']
                        visitscore = k['visitscore']
                        countryname = k['countryname']
                        continent = k['continent']
                        region = k['region']
                        address = k['address']
                        no_of_employees = k['no_of_employees']
                        logging.info('fooooooooooooooooo2222222222222')
                        
                for g in ga_result['rows']:
                    if g[0] == k['page']:
                        ga_visits = g[1]
                        
                if visitscore and ga_visits:
                    graph_result.append([int(visitscore), int(ga_visits)])
                    dict_list.append([page,url,sic,org_name,org_sales,city,visitscore,ga_visits,countryname,continent,region,address,no_of_employees])

            """endsssssssssssss"""    
                
            #logging.info(update_list)
    except Exception as e:
        logging.info(str(e))
        logging.info(str("2222222222222222222"))
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
    
    return render(request, 'reports.html', {'response_details':json.loads(result.content),'ga_result':ga_result,'graph_data':graph_data,'graph_result':graph_result,'dict_list':dict_list,'lead_api_settings':lead_api_settings})
    
    
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
