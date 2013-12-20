from django.conf.urls.defaults import patterns, include, url,  handler404, handler500

from django.contrib.auth.forms import AuthenticationForm

from django.conf import settings
# Uncomment the next two lines to enable the admin:
from django.contrib import admin
admin.autodiscover()

handler500 = 'djangotoolbox.errorviews.server_error'

urlpatterns = patterns('lead_app.views',
    # Examples:
    url(r'^$', 'home', name='home'),
    url(r'login/$', 'login', name='login'),
    url(r'logout/$', 'logout', name='logout'),
    url(r'view-report/$', 'view_reports', name='view_reports'),
    url(r'customize-report/$', 'customize_reports', name='customize_reports'),
    url(r'help/$', 'help', name='help'),
    url(r'about-us/$', 'about_us', name='about_us'),
    url(r'^oauth2callback/$', 'oauth2callback', name='oauth2callback'),
    # url(r'^$', 'lead_enhancer.views.home', name='home'),
    # url(r'^lead_enhancer/', include('lead_enhancer.foo.urls')),

    # Uncomment the admin/doc line below to enable admin documentation:
    # url(r'^admin/doc/', include('django.contrib.admindocs.urls')),

    # Uncomment the next line to enable the admin:
    url(r'^admin/', include(admin.site.urls)),
    url(r'^settings/', include('livesettings.urls')),
)

urlpatterns += patterns('',
        url(r'^static/(?P<path>.*)$', 'django.views.static.serve', {
            'document_root': settings.STATIC_ROOT,'show_indexes': True,
        })
)