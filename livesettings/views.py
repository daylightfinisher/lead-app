from django.http import HttpResponseRedirect
from django.shortcuts import render_to_response
from django.template import RequestContext
from django.contrib.admin.views.decorators import staff_member_required
from django.views.decorators.cache import never_cache
from livesettings import ConfigurationSettings, forms
from livesettings.overrides import get_overrides
import logging

log = logging.getLogger('configuration.views')

def group_settings(request, group, template='livesettings/group_settings.html'):
    # Determine what set of settings this editor is used for
    try:
        message = request.session['message']
        del request.session['message']
    except:
        message = None
    use_db, overrides = get_overrides();
    
    mgr = ConfigurationSettings()
    if group is None:
        settings = mgr
        title = 'Site settings'
    else:
        settings = mgr[group]
        title = settings.name
        log.debug('title: %s', title)

    if use_db:
        # Create an editor customized for the current user
        #editor = forms.customized_editor(settings)

        if request.method == 'POST':
            # Populate the form with user-submitted data
            data = request.POST.copy()
            form = forms.SettingsEditor(data, settings=settings)
            if form.is_valid():
                form.full_clean()
                for name, value in form.cleaned_data.items():
                    group, key = name.split('__')
                    cfg = mgr.get_config(group, key)
                    if cfg.update(value):
                        request.session['message'] = 'Contents Has Been Updated'
                        pass
                        # Give user feedback as to which settings were changed
                        #request.user.message_set.create(message='Updated %s on %s' % (cfg.key, cfg.group.key))

                return HttpResponseRedirect(request.path)
        else:
            # Leave the form populated with current setting values
            #form = editor()
            form = forms.SettingsEditor(settings=settings)
    else:
        form = None
        
    return render_to_response(template, {
        'title': title,
        'group' : group,
        'form': form,
        'use_db' : use_db,
        'message':message,
    }, context_instance=RequestContext(request))
group_settings = never_cache(staff_member_required(group_settings))

# Site-wide setting editor is identical, but without a group
# staff_member_required is implied, since it calls group_settings
def site_settings(request):
    return group_settings(request, group=None, template='livesettings/site_settings.html')
    
def export_as_python(request):
    """Export site settings as a dictionary of dictionaries"""
    
    from livesettings.models import Setting, LongSetting
    import pprint
    
    work = {}
    both = list(Setting.objects.all())
    both.extend(list(LongSetting.objects.all()))
    
    for s in both:
        if not work.has_key(s.site.id):
            work[s.site.id] = {}
        sitesettings = work[s.site.id]
                    
        if not sitesettings.has_key(s.group):
            sitesettings[s.group] = {}
        sitegroup = sitesettings[s.group]
        
        sitegroup[s.key] = s.value
        
    pp = pprint.PrettyPrinter(indent=4)
    pretty = pp.pformat(work)

    return render_to_response('livesettings/text.txt', { 'text' : pretty }, mimetype='text/plain')
    
export_as_python = never_cache(staff_member_required(export_as_python))
