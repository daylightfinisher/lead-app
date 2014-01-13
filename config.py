from livesettings import config_register, ConfigurationGroup, DecimalValue, \
        StringValue, PositiveIntegerValue, FloatValue, LongStringValue
from django.utils.translation import ugettext_lazy as _
from django.utils.translation import ugettext
from livesettings import *


# First, setup a group to hold all our possible configs
LEAD_GROUP = ConfigurationGroup(
    'leadappsettings',                        # key: internal name of the group to be created
    _('CMS Block'),                # name: verbose name which can be automatically translated
    ordering=0                          # ordering: order of group in the list (default is 1)
    )

#About Us 
config_register(LongStringValue(
    LEAD_GROUP,
    'about_us',
    description = _('about_us :'),
    default = """Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do eiusmod tempor
    incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation
    ullamco laboris nisi ut aliquip ex ea commodo consequat.
    Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur.
    Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id
    est laborum.
    <br />
    <br />
    Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do eiusmod tempor
    incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation
    ullamco laboris nisi ut aliquip ex ea commodo consequat.
    Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur.
    Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id
    est laborum.
    <br />
    <br />
    """,
    ordering=0 ))


#How It Works
config_register(LongStringValue(
    LEAD_GROUP,
    'how_to',
    description = _('how_to :'),
    default = """Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do eiusmod tempor
    incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation
    ullamco laboris nisi ut aliquip ex ea commodo consequat.
    Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur.
    Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id
    est laborum.
    <br />
    <br />
    Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do eiusmod tempor
    incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation
    ullamco laboris nisi ut aliquip ex ea commodo consequat.
    Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur.
    Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id
    est laborum.
    <br />
    <br />
    """,
    ordering=1 ))



#How It Works
config_register(LongStringValue(
    LEAD_GROUP,
    'copy_rights',
    description = _('copyrights :'),
    default = """ <p>Copyright 2013 Trend Micro Incorporated. All rights reserved</p>
    """,
    ordering= 2))


