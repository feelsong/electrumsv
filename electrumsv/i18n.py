#!/usr/bin/env python
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2012 thomasv@gitorious
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
import gettext
from typing import Optional

from .util import resource_path

LOCALE_DIR = resource_path('locale')
language = gettext.translation('electrumsv', LOCALE_DIR, fallback = True)

def _(x: str) -> str:
    global language
    return language.gettext(x)

def set_language(x: Optional[str]) -> None:
    global language
    if x:
        language = gettext.translation('electrumsv', LOCALE_DIR, fallback=True, languages=[x])


languages = {
    '':_('Default'),
    'ar_SA':_('Arabic'),
    'cs_CZ':_('Czech'),
    'da_DK':_('Danish'),
    'de_DE':_('German'),
    'eo_UY':_('Esperanto'),
    'el_GR':_('Greek'),
    'en_UK':_('English'),
    'es_AR':_('Spanish (S. America)'),
    'es_ES':_('Spanish'),
    'fr_FR':_('French'),
    'hu_HU':_('Hungarian'),
    'hy_AM':_('Armenian'),
    'id_ID':_('Indonesian'),
    'it_IT':_('Italian'),
    'ja_JP':_('Japanese'),
    'ky_KG':_('Kyrgyz'),
    'lv_LV':_('Latvian'),
    'nl_NL':_('Dutch'),
    'no_NO':_('Norwegian'),
    'pl_PL':_('Polish'),
    'pt_BR':_('Brasilian'),
    'pt_PT':_('Portuguese'),
    'ro_RO':_('Romanian'),
    'ru_RU':_('Russian'),
    'sk_SK':_('Slovak'),
    'sl_SI':_('Slovenian'),
    'ta_IN':_('Tamil'),
    'th_TH':_('Thai'),
    'vi_VN':_('Vietnamese'),
    'zh_CN':_('Chinese')
    }
