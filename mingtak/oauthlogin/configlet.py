from plone.app.registry.browser.controlpanel import RegistryEditForm
from plone.app.registry.browser.controlpanel import ControlPanelFormWrapper

from oauth2login import IOauth2Setting
from plone.z3cform import layout
from z3c.form import form

class Oauth2LoginControlPanelForm(RegistryEditForm):
    form.extends(RegistryEditForm)
    schema = IOauth2Setting

Oauth2LoginControlPanelView = layout.wrap_form(Oauth2LoginControlPanelForm, ControlPanelFormWrapper)
Oauth2LoginControlPanelView.label = u"OAuth2 setting"
