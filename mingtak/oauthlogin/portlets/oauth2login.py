from zope.interface import Interface
from zope.interface import implements

from plone.app.portlets.portlets import base
from plone.portlets.interfaces import IPortletDataProvider

from zope import schema
from zope.formlib import form
from Products.Five.browser.pagetemplatefile import ViewPageTemplateFile

from mingtak.oauthlogin import MessageFactory as _

#from zope.i18nmessageid import MessageFactory
#__ = MessageFactory("plone")


class IOAuth2Login(IPortletDataProvider):
    """
    OAuth 2 login method panel
    """


class Assignment(base.Assignment):
    implements(IOAuth2Login)

    @property
    def title(self):
        return _(u"OAuth 2 login method panel")


class Renderer(base.Renderer):
    render = ViewPageTemplateFile('oauth2login.pt')


class AddForm(base.AddForm):
    form_fields = form.Fields(IOAuth2Login)

    def create(self, data):
        return Assignment(**data)


class EditForm(base.EditForm):
    form_fields = form.Fields(IOAuth2Login)
