from five import grok

from z3c.form import group, field
from zope import schema
from zope.interface import invariant, Invalid
from zope.schema.interfaces import IContextSourceBinder
from zope.schema.vocabulary import SimpleVocabulary, SimpleTerm

from plone.dexterity.content import Container
from plone.directives import dexterity, form
from plone.app.textfield import RichText
from plone.namedfile.field import NamedImage, NamedFile
from plone.namedfile.field import NamedBlobImage, NamedBlobFile
from plone.namedfile.interfaces import IImageScaleTraversable

from z3c.relationfield.schema import RelationList, RelationChoice
from plone.formwidget.contenttree import ObjPathSourceBinder


from mingtak.oauthlogin import MessageFactory as _


# Interface class; used to define content-type schema.

allowWebsite = SimpleVocabulary(
    [SimpleTerm(value=u'facebook', title=_(u'facebook')),
     SimpleTerm(value=u'google', title=_(u'google')),]
)
"""
     SimpleTerm(value=u'linkedin', title=_(u'linkedin')),
     SimpleTerm(value=u'twitter', title=_(u'twitter'))]
)
"""


class IOauth2Setting(form.Schema, IImageScaleTraversable):
    """
    Oauth2 login method
    """
    allowList = schema.List(
        title=_(u"Allow List"),
        description=_(u"Allow list that select website to login."),
        value_type=schema.Choice(
                       title=_(u"Allow website"),
                       vocabulary=allowWebsite,
                       required=False,
                   ),
        required=False,
    )

    facebookAppId = schema.TextLine(
        title=_(u"Facebook app id"),
        required=False,
    )

    facebookAppSecret = schema.TextLine(
        title=_(u"Facebook app secret"),
        required=False,
    )

    facebookScope = schema.TextLine(
        title=_(u"Facebook auth scope"),
        required=False,
    )

    facebookRedirectUri = schema.URI(
        title=_(u"Facebook redirect URL"),
        required=False,
    )

    googleAppId = schema.TextLine(
        title=_(u"Google app id"),
        required=False,
    )

    googleAppSecret = schema.TextLine(
        title=_(u"Google app secret"),
        required=False,
    )

    googleScope = schema.TextLine(
        title=_(u"Google auth scope"),
        required=False,
    )

    googleRedirectUri = schema.URI(
        title=_(u"Google redirect URL"),
        required=False,
    )


class Oauth2Login(Container):
    grok.implements(IOauth2Setting)


class SampleView(grok.View):
    """ sample view class """

    grok.context(IOauth2Setting)
    grok.require('zope2.View')
    grok.name('view')
