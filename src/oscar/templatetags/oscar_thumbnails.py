import re

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.template import Library, Node, TemplateSyntaxError
from django.utils.encoding import smart_str
from django.utils.six import text_type

if 'easy_thumbnails' in settings.INSTALLED_APPS:
    from easy_thumbnails.files import get_thumbnailer as easy_thumbnails_thumbnailer
else:
    easy_thumbnails_thumbnailer = None

if 'sorl.thumbnail' in settings.INSTALLED_APPS:
    from sorl.thumbnail.shortcuts import get_thumbnail as sorl_get_thumbnail
else:
    sorl_get_thumbnail = None


register = Library()
kw_pat = re.compile(r'^(?P<key>[\w]+)=(?P<value>.+)$')


def get_sorl_thumbnail(file_, geometry, **options):
    return sorl_get_thumbnail(file_, geometry, **options)


def get_easy_thumbnails_thumbnail(file_, geometry, **options):
    options['size'] = geometry.split('x', 1)

    if len(options['size']) < 2:
        options['size'] = (options['size'], None)

    options['size'] = tuple(int(size) if size is not None and size != '' else 0 for size in options['size'])

    with open(file_.static_file_path, 'rb') as f:
        return easy_thumbnails_thumbnailer(f, file_.name).get_thumbnail(options)


def get_thumbnail_function():
    thumbnail_functions = {
        'sorl.thumbnail': get_sorl_thumbnail,
        'easy_thumbnails': get_easy_thumbnails_thumbnail,
    }

    try:
        thumbnail_function = thumbnail_functions[settings.OSCAR_THUMBNAILER]
    except KeyError:
        raise ImproperlyConfigured(
            "{} is not a valid choice for OSCAR_THUMBNAILER. Valid choices are {}".format(
                settings.OSCAR_THUMBNAILER, thumbnail_functions.keys()
            )
        )

    return thumbnail_function


class AgnosticThumbnail(Node):
    child_nodelists = ('nodelist_file', 'nodelist_empty')
    error_msg = ('Syntax error. Expected: ``thumbnail source geometry '
                 '[key1=val1 key2=val2...] as var``')

    def __init__(self, parser, token):
        """
        TODO:
            - options validation / translation
        """
        bits = token.split_contents()
        self.file_ = parser.compile_filter(bits[1])
        self.geometry = parser.compile_filter(bits[2])
        self.options = []
        self.as_var = None
        self.nodelist_file = None

        if bits[-2] == 'as':
            options_bits = bits[3:-2]
        else:
            options_bits = bits[3:]

        for bit in options_bits:
            m = kw_pat.match(bit)
            if not m:
                raise TemplateSyntaxError(self.error_msg)
            key = smart_str(m.group('key'))
            expr = parser.compile_filter(m.group('value'))
            self.options.append((key, expr))

        if bits[-2] == 'as':
            self.as_var = bits[-1]
            self.nodelist_file = parser.parse(('empty', 'endthumbnail',))
            if parser.next_token().contents == 'empty':
                self.nodelist_empty = parser.parse(('endthumbnail',))
                parser.delete_first_token()

    def render(self, context):
        file_ = self.file_.resolve(context)
        geometry = self.geometry.resolve(context)
        options = {}
        for key, expr in self.options:
            noresolve = {'True': True, 'False': False, 'None': None}
            value = noresolve.get(text_type(expr), expr.resolve(context))
            if key == 'options':
                options.update(value)
            else:
                options[key] = value

        thumbnail = get_thumbnail_function()(file_, geometry, **options)

        if not thumbnail:
            if self.nodelist_empty:
                return self.nodelist_empty.render(context)
            else:
                return ''

        if self.as_var:
            context.push()
            context[self.as_var] = thumbnail
            output = self.nodelist_file.render(context)
            context.pop()
        else:
            output = thumbnail.url

        return output

    def __repr__(self):
        return "<AgnosticThumbnailNode>"

    def __iter__(self):
        for node in self.nodelist_file:
            yield node
        for node in self.nodelist_empty:
            yield node


@register.tag
def thumbnail(parser, token):
    return AgnosticThumbnail(parser, token)
