"""
Tools for dealing with URIs within the Hypothesis API.

There are two main ways of considering the relationship between annotations and
annotated objects:

1. Annotations are, practically speaking, made on web pages, and thus they have
   a URL associated with them.

2. Annotations are made on documents, and the particular HTML or PDF page being
   annotated is merely a specific manifestation of the abstract document that
   is being annotated. In this scenario, a document may be identified by one or
   more URIs.

The second model is more complex from both a conceptual point of view and in
terms of implementation, but it offers substantial benefits. If we talk of
annotations attached to documents, without regard to presentation format or
location, we are able to do many interesting things:

- Alice makes an annotation on a PDF; Bob visits an HTML version of the same
  document, and sees Alice's annotation.
- Alice makes an annotation on an Instapaper-hosted version of a web page which
  contains a <link rel=canonical> tag. Bob visits the original article and sees
  Alice's annotation.
- Bob makes an annotation on a PDF which is on his local machine. Alice opens
  the same PDF on her machine, and see's Bob's annotations even if the PDF has
  never been uploaded to a webserver. (We can do this because of the
  immutability of PDF documents -- we can uniquely fingerprint each one and
  form a "URN" of the form "urn:x-pdf:<fingerprint>".)

The challenge, then, is to enable these features without making the public API
for creating and updating annotations overly complex. It turns out this is
possible if we can answer two questions:

1. Given two URI strings, do they both refer to the same URI, practically
   speaking? (AKA "normalisation".)

   e.g. on the web, the following URLs will *usually* refer to the same web
   page::

       http://example.com/foo?a=hello&b=world
       http://exAMPle.com/foo?a=hello&b=world
       http://example.com/foo/?a=hello&b=world
       http://example.com/foo?b=world&a=hello
       http://example.com/foo?a=hello&b=world#somefragment

2. Given a URI, what are all the known URIs of the underlying *document* (in
   the sense given above). (AKA "expansion".)

   e.g. we may know (from page metadata or otherwise) that all the following
   URIs refer to the same content, even if in differing formats::

       http://example.com/research/papers/2015-discoveries.html
       http://example.com/research/papers/2015-discoveries.pdf
       http://example.org/reprints/example-com-2015-discoveries.pdf
       urn:x-pdf:c83fa94bd1d522276a32f81682a43d29
       urn:doi:10.1000/12345

This package is responsible for defining URI normalisation and expansion
routines for use elsewhere in the Hypothesis application.
"""

from h.api import models


def normalise(uri):
    """Translate the given URI into a normalised form."""
    # For now this is simply the identity function. We will add normalisation
    # logic here a piece at a time as we transfer these responsibilities into
    # the URI package.
    return uri


def expand(uri):
    """
    Return all URIs which refer to the same underlying document as `uri`.

    This function determines whether we already have "document" records for the
    passed URI, and if so returns the set of all URIs which we currently
    believe refer to the same document.
    """
    doc = models.Document.get_by_uri(uri)
    if doc is None:
        return [uri]
    return doc.uris()

