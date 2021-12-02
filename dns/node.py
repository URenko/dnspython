# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

# Copyright (C) 2001-2017 Nominum, Inc.
#
# Permission to use, copy, modify, and distribute this software and its
# documentation for any purpose with or without fee is hereby granted,
# provided that the above copyright notice and this permission notice
# appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND NOMINUM DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL NOMINUM BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
# OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

"""DNS nodes.  A node is a set of rdatasets."""

import io

import dns.rdataset
import dns.rdatatype
import dns.renderer


class Node:

    """A Node is a set of rdatasets.

    A node is either a CNAME node or an "other data" node.  A CNAME
    node contains only CNAME, RRSIG(CNAME), NSEC, RRSIG(NSEC), NSEC3,
    or RRSIG(NSEC3) rdatasets.  An "other data" node contains any
    rdataset other than a CNAME or RRSIG(CNAME) rdataset.  When
    changes are made to a node, the CNAME or "other data" state is
    always consistent with the update, i.e. the most recent change
    wins.  For example, if you have a node which contains a CNAME
    rdataset, and then add an MX rdataset to it, then the CNAME
    rdataset will be deleted.  Likewise if you have a node containing
    an MX rdataset and add a CNAME rdataset, the MX rdataset will be
    deleted.
    """

    __slots__ = ['rdatasets']

    def __init__(self):
        # the set of rdatasets, represented as a list.
        self.rdatasets = []

    def to_text(self, name, **kw):
        """Convert a node to text format.

        Each rdataset at the node is printed.  Any keyword arguments
        to this method are passed on to the rdataset's to_text() method.

        *name*, a ``dns.name.Name`` or ``str``, the owner name of the
        rdatasets.

        Returns a ``str``.

        """

        s = io.StringIO()
        for rds in self.rdatasets:
            if len(rds) > 0:
                s.write(rds.to_text(name, **kw))
                s.write('\n')
        return s.getvalue()[:-1]

    def __repr__(self):
        return '<DNS node ' + str(id(self)) + '>'

    def __eq__(self, other):
        #
        # This is inefficient.  Good thing we don't need to do it much.
        #
        for rd in self.rdatasets:
            if rd not in other.rdatasets:
                return False
        for rd in other.rdatasets:
            if rd not in self.rdatasets:
                return False
        return True

    def __ne__(self, other):
        return not self.__eq__(other)

    def __len__(self):
        return len(self.rdatasets)

    def __iter__(self):
        return iter(self.rdatasets)

    def _append_rdataset(self, rdataset):
        """Append rdataset to the node with special handling for CNAME and
        other data conditions.

        Specifically, if the rdataset being appended is a CNAME, then
        all rdatasets other than NSEC, NSEC3, and their covering RRSIGs
        are deleted.  If the rdataset being appended is NOT a CNAME, then
        CNAME and RRSIG(CNAME) are deleted.
        """
        # Make having just one rdataset at the node fast.
        if len(self.rdatasets) > 0:
            if rdataset.implies_cname():
                self.rdatasets = [rds for rds in self.rdatasets
                                  if rds.ok_for_cname()]
            elif rdataset.implies_other_data():
                self.rdatasets = [rds for rds in self.rdatasets
                                  if rds.ok_for_other_data()]
        self.rdatasets.append(rdataset)


    def find_rdataset(self, rdclass, rdtype, covers=dns.rdatatype.NONE,
                      create=False):
        """Find an rdataset matching the specified properties in the
        current node.

        *rdclass*, an ``int``, the class of the rdataset.

        *rdtype*, an ``int``, the type of the rdataset.

        *covers*, an ``int`` or ``None``, the covered type.
        Usually this value is ``dns.rdatatype.NONE``, but if the
        rdtype is ``dns.rdatatype.SIG`` or ``dns.rdatatype.RRSIG``,
        then the covers value will be the rdata type the SIG/RRSIG
        covers.  The library treats the SIG and RRSIG types as if they
        were a family of types, e.g. RRSIG(A), RRSIG(NS), RRSIG(SOA).
        This makes RRSIGs much easier to work with than if RRSIGs
        covering different rdata types were aggregated into a single
        RRSIG rdataset.

        *create*, a ``bool``.  If True, create the rdataset if it is not found.

        Raises ``KeyError`` if an rdataset of the desired type and class does
        not exist and *create* is not ``True``.

        Returns a ``dns.rdataset.Rdataset``.
        """

        for rds in self.rdatasets:
            if rds.match(rdclass, rdtype, covers):
                return rds
        if not create:
            raise KeyError
        rds = dns.rdataset.Rdataset(rdclass, rdtype, covers)
        self._append_rdataset(rds)
        return rds

    def get_rdataset(self, rdclass, rdtype, covers=dns.rdatatype.NONE,
                     create=False):
        """Get an rdataset matching the specified properties in the
        current node.

        None is returned if an rdataset of the specified type and
        class does not exist and *create* is not ``True``.

        *rdclass*, an ``int``, the class of the rdataset.

        *rdtype*, an ``int``, the type of the rdataset.

        *covers*, an ``int``, the covered type.  Usually this value is
        dns.rdatatype.NONE, but if the rdtype is dns.rdatatype.SIG or
        dns.rdatatype.RRSIG, then the covers value will be the rdata
        type the SIG/RRSIG covers.  The library treats the SIG and RRSIG
        types as if they were a family of
        types, e.g. RRSIG(A), RRSIG(NS), RRSIG(SOA).  This makes RRSIGs much
        easier to work with than if RRSIGs covering different rdata
        types were aggregated into a single RRSIG rdataset.

        *create*, a ``bool``.  If True, create the rdataset if it is not found.

        Returns a ``dns.rdataset.Rdataset`` or ``None``.
        """

        try:
            rds = self.find_rdataset(rdclass, rdtype, covers, create)
        except KeyError:
            rds = None
        return rds

    def delete_rdataset(self, rdclass, rdtype, covers=dns.rdatatype.NONE):
        """Delete the rdataset matching the specified properties in the
        current node.

        If a matching rdataset does not exist, it is not an error.

        *rdclass*, an ``int``, the class of the rdataset.

        *rdtype*, an ``int``, the type of the rdataset.

        *covers*, an ``int``, the covered type.
        """

        rds = self.get_rdataset(rdclass, rdtype, covers)
        if rds is not None:
            self.rdatasets.remove(rds)

    def replace_rdataset(self, replacement):
        """Replace an rdataset.

        It is not an error if there is no rdataset matching *replacement*.

        Ownership of the *replacement* object is transferred to the node;
        in other words, this method does not store a copy of *replacement*
        at the node, it stores *replacement* itself.

        *replacement*, a ``dns.rdataset.Rdataset``.

        Raises ``ValueError`` if *replacement* is not a
        ``dns.rdataset.Rdataset``.
        """

        if not isinstance(replacement, dns.rdataset.Rdataset):
            raise ValueError('replacement is not an rdataset')
        if isinstance(replacement, dns.rrset.RRset):
            # RRsets are not good replacements as the match() method
            # is not compatible.
            replacement = replacement.to_rdataset()
        self.delete_rdataset(replacement.rdclass, replacement.rdtype,
                             replacement.covers)
        self._append_rdataset(replacement)

    def is_cname(self):
        """Is this a CNAME node?

        If the node has a CNAME or an RRSIG(CNAME) it is considered a CNAME
        node for CNAME-and-other-data purposes, and ``True`` is returned.
        Otherwise the node is an "other data" node, and ``False`` is returned.
        """
        for rdataset in self.rdatasets:
            if rdataset.implies_cname():
                return True
        return False
