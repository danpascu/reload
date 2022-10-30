# SPDX-FileCopyrightText: 2020-present Dan Pascu <dan@aethereal.link>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
6.3. Message Structure

   RELOAD is a message-oriented request/response protocol.  The messages
   are encoded using binary fields.  All integers are represented in
   network byte order.  The general philosophy behind the design was to
   use Type, Length, Value (TLV) fields to allow for extensibility.
   However, for the parts of a structure that were required in all
   messages, we just define these in a fixed position, as adding a type
   and length for them is unnecessary and would only increase bandwidth
   and introduce new potential interoperability issues.

   Each message has three parts, which are concatenated, as shown below:

     +-------------------------+
     |    Forwarding Header    |
     +-------------------------+
     |    Message Contents     |
     +-------------------------+
     |     Security Block      |
     +-------------------------+

   The contents of these parts are as follows:

   Forwarding Header:  Each message has a generic header which is used
      to forward the message between peers and to its final destination.
      This header is the only information that an intermediate peer
      (i.e., one that is not the target of a message) needs to examine.
      Section 6.3.2 describes the format of this part.

   Message Contents:  The message being delivered between the peers.
      From the perspective of the forwarding layer, the contents are
      opaque; however, they are interpreted by the higher layers.
      Section 6.3.3 describes the format of this part.

   Security Block:  A security block containing certificates and a
      digital signature over the "Message Contents" section.  Note that
      this signature can be computed without parsing the message
      contents.  All messages MUST be signed by their originator.
      Section 6.3.4 describes the format of this part.

"""

# __all__ =
