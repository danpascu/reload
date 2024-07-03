
Testing
-------

To test the code, create a python virtual environment using python-3.12 and
activate it, after which install reload in that virtual environment with the
test dependencies and run the test-suite:

.. code-block:: console

    $ git clone https://github.com/danpascu/reload.git
    $ cd reload
    $ python3.12 -m venv .venv
    $ source .venv/bin/activate
    (.venv) $ pip install .[test]
    (.venv) $ pytest


Demo
----

Inside the tests directory there is a peer_link script that can be used to
demonstrate the existing functionality. Run the script without arguments to
simulate one side of the connection (which will act as a server by listening
on port 10000):

.. code-block:: console

    $ ./peer_link


Then on a different terminal or system run the script in client mode by
providing the IP address of the first instance as an argument:

.. code-block:: console

    $ ./peer_link 10.0.0.1

The client instance will connect to the server, exchange ICE information and
then both instances will use ICE to negotiate a connection between them.
After that, the client will send a RELOAD PingRequest to the server and the
server will reply with a PingResponse. If it receives anything else or if the
received message cannot be decoded, the server will send back a RELOAD error
response instead.

Note: running the peer_link script with the -d option will turn on debugging
which can show details about ICE negotiation and which candidates are used.
