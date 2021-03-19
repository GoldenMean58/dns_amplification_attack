########################
DNS Amplification Attack
########################

* Contents:

  + 1 `DNS Amplification Attack`_

    + 1.1 `About The Project`_
    + 1.2 `Getting Started`_
    + 1.3 Screenshots_
    + 1.4 License_
    + 1.5 Contact_
    + 1.6 Acknowledgments_

About The Project
=================

This repository is a simple experiment of DNS-Amplification-Attack_.

How it started
  This is my graduation project

How it's going
  This project now is not as good as I expected, especially the dns server, which now can only send 512-byte useless response packet. I'd like to make it a valid dns response.

Getting Started
===============

To quickly get started, you should set up a local network, at least one **attacker**, one **dns server** and a **victim**. Of course they can be in the same host.

After that, let's begin building the executable files:

.. code-block:: bash

   root@build:~# git clone https://github.com/GoldenMean58/dns_amplification_attack
   root@build:~# cd dns_amplification_attack
   root@build:~/dns_amplification_attack# ./configure && make

And you will have **dns_attacker** and **dns_server** in the *src* directory. They do what as their names show.

Let's pretend the IP configure as below::

  Network Gateway: 192.168.1.1
  DNS Server: 192.168.1.1
  Attacker: 192.168.1.2
  Victim: 192.168.1.3

Now, we can put our hands to attack. First we start our DNS server:

.. code-block:: bash

   root@dns-server:~# ./dns_server
   DNS server bind address: 0.0.0.0    
   DNS server bind port:53

As you can see, we bind the dns_server to 0.0.0.0:53 for external access, which need privilege.

Then we start our attacker:

.. code-block:: bash

   root@attacker:~# ./dns_attacker
   Target ip address: 192.168.1.3
   DNS server ip address: 192.168.1.1
   DNS server port: 53
   Query domain name(Ctrl+D to end): www.baidu.com
   Query type(A = 1, NS = 2, CNAME = 5, MX = 15, TXT = 16 , AAAA = 28): 16
   Query domain name(Ctrl+D to end):<Ctrl+D>

We asked the dns server(192.168.1.1:53) for *www.baidu.com*'s TXT record and spoof the query packet's source ip to **Target ip address** (192.168.1.3). After we enter <Ctrl+D>, the target victim was under attack. You can monitor network flow(UDP) on the dns server, attacker and victim.

Screenshots
===========

Linux attack:
  .. image:: https://www.helloimg.com/images/2021/03/19/BQLjpK.png

Windows victim:
  .. image:: https://www.helloimg.com/images/2021/03/19/BQAXHv.png

License
=======

Distributed under the MIT License. See `LICENSE`_ for more information.

Contact
=======

GoldenMean_ - GoldenMean58@outlook.com

Acknowledgments
===============

`Cloudflare article`_

`User Datagram Protocol(UDP) WIKIPEDIA article`_

`IPv4 WIKIPEDIA article`_

`Domain Name System WIKIPEDIA article`_

.. _DNS-Amplification-Attack: https://www.cloudflare.com/learning/ddos/dns-amplification-ddos-attack/
.. _LICENCE: https://github.com/GoldenMean58/dns_amplification_attack/blob/master/LICENSE
.. _GoldenMean: https://github.com/GoldenMean58
.. _Cloudflare article: https://www.cloudflare.com/learning/ddos/dns-amplification-ddos-attack/
.. _User Datagram Protocol(UDP) WIKIPEDIA article: https://en.wikipedia.org/wiki/User_Datagram_Protocol
.. _IPv4 WIKIPEDIA article: https://en.wikipedia.org/wiki/IPv4#Packet_structure
.. _Domain Name System WIKIPEDIA article: https://en.wikipedia.org/wiki/Domain_Name_System
