The database
============

.. toctree::


Model
-----

The entity relation diagram shows 7 entities related to certificates and
their deployment. The normalized schema has rules and triggers to ensure
integrity.
  
.. image:: ERD.png


The tables
----------

.. index:: Subject, Subject.type, Subject.isAltName, Subject.certificate

.. index::
  see: Subject.certificate; Certificates

* Subjects - holds all the subject names

  * **name** - name of subject
  * type - subject type, one of
  
    * 'server' - server subject
    * 'client' - client (or personal) subject
    * 'CA' - certificate authority

  * isAltName - true if subject is an alternate name
  * *certificate* - reference to Certificates