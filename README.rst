..
      Licensed under the Apache License, Version 2.0 (the "License"); you may
      not use this file except in compliance with the License. You may obtain
      a copy of the License at

          http://www.apache.org/licenses/LICENSE-2.0

      Unless required by applicable law or agreed to in writing, software
      distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
      WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
      License for the specific language governing permissions and limitations
      under the License.

==================================
Octavia Health Manager Stress Tool
==================================

.. warning::

  DO NOT RUN THIS ON A PRODUCTION OCTAVIA DEPLOYMENT!
  It can cause a denial of service in your health manager and
  lead to all of your load balancers failing over. It also may
  leave some data in the Octavia database tables.
  You have been warned....

.. note::

  This tool does raw database transactions and may be out of date
  compared to the current Octavia schema. It was written against a Rocky
  cloud.

This is a quick and (very) dirty app I wrote to stress certain aspects of
the OpenStack Octavia Health Manager process.  It's intent is to exercise the
health heartbeat code in the Octavia Health Manager. 
This code is lightly tested in my devstack development environment.
It may/may not work and/or be complete enough for yours.

This tool can also be used to populate a database with "ghost" load balancers.
I used it to populate the database with load balancer records so I could test
the performance of the Octavia API "list" methods.
My hope is that this type of testing will be integrated into Rally tests
for the Octavia API.

Database Population Mode
========================

In this mode the tool simply creates "ghost" load balancer records in the
Octavia database listed in the stresshm.conf. It does not run any stress
testing load against the Octavia Health Manager.

Creating Load Balancer Records
------------------------------

The first step is to edit the stresshm.conf file and configure the
[test_params] section. This defines the database connection string and
the number of objects to create. The object values are "for each", meaning
they are multipliers. A configuration with ten load balancers and five
listeners will result in 50 listeners being created, five "for each" load
balancer. No actual load balancers will be created, meaning no amphora
will be booted. These are simply "ghost" database records for testing.

To create the database records:

.. code-block:: bash

  python stresshm.py --config-file stresshm.conf --db_create_only

Please note the "prefix ID" this command will output. It can be used to
cleanup the records this tool creates by using the --clean_db command.

Cleaning up the Load Balancer Records
-------------------------------------

To cleanup and delete the records created above:

.. code-block:: bash

  python stresshm.py --config-file stresshm.conf --clean_db <prefix ID>

This will remove the database records created by the tool.

.. note::

  This will not cleanup other tables that may be loaded during test runs.

Health Manager Stress Test Mode
===============================

.. warning::

  This tool will put heavy load on your test host, Octavia health manager,
  and your Octavia database. This includes disk IO, memory usage, and CPU
  load.

When run in health manager stress test mode this tool will do the following:

* It will populate the database with load balancers
* Fork stress test processes to simulate the amphora (2 per LB)
* They will send heartbeat messages to the health manager endpoint(s)
* It will run until the "test_runtime_secs" have elapsed
* It will delete the load balancers that were created in the database

.. note::

  This tool will leave amphora health and stats records in the database.

To run the health manager stress test:

.. code-block:: bash

  python stresshm.py --config-file stresshm.conf

While this tool is running you should be watching your health manager log
file to see if your health manager(s) are able to keep up with the heartbeat
rates. Specifically you do not want to see "THIS IS NOT GOOD." messages.
