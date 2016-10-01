Name
====

# lua-resty-socks5-server
This is an implementation of the SOCKS v5 [RFC1928](https://www.ietf.org/rfc/rfc1928.txt) server in the OpenResty and It's based on the stream-lua-ningx-module under the hood.

Table of Contents
-----------------
* [Name](#name)
* [Status](#status)
* [Usage](#usage)
* [API](#api)
* [Contributing](#contributing)
* [Author](#author)
* [License](#license)

Status
====
Experimental

Usage
====
Make sure your stream_lua_nginx's cosocket support the API `tcpsock:receive('*b')`, we are rely on it to implementation full duplex between upstream and downstream.

````bash
    server {
        listen 1234;

        content_by_lua_block {
                local socks5_server = require "lib.resty.socks5.server"

                socks5_server.run(3000)
                # or if you want to enable authentication
                # socks5_server.run(3000, "username", "password")
        }
    }
````

API
====

run
---
`syntax: module.run(timeout[,username, password])`

run a socks5 server.

* `timeout`
    The socket timeout (default 1000 ms) include connect、read、write between upstream and downstream.

* `username`
    The socks5 authentication username.

* `password`
    The socks5 authentication username.


Contributing
------------

To contribute to lua-resty-socks5-server, clone this repo locally and commit your code on a separate branch.

PS: PR Welcome :rocket: :rocket: :rocket: :rocket:


Author
------

> GitHub [@detailyang](https://github.com/detailyang)


License
-------
lua-resty-socks5-server is licensed under the [MIT] license.

[MIT]: https://github.com/detailyang/ybw/blob/master/licenses/MIT
