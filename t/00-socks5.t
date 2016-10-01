use Test::Nginx::Socket::Lua::Stream;

my $workdir = $ENV{WORKDIR};

#worker_connections(1014);
#master_on();
#workers(2);
#log_level('warn');

#no_diff();
#no_long_string();
repeat_each(2);
plan tests => repeat_each() * 2 * blocks();

no_shuffle();
run_tests();

our $stream_config = <<"_EOS_";
    lua_resolver 114.114.114.114;
    lua_code_cache off;
    lua_package_path '$workdir/?.lua;;';
_EOS_

__DATA__

=== TEST 1: noauth method
--- stream_config eval: $::http_config
--- stream_server_config
    content_by_lua_block {
        local socks5_server = require "lib.resty.socks5.server"

        socks5_server.run(2000)
    }

--- stream_request eval
"\x05\x01\x00"

--- stream_response eval
"\x05\x00"

=== TEST 2: auth method
--- stream_config eval: $::http_config
--- stream_server_config
    content_by_lua_block {
        local socks5_server = require "lib.resty.socks5.server"

        socks5_server.run(2000, 'user', 'password')
    }

--- stream_request eval
"\x05\x02\x00\x02"

--- stream_response eval
"\x05\x02"
