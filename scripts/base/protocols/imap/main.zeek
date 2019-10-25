
module IMAP;

const ports = { 143/tcp };
redef likely_server_ports += { ports };

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		## Time when the message was first seen.
		ts:                time            &log;
		## Unique ID for the connection.
		uid:               string          &log;
		## The connection's 4-tuple of endpoint addresses/ports.
		id:                conn_id         &log;
        capabilities:       string_vec      &log;
        cmd:                string          &log;
        arg:                string          &log;
	};

    global log_imap: event(rec: Info);
}

redef record connection += {
	imap:       Info  &optional;
};

event zeek_init() &priority=5
	{
	Log::create_stream(IMAP::LOG, [$columns=IMAP::Info, $ev=log_imap, $path="imap"]);
	Analyzer::register_for_ports(Analyzer::ANALYZER_IMAP, ports);
	}

function new_imap_log(c: connection)
{
	if ( ! c?$imap )
	{
	    local l:Info;
	    l$ts = network_time();
	    l$uid = c$uid;
	    l$id = c$id;
	    c$imap = l;
	}
}

event imap_capabilities(c: connection, capabilities: string_vec)
{
    new_imap_log(c);
    c$imap$capabilities = capabilities;

    Log::write(IMAP::LOG, c$imap);
}

event imap_request(c: connection,
			command: string, arg: string)
{
    new_imap_log(c);
    c$imap$cmd = command;
    c$imap$arg = arg;
    Log::write(IMAP::LOG, c$imap);
}

event imap_reply(c: connection,
            cmd: string, msg: string)
{
    new_imap_log(c);
    c$imap$cmd = cmd;
    c$imap$arg = msg;
    Log::write(IMAP::LOG, c$imap);
}

event imap_data(c: connection, is_orig: bool, data: string)
{
}
