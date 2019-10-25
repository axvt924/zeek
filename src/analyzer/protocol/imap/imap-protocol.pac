%include consts.pac

type TAG = RE/[(\*|[:xdigit:]|\+)]+/;
type CAPABILITIES = RE/[[:alnum:][:punct:]]+/;
type COMMAND = RE/[[:alnum:]]+/;
type CONTENT = RE/[^\r\n]*/;
type SPACING = RE/[ ]+/;
type OPTIONALSPACING = RE/[ ]*/;
type NEWLINE = RE/[\r\n]+/;
type OPTIONALNEWLINE = RE/[\r\n]*/;

type IMAP_PDU(is_orig: bool) = case $context.connection.get_state(is_orig) of {
	COMMANDS -> commands : ImapCommandLine(is_orig);
	AUTHENTIFICATION -> auth : ImapAuth(is_orig);
	BODY -> body: ImapBodyLine(is_orig);
};

# Parse an IMAP command line, this could be a client of server command example:
# Client: a111 SELECT "INBOX" -> tag = a111, command = SELECT, args = "INBOX"
# Server: * 13 RECENT -> tag = *, command = 13, args = RECENT
# Server: * FLAGS (\seen) -> tag = *, command = FLAGS, args = (\seen)
# Server: * OK UIDVALIDITY value. -> tag = *, command = OK, args = UIDVALIDITY value.
# Server: a112 OK SELECT completed. -> tag = a112, command = OK, args = SELECT completed.
#
type ImapCommandLine(is_orig: bool) = record {
	tag : TAG;
	: SPACING;
	command: COMMAND;
	: OPTIONALSPACING;
	args: bytestring &exportsourcedata &restofdata;
} &let {
	pcommand: int = $context.connection.determine_command(is_orig, tag, command, args);
	client: ClientCommand(is_orig, this) withinput sourcedata &if(is_orig);
	server: ServerCommand(is_orig, this) withinput sourcedata &if(!is_orig);
} &oneline;

type ServerCommand(is_orig: bool, rec: ImapCommandLine) = case rec.pcommand of {
	CMD_CAPABILITY -> capability: ServerCapability(rec);
	default -> unknown: GenericCommand(is_orig, rec);
};

type ClientCommand(is_orig: bool, rec: ImapCommandLine) = case rec.pcommand of {
	default -> unknown: GenericCommand(is_orig, rec);
};

type Capability = record {
	cap: CAPABILITIES;
	: OPTIONALSPACING;
	nl: OPTIONALNEWLINE;
};

type ServerCapability(rec: ImapCommandLine) = record {
	capabilities: Capability[] &until($context.connection.strlen($element.nl) > 0);
};

type GenericCommand(is_orig: bool, rec: ImapCommandLine) = record {
	tagcontent: CONTENT;
};

type ImapBodyLine(is_orig: bool) = record {
	tagcontent: CONTENT;
} &oneline;

type ImapAuth(is_orig: bool) = record {
	tagcontent: CONTENT;
} &oneline;
