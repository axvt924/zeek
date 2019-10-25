refine connection IMAP_Conn += {

	%member{
		string client_starttls_id;
		int state_up_;
		int state_down_;
		int body_size_;
		int body_size_current_;
	%}

	%init{
		state_up_ = COMMANDS;
		state_down_ = COMMANDS;
		body_size_ = 0;
		body_size_current_ = 0;
	%}

	function get_state(is_orig: bool) : int
		%{
		if (is_orig)
			return state_up_;
		else
			return state_down_;
		return true;
		%}

	function update_state(s: state, is_orig: bool) : int
		%{
		if (is_orig)
			state_up_ = s;
		else
			state_down_ = s;
		return true;
		%}

	function determine_command(is_orig: bool, tag: bytestring, command: bytestring, value: bytestring): int
		%{
		string cmdstr = std_str(command);
		std::transform(cmdstr.begin(), cmdstr.end(), cmdstr.begin(), ::tolower);
		string tagstr = std_str(tag);
		string valuestr = std_str(value);
		std::transform(valuestr.begin(), valuestr.end(), valuestr.begin(), ::tolower);
		size_t value_len = valuestr.length();
		size_t i;
		size_t p;
		size_t power_ten[] = {0, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000, 1000000000};

		if ( !is_orig && cmdstr == "capability" && tag == "*" ) {
			return CMD_CAPABILITY;
		}

		// Check for FECTH command in server side, next line could be content.
		if ( !is_orig && value_len > 6 && valuestr.compare(0, 6, "fetch ") == 0 ) {
			// found body or rfc822, next line will be content
			if ( valuestr.find("body", 0) != std::string::npos
				|| valuestr.find("rfc822", 0) != std::string::npos) {
				// determine the size of the body by starting to the end
				// (ex: * 12 FETCH (RFC822 {321} ) will be read as 1,2,3
				if (valuestr[value_len - 1] == '}') {
					for (i = value_len - 2, p = 0; i > 0 && p < (sizeof(power_ten) / sizeof(size_t)); i--, p++) {
						if (std::isdigit(valuestr[i])) {
							// Convert char to integer
							if ( i == (value_len - 2 ))
								body_size_ += (int)valuestr[i] - '0';
							else
								body_size_ += power_ten[p] * ((int)valuestr[i] - '0');
						} else {
							if (valuestr[i] != '{')
								body_size_ = 0;
							break;
						}
					}
				}
				// change state to BODY for the next line
				update_state(BODY, is_orig);
			}
		}

		if ( is_orig && cmdstr == "authenticate" ) {
			update_state(AUTHENTIFICATION, is_orig);
		}

		return CMD_UNKNOWN;
		%}

	function strlen(str: bytestring): int
		%{
		return str.length();
		%}

	function proc_imap_command(is_orig: bool, tag: bytestring, command: bytestring): bool
		%{
		string commands = std_str(command);
		std::transform(commands.begin(), commands.end(), commands.begin(), ::tolower);

		string tags = std_str(tag);

		if ( !is_orig && tags == "*" && commands == "ok" )
			bro_analyzer()->ProtocolConfirmation();

		if ( is_orig && ( commands == "capability" || commands == "starttls" ) )
			bro_analyzer()->ProtocolConfirmation();

		if ( !is_orig && !client_starttls_id.empty() && tags == client_starttls_id )
			{
			if ( commands == "ok" )
				{
				bro_analyzer()->StartTLS();

				if ( imap_starttls )
					BifEvent::generate_imap_starttls(bro_analyzer(), bro_analyzer()->Conn());
				}
			else
				reporter->Weird(bro_analyzer()->Conn(), "IMAP: server refused StartTLS");
			}

		if ( is_orig && commands == "starttls" )
			{
			if ( !client_starttls_id.empty() )
				reporter->Weird(bro_analyzer()->Conn(), "IMAP: client sent duplicate StartTLS");

			client_starttls_id = tags;
			}

		if ( commands == "authenticate" ||
			commands == "login" ||
			commands == "examine" ||
			commands == "create" ||
			commands == "list" ||
			commands == "fetch" ||
			commands == "select" ||
			commands == "flags")
			{
			bro_analyzer()->ProtocolConfirmation();
			}

		return true;
		%}

	function proc_server_capability(capabilities: Capability[]): bool
		%{
		if ( ! capabilities )
			return true;

		VectorVal* capv = new VectorVal(internal_type("string_vec")->AsVectorType());
		for ( unsigned int i = 0; i< capabilities->size(); i++ )
			{
			const bytestring& capability = (*capabilities)[i]->cap();
			capv->Assign(i, new StringVal(capability.length(), (const char*)capability.data()));
			}

		BifEvent::generate_imap_capabilities(bro_analyzer(), bro_analyzer()->Conn(), capv);
		return true;
		%}

       function generic_cmd(is_orig: bool, tag: bytestring, command: bytestring, tagcontent: bytestring): bool
               %{
		StringVal *cmd = new StringVal(std_str(command));
		StringVal *arg = new StringVal(std_str(tagcontent));

		string args = std_str(tagcontent);
		std::transform(args.begin(), args.end(), args.begin(), ::tolower);

		if ( is_orig )
			BifEvent::generate_imap_request(bro_analyzer(), bro_analyzer()->Conn(), cmd, arg );
		else
			BifEvent::generate_imap_reply(bro_analyzer(), bro_analyzer()->Conn(), cmd, arg );

               return true;
               %}

	function proc_imap_body(is_orig: bool, tagcontent: bytestring): bool
               %{
		StringVal *arg = new StringVal(std_str(tagcontent));

		BifEvent::generate_imap_data(bro_analyzer(), bro_analyzer()->Conn(), is_orig, arg );

		body_size_current_ += tagcontent.length();

		printf("data: %s\n", std_str(tagcontent).c_str());
		// Stop content state if the line contains only a parenthesis
		// or if we overlap the body size
		if ((std_str(tagcontent)[0] == ')' && tagcontent.length() == 1)
			|| (body_size_ != 0 && body_size_current_ > body_size_ )) {
			update_state(COMMANDS, is_orig);
			body_size_current_ = 0;
			body_size_ = 0;
		}
		return true;
               %}

	       function proc_imap_auth(is_orig: bool, tagcontent: bytestring): bool
               %{
		update_state(AUTHENTIFICATION, is_orig);
		return true;
               %}
};

refine typeattr ImapCommandLine += &let {
    proc: bool = $context.connection.proc_imap_command(is_orig, tag, command);
};

refine typeattr ImapBodyLine += &let {
    proc: bool = $context.connection.proc_imap_body(is_orig, tagcontent);
};

refine typeattr ImapAuth += &let {
    proc: bool = $context.connection.proc_imap_auth(is_orig, tagcontent);
};

refine typeattr ServerCapability += &let {
	proc: bool = $context.connection.proc_server_capability(capabilities);
};

refine typeattr GenericCommand += &let {
       proc: bool = $context.connection.generic_cmd(is_orig, rec.tag, rec.command, tagcontent);
};
